# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Big Switch Networks, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Mandeep Dhami, Big Switch Networks, Inc.

"""
Quantum REST Proxy Plug-in

QuantumRestProxy provides a generic quantum plugin that translates all plugin
function calls to equivalent authenticated REST calls to a set of redundant
external network controllers. It also keeps persistent store for all quantum
state to allow for re-sync of the external controller(s), if required.

The local state on the plugin also allows for local response and fast-fail
semantics where it can be determined based on the local persistent store.

Network controller specific code is decoupled from this plugin and expected
to reside on the controller itself (via the REST interface).

This allows for:
 - independent auth and redundancy schemes between quantum and network ctrl
 - independent upgrade/development cycles between quantum and network ctrl
   as it limits the proxy code upgrade requirement to quantum release cycle
   and the net ctrl specific code upgrade requirement to network ctrl code
 - ability to sync network ctrl with quantum for independent recovery/reset

External REST API used by proxy is the same API as defined for quantum (JSON
subset) with some additional parameters (gateway on network-create and macaddr
on port-attach) on an additional PUT to do a bulk dump of all persistent data.
"""

import ConfigParser
import base64
import gettext
import httplib
import json
import logging
import os
import socket
import sys

from quantum.common import exceptions
from quantum.common import topics
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import models_v2
from quantum.openstack.common import context as glbcontext
from quantum.openstack.common.rpc import dispatcher
from quantum.openstack.common import rpc
from quantum.plugins.restproxy.version import version_string_with_vcs

gettext.install("quantum", unicode=1)
LOG = logging.getLogger('quantum.plugins.QuantumRestProxy')
LOG.setLevel(logging.INFO)


class ConfigurationError(exceptions.QuantumException):
    def __init__(self, message):
        if message is None:
            message = ""
        self.message = \
            _("Error in configuration file") + \
            ": " + message
        super(ConfigurationError, self).__init__()


class RemoteRestError(exceptions.QuantumException):
    def __init__(self, message):
        if message is None:
            message = ""
        self.message = \
                _("Error in REST call to remote network controller") + \
                ": " + message
        super(RemoteRestError, self).__init__()


class ConfigProxy(object):
    """Config handler for REST proxy plugin"""

    def __init__(self, config_dir, filename, section):
        self.filename = filename
        if config_dir is not None:
            self.filename = self.find_config_file(config_dir, filename)
        self.section = section
        self.config = ConfigParser.SafeConfigParser()
        self.config.read(self.filename)

    def get(self, fld):
        try:
            return self.config.get(self.section, fld)
        except ConfigParser.NoOptionError:
            return None
        except ConfigParser.NoSectionError:
            raise ConfigurationError(_("Can not read: [%s]/%s" %
                (self.section, fld)))

    def get_bool(self, fld):
        valstr = self.get(fld)
        val = False
        if valstr is not None and valstr.lower() == 'true':
            val = True
        return val

    def find_config_file(self, config_dir, filename):
        """
        Return the first config file found for an application.

        We search for the config file in the following order:
            * /etc/config_dir
            * ./etc

        :retval Full path to config file, or raise exception
          if no config file found
        """

        config_file_dirs = [
            os.path.join('/etc', config_dir),
            os.path.join(os.getcwd(), 'etc'),
        ]

        for cfg_dir in config_file_dirs:
            cfg_file = os.path.join(cfg_dir, filename)
            if os.path.exists(cfg_file):
                return cfg_file

        raise ConfigurationError(_("Can find conf file: %s [%r]" % \
            (filename, config_file_dirs)))


class ServerProxy(object):
    """
    REST server proxy to a network controller
    """

    def __init__(self, server, port, ssl, auth, timeout, base_uri, name):
        self.server = server
        self.port = port
        self.ssl = ssl
        self.base_uri = base_uri
        self.timeout = timeout
        self.name = name
        self.success_codes = range(200, 207)
        self.auth = None
        if auth:
            self.auth = 'Basic ' + base64.encodestring(auth).strip()

    def rest_call(self, action, resource, data, headers):
        uri = self.base_uri + resource
        body = json.dumps(data)
        if not headers:
            headers = {}
        headers['Content-type'] = 'application/json'
        headers['Accept'] = 'application/json'
        headers['QuantumProxy-Agent'] = self.name
        if self.auth:
            headers['Authorization'] = self.auth

        LOG.debug('ServerProxy: server=%s, port=%d, ssl=%r, action=%s' %
                (self.server, self.port, self.ssl, action))
        LOG.debug('ServerProxy: resource=%s, data=%r, headers=%r' %
                (resource, data, headers))

        conn = None
        if self.ssl:
            conn = httplib.HTTPSConnection(
                self.server, self.port, timeout=self.timeout)
        else:
            conn = httplib.HTTPConnection(
                self.server, self.port, timeout=self.timeout)

        try:
            conn.request(action, uri, body, headers)
            response = conn.getresponse()
            respstr = response.read()
            respdata = respstr
            if response.status in self.success_codes:
                try:
                    respdata = json.loads(respstr)
                except ValueError:
                    # response was not JSON, ignore the exception
                    pass
            ret = (response.status, response.reason, respstr, respdata)
        except (socket.timeout, socket.error) as e:
            LOG.error('ServerProxy: %s failure, %r' % (action, e))
            ret = 0, None, None, None
        conn.close()
        LOG.debug('ServerProxy: status=%d, reason=%r, ret=%s, data=%r' % ret)
        return ret


class ServerPool(object):
    def __init__(self, servers, ssl, auth, timeout=10,
            base_uri='/quantum/v1.0', name='QuantumRestProxy'):
        self.base_uri = base_uri
        self.timeout = timeout
        self.name = name
        self.auth = auth
        self.ssl = ssl
        self.servers = []
        for server_port in servers:
            self.servers.append(self.server_proxy_for(*server_port))

    def server_proxy_for(self, server, port):
        return ServerProxy(server, port, self.ssl, self.auth, self.timeout,
                self.base_uri, self.name)

    # define failure as required
    def server_failure(self, resp):
        # Note: We assume 301-303 is a failure, and try the next server in
        # the server pool.
        return resp[0] in [0, 301, 302, 303]

    # define success as required
    def action_success(self, resp):
        # Note: We assume any valid 2xx as being successful response
        return resp[0] in range(200, 207)

    def rest_call(self, action, resource, data, headers):
        failed_servers = []
        while self.servers:
            active_server = self.servers[0]
            ret = active_server.rest_call(action, resource, data, headers)
            if not self.server_failure(ret):
                self.servers.extend(failed_servers)
                return ret
            else:
                LOG.error('ServerProxy: %s failure for servers: %r' % (
                    action, (active_server.server, active_server.port)))
                failed_servers.append(self.servers.pop(0))

        # All servers failed, reset server list and try again next time
        LOG.error('ServerProxy: %s failure for all servers: %r' % (
            action, tuple((s.server, s.port) for s in failed_servers)))
        self.servers.extend(failed_servers)
        return (0, None, None, None)

    def get(self, resource, data='', headers=None):
        return self.rest_call('GET', resource, data, headers)

    def put(self, resource, data, headers=None):
        return self.rest_call('PUT', resource, data, headers)

    def post(self, resource, data, headers=None):
        return self.rest_call('POST', resource, data, headers)

    def delete(self, resource, data='', headers=None):
        return self.rest_call('DELETE', resource, data, headers)


class RpcProxy(dhcp_rpc_base.DhcpRpcCallbackMixin):

    RPC_API_VERSION = '1.0'

    def __init__(self, rpc_context):
        self.rpc_context = rpc_context

    def create_rpc_dispatcher(self):
        return dispatcher.RpcDispatcher([self])


class QuantumRestProxy(db_base_plugin_v2.QuantumDbPluginV2):

    def __init__(self):
        # Read configuration, for unit tests pass in conf as first arg
        # - proxy's persistent store defaults to in-memory sql-lite DB
        # - nova can be configured to read DB ditrectly using 'novadb' or
        #   to query the nova server using 'novaapi' as REST end-points
        #   with 'novauth' for encoding a user:pass to access it as admin
        #   Note: novaapi is not currently supported
        # - 'servers' is the list of network controller REST end-points
        #   (used in order specified till one suceeds, and it is sticky
        #   till next failure). Use 'serverauth' to encode api-key
        config_file = os.environ.get('RESTPROXY_CONFIG')
        if config_file:
            self.conf = ConfigProxy(None, config_file, 'restproxy')
        else:
            self.conf = ConfigProxy('quantum/plugins/restproxy', \
                'restproxy.ini', 'restproxy')
        self.setup_logging()
        LOG.info('QuantumRestProxy: Starting plugin. Version=%s' %
            version_string_with_vcs())

        # read config
        proxydb = self.conf.get('proxydb') or \
                'mysql://root@localhost/restproxy'
        servers = self.conf.get('servers')
        serverauth = self.conf.get('serverauth')
        serverssl = self.conf.get_bool('serverssl')

        # validate config
        assert servers is not None, 'Servers not defined. Aborting plugin'
        servers = tuple(s.split(':') for s in servers.split(','))
        servers = tuple((server, int(port)) for server, port in servers)
        assert all(len(s) == 2 for s in servers), \
                'Syntax error in servers in config file. Aborting plugin'

        # init DB, nova and network ctrl connections
        db.configure_db({
            'sql_connection': proxydb,
            'base': models_v2.model_base.BASEV2,
        })
        self.servers = ServerPool(servers, serverssl, serverauth)

        # init dhcp support
        self.topic = topics.PLUGIN
        self.rpc_context = glbcontext.RequestContext(
            'quantum', 'quantum', is_admin=False)
        self.conn = rpc.create_connection(new=True)
        self.callbacks = RpcProxy(self.rpc_context)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()


    def setup_logging(self):
        root_logger = LOG
        log_format = "%(asctime)s %(levelname)8s [%(name)s] %(message)s"
        log_date_format = "%Y-%m-%d %H:%M:%S"

        if self.conf.get_bool('debug'):
            root_logger.setLevel(logging.DEBUG)
        elif self.conf.get_bool('verbose'):
            root_logger.setLevel(logging.INFO)
        else:
            root_logger.setLevel(logging.WARNING)

        # Set log configuration from options or defaults
        log_format = self.conf.get('log_format') or log_format
        log_date_format = self.conf.get('log_date_format') or log_date_format
        formatter = logging.Formatter(log_format, log_date_format)

        logfile = self.conf.get('log_file')
        use_syslog = self.conf.get_bool('use_syslog')

        if use_syslog:
            handler = logging.handlers.SysLogHandler(address='/dev/log')
        elif logfile:
            logdir = self.conf.get('log_dir')
            if logdir:
                logfile = os.path.join(logdir, logfile)
            handler = logging.FileHandler(logfile)
        else:
            handler = logging.StreamHandler(sys.stdout)

        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

    def create_network(self, context, network):
        """
        Create a network, which represents an L2 network segment which
        can have a set of subnets and ports associated with it.
        :param context: quantum api request context
        :param network: dictionary describing the network

        :returns: a sequence of mappings with the following signature:
        {
            "id": UUID representing the network.
            "name": Human-readable name identifying the network.
            "tenant_id": Owner of network. NOTE: only admin user can specify
                         a tenant_id other than its own.
            "admin_state_up": Sets admin state of network.
                              if down, network does not forward packets.
            "status": Indicates whether network is currently operational
                      (values are "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "subnets": Subnets associated with this network.
        }

        :raises: exceptions.NoImplementedError
        """

        LOG.debug("QuantumRestProxy: create_network() called")

        # Validate args
        tenant_id = self._get_tenant_id_for_create(context, network["network"])
        net_name = network["network"]["name"]
        if network["network"]["admin_state_up"] is False:
            LOG.warning("Network with admin_state_up=False are not yet "
                        "supported by this plugin. Ignoring setting for "
                        "network %s", net_name)
            # For now, just force the admin_state_up to be True and continue
            network["network"]["admin_state_up"] = True

        # create in DB
        new_net = super(QuantumRestProxy, self).create_network(context, network)

        # create on networl ctrl
        try:
            resource = "/tenants/%s/networks" % tenant_id
            data = {
                "network": {
                    "id": new_net["id"],
                    "name": new_net["name"],
                }
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxy: Unable to create remote network: %s" %
                e.message)
            super(QuantumRestProxy, self).network_delete(context, new_net["id"])
            raise

        # return created network
        return new_net

    def update_network(self, context, net_id, network):
        """
        Updates the properties of a particular Virtual Network.
        :param context: quantum api request context
        :param net_id: uuid of the network to update
        :param network: dictionary describing the updates

        :returns: a sequence of mappings with the following signature:
        {
            "id": UUID representing the network.
            "name": Human-readable name identifying the network.
            "tenant_id": Owner of network. NOTE: only admin user can
                         specify a tenant_id other than its own.
            "admin_state_up": Sets admin state of network.
                              if down, network does not forward packets.
            "status": Indicates whether network is currently operational
                      (values are "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "subnets": Subnets associated with this network.
        }

        :raises: exceptions.NoImplementedError
        :raises: exceptions.NetworkNotFound
        """

        LOG.debug("QuantumRestProxy.update_network() called")

        # Validate Args
        if network["network"].get("admin_state_up"):
            if network["network"]["admin_state_up"] is False:
                raise exceptions.NotImplementedError("admin_state_up=False")

        # update DB
        orig_net = super(QuantumRestProxy, self).get_network(context, net_id)
        tenant_id = orig_net["tenant_id"]
        new_net = super(QuantumRestProxy, self).update_network(
            context, net_id, network)

        # update network on network controller
        if new_net["name"] != orig_net["name"]:
            try:
                resource = "/tenants/%s/networks/%s" % (tenant_id, net_id)
                data = {
                    "network": new_net,
                }
                ret = self.servers.put(resource, data)
                if not self.servers.action_success(ret):
                    raise RemoteRestError(ret[2])
            except RemoteRestError as e:
                LOG.error(
                    "QuantumRestProxy: Unable to update remote network: %s" %
                    e.message)
                # reset network to original state
                super(QuantumRestProxy, self).update_network(
                    context, id, orig_net)
                raise

        # return updated network
        return new_net

    def delete_network(self, context, net_id):
        """
        Delete a network.
        :param context: quantum api request context
        :param id: UUID representing the network to delete.

        :returns: None

        :raises: exceptions.NetworkInUse
        :raises: exceptions.NetworkNotFound
        """

        LOG.debug("QuantumRestProxy: delete_network() called")

        # Validate args
        orig_net = super(QuantumRestProxy, self).get_network(context, net_id)
        tenant_id = orig_net["tenant_id"]
        super(QuantumRestProxy, self).delete_network(context, net_id)

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = "/tenants/%s/networks/%s" % (tenant_id, net_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxy: Unable to update remote network: %s" %
                e.message)

        # return None
        return None

    def create_port(self, context, port):
        """
        Create a port, which is a connection point of a device
        (e.g., a VM NIC) to attach to a L2 Quantum network.
        :param context: quantum api request context
        :param port: dictionary describing the port

        :returns:
        {
            "id": uuid represeting the port.
            "network_id": uuid of network.
            "tenant_id": tenant_id
            "mac_address": mac address to use on this port.
            "admin_state_up": Sets admin state of port. if down, port
                              does not forward packets.
            "status": dicates whether port is currently operational
                      (limit values to "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "fixed_ips": list of subnet ID"s and IP addresses to be used on
                         this port
            "device_id": identifies the device (e.g., virtual server) using
                         this port.
        }

        :raises: exceptions.NetworkNotFound
        :raises: exceptions.StateInvalid
        """

        # Validate Args
        LOG.debug("QuantumRestProxy: create_port() called")

        # Update DB
        port["port"]["admin_state_up"] = False
        new_port = super(QuantumRestProxy, self).create_port(context, port)
        net = super(QuantumRestProxy, self).get_network(
                context, new_port["network_id"])

        # create on networl ctrl
        try:
            resource = "/tenants/%s/networks/%s/ports" % (
                    net["tenant_id"], net["id"])
            data = {
                "port": {
                    "id": new_port["id"],
                    "state": "ACTIVE",
                }
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])

            # connect device to network, if present
            if port["port"].get("device_id"):
                self.plug_interface(context,
                    net["tenant_id"], net["id"],
                    new_port["id"], port["port"]["device_id"])
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxy: Unable to create remote port: %s" %
                e.message)
            super(QuantumRestProxy, self).delete_port(context, new_port["id"])
            raise

        # Set port state up and return that port
        port_update = {"port": {"admin_state_up": True}}
        return super(QuantumRestProxy, self).update_port(context,
                new_port["id"], port_update)

    def update_port(self, context, port_id, port):
        """
        Update values of a port.
        :param context: quantum api request context
        :param id: UUID representing the port to update.
        :param port: dictionary with keys indicating fields to update.

        :returns: a mapping sequence with the following signature:
        {
            "id": uuid represeting the port.
            "network_id": uuid of network.
            "tenant_id": tenant_id
            "mac_address": mac address to use on this port.
            "admin_state_up": sets admin state of port. if down, port
                               does not forward packets.
            "status": dicates whether port is currently operational
                       (limit values to "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "fixed_ips": list of subnet ID's and IP addresses to be used on
                         this port
            "device_id": identifies the device (e.g., virtual server) using
                         this port.
        }

        :raises: exceptions.StateInvalid
        :raises: exceptions.PortNotFound
        """

        LOG.debug("QuantumRestProxy: update_port() called")

        # Validate Args
        orig_port = super(QuantumRestProxy, self).get_port(context, port_id)

        # Update DB
        new_port = super(QuantumRestProxy, self).update_port(
                context, port_id, port)

        # update on networl ctrl
        try:
            resource = "/tenants/%s/networks/%s/ports/%s" % (
                    orig_port["tenant_id"], orig_port["network_id"], port_id)
            data = {
                    "port": new_port,
            }
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])

            if new_port.get("device_id") != orig_port.get("device_id"):
                if orig_port.get("device_id"):
                    self.unplug_interface(context,
                        orig_port["tenant_id"], orig_port["network_id"],
                        orig_port["id"])
                if new_port.get("device_id"):
                    self.plug_interface(context,
                        new_port["tenant_id"], new_port["network_id"],
                        new_port["id"], new_port["device_id"])

        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxy: Unable to create remote port: %s" %
                e.message)
            # reset port to original state
            super(QuantumRestProxy, self).update_port(
                    context, port_id, orig_port)
            raise

        # return new_port
        return new_port

    def delete_port(self, context, port_id):
        """
        Delete a port.
        :param context: quantum api request context
        :param id: UUID representing the port to delete.

        :raises: exceptions.PortInUse
        :raises: exceptions.PortNotFound
        :raises: exceptions.NetworkNotFound
        """

        LOG.debug("QuantumRestProxy: delete_port() called")

        # Delete from DB
        try:
            port = super(QuantumRestProxy, self).delete_port(context, port_id)
        except Exception, e:
            raise Exception("Failed to delete port: %s" % str(e))

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = "/tenants/%s/networks/%s/ports/%s" % (
                    port["tenant_id"], port["network_id"], port_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])

            if port.get("device_id"):
                self.unplug_interface(context,
                    port["tenant_id"], port["network_id"], port["id"])
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxy: Unable to update remote port: %s" %
                e.message)

        # return
        return port

    def plug_interface(self, context,
        tenant_id, net_id, port_id, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.

        :returns: None

        :raises: exceptions.NetworkNotFound
        :raises: exceptions.PortNotFound
        :raises: RemoteRestError
        """

        LOG.debug("QuantumRestProxy: plug_interface() called")

        # update attachment on network controller
        try:
            port = super(QuantumRestProxy, self).get_port(context, port_id)
            mac = port["mac_address"]

            for ip in port["fixed_ips"]:
                if ip.get("subnet_id") is not None:
                    subnet = super(QuantumRestProxy, self).get_subnet(
                        context, ip["subnet_id"])
                    gateway = subnet.get("gateway_ip")
                    if gateway is not None:
                        resource = "/tenants/%s/networks/%s" % (
                                tenant_id, net_id)
                        data = {
                            "network": {
                                "id": net_id,
                                "gateway": gateway,
                            }
                        }
                        ret = self.servers.put(resource, data)
                        if not self.servers.action_success(ret):
                            raise RemoteRestError(ret[2])

            if mac is not None:
                resource = "/tenants/%s/networks/%s/ports/%s/attachment" % (
                        tenant_id, net_id, port_id)
                data = {"attachment": {
                    "id": remote_interface_id,
                    "mac": mac,
                }}
                ret = self.servers.put(resource, data)
                if not self.servers.action_success(ret):
                    raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxy: Unable to update remote network: %s" %
                e.message)
            raise

        return None

    def unplug_interface(self, context,
        tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        network controller

        :returns: None

        :raises: RemoteRestError
        """

        LOG.debug("QuantumRestProxy: unplug_interface() called")

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = "/tenants/%s/networks/%s/ports/%s/attachment" % (
                    tenant_id, net_id, port_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxy: Unable to update remote port: %s" %
                e.message)

        return None

    def send_all_data(self):
        """
        Pushes all data to network ctrl (networks/ports, ports/attachments)
        to give the controller an option to re-sync it's persistent store
        with quantum's current view of that data.
        """
        admin_context = glbcontext.get_admin_context()
        networks = {}
        ports = {}

        nova_networks = self.get_networks(admin_context) or []
        for net in nova_networks:
            networks[net.get('id')] = {
                'id': net.get('id'),
                'name': net.get('name'),
                'op-status': net.get('admin_state_up'),
            }

            subnets = net.get('subnets') or []
            for subnet_id in subnets:
                subnet = self.get_subnet(admin_context, subnet_id)
                if subnet.get('gateway_ip') is not None:
                    # FIX: For backward compatibility with wire protocol
                    networks[net.get('id')]['gateway'] = \
                            subnet.get('gateway_ip')

            ports = []
            net_filter = {'network_id': [net.get('id')]}
            net_ports = self.get_ports(admin_context, filters=net_filter) or []
            for port in net_ports:
                port_details = {
                    'id': port.get('id'),
                    'attachment': {
                        'id': port.get('id') + '00',
                        'mac': port.get('mac_address'),
                    },
                    'state': port.get('status'),
                    'op-status': port.get('admin_state_up'),
                    'mac': None
                }
                ports.append(port_details)
            networks[net.get('id')]['ports'] = ports
        try:
            resource = '/topology'
            data = {
                'networks': networks,
            }
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                'QuantumRestProxy: Unable to update remote network: %s' %
                e.message)
            raise


# End
