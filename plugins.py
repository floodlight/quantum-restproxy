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
from sqlalchemy import create_engine, orm, MetaData
from sqlalchemy import Table, Column, Integer, Text, VARCHAR

from quantum.api.api_common import OperationalStatus
from quantum.common import exceptions as exc
from quantum.db import api as db
from quantum.quantum_plugin_base import QuantumPluginBase
from version import version_string_with_vcs as version


gettext.install("quantum", unicode=1)
LOG = logging.getLogger('quantum.plugins.QuantumRestProxy')
LOG.setLevel(logging.INFO)


class ConfigurationError(exc.QuantumException):
    def __init__(self, message):
        if message is None:
            message = ""
        self.message = \
            _("Error in configuration file") + \
            ": " + message
        super(ConfigurationError, self).__init__()


class RemoteRestError(exc.QuantumException):
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


class NovaDbProxy(object):
    """
    Proxy for Nova controller that uses access to Nova DB

    Used for following functions:
    get_mac: lookup MAC address assigned to a virtual interface
    get_gateway: lookup gateway for a virtual network
    get_networks: list all networks
    """

    def __init__(self, novadb):
        self.nova_db = create_engine(novadb)
        self.nova_metadata = MetaData()
        self.nova_metadata.bind = self.nova_db
        self.nova_vifs = Table('virtual_interfaces', self.nova_metadata,
            Column('id', Integer),
            Column('uuid', VARCHAR(255)),
            Column('instance_id', Integer),
            Column('address', VARCHAR(36)))
        self.nova_vnets = Table('networks', self.nova_metadata,
            Column('id', Integer),
            Column('uuid', VARCHAR(255)),
            Column('project_id', VARCHAR(255)),
            Column('gateway', VARCHAR(36)))

    def get_mac(self, vif):
        try:
            vifq = self.nova_vifs.select(self.nova_vifs.c.uuid == str(vif))
            vifs = vifq.execute()
            if vifs.rowcount == 0:
                raise Exception(
                    'Matching vif not found in nova database: ' + str(vif))
            if vifs.rowcount > 1:
                raise Exception(
                    'More than one vif found in nova database!: ' + str(vif))
            (_, _, _, address) = vifs.fetchone()
            return address
        except Exception, excp:
            LOG.error(str(excp))
            return None

    def get_gateway(self, vnet):
        try:
            vnetq = self.nova_vnets.select(self.nova_vnets.c.uuid == str(vnet))
            vnets = vnetq.execute()
            if vnets.rowcount == 0:
                raise Exception(
                    'Matching network not found in nova database: ' +
                    str(vnet))
            if vnets.rowcount > 1:
                raise Exception(
                    'More than one network found in nova database!: ' +
                    str(vnet))
            (_, _, _, gateway) = vnets.fetchone()
            return gateway
        except Exception, excp:
            LOG.error(str(excp))
            return None

    def get_networks(self):
        ret = []
        try:
            vnetq = self.nova_vnets.select()
            vnets = vnetq.execute()
            for i in range(vnets.rowcount):
                (_, net_id, tenant_id, _) = vnets.fetchone()
                if tenant_id is None:
                    tenant_id = 'default'
                ret.append((tenant_id, net_id))
        except Exception, excp:
            LOG.error(str(excp))
            return None
        return ret


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


class QuantumRestProxy(QuantumPluginBase):

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
        LOG.info('QuantumRestProxy: Starting plugin. Version=%s' % version())

        # read config
        proxydb = self.conf.get('proxydb') or \
                'mysql://root@localhost/restproxy'
        novadb = self.conf.get('novadb') or \
                'mysql://root@localhost/nova'
        servers = self.conf.get('servers')
        serverauth = self.conf.get('serverauth')
        serverssl = self.conf.get_bool('serverssl')

        # validate config
        assert novadb or novaauth, 'Nova must be accessible from plugin'
        assert servers is not None, 'Servers not defined. Aborting plugin'
        servers = tuple(s.split(':') for s in servers.split(','))
        servers = tuple((server, int(port)) for server, port in servers)
        assert all(len(s) == 2 for s in servers), \
                'Syntax error in servers in config file. Aborting plugin'

        # init DB, nova and network ctrl connections
        db.configure_db({'sql_connection': proxydb})
        self.nova = NovaDbProxy(novadb)
        self.servers = ServerPool(servers, serverssl, serverauth)

    def setup_logging(self):
        root_logger = LOG
        LOG_FORMAT = "%(asctime)s %(levelname)8s [%(name)s] %(message)s"
        LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

        if self.conf.get_bool('debug'):
            root_logger.setLevel(logging.DEBUG)
        elif self.conf.get_bool('verbose'):
            root_logger.setLevel(logging.INFO)
        else:
            root_logger.setLevel(logging.WARNING)

        # Set log configuration from options or defaults
        log_format = self.conf.get('log_format') or LOG_FORMAT
        log_date_format = self.conf.get('log_date_format') or LOG_DATE_FORMAT
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

    def get_network(self, tenant_id, network_id):
        db.validate_network_ownership(tenant_id, network_id)
        try:
            network = db.network_get(network_id)
        except:
            raise exc.NetworkNotFound(net_id=network_id)
        return network

    def get_port(self, tenant_id, network_id, port_id):
        db.validate_port_ownership(tenant_id, network_id, port_id)
        net = self.get_network(tenant_id, network_id)
        try:
            port = db.port_get(port_id, network_id)
        except:
            raise exc.PortNotFound(net_id=network_id, port_id=port_id)

        # Port must exist and belong to the appropriate network.
        if port['network_id'] != net['uuid']:
            raise exc.PortNotFound(net_id=network_id, port_id=port_id)
        return port

    def make_port_dict(self, port):
        if port.state == "ACTIVE":
            op_status = port.op_status
        else:
            op_status = OperationalStatus.DOWN

        return {
            'port-id': str(port.uuid),
            'port-state': port.state,
            'port-op-status': op_status,
            'net-id': port.network_id,
            'attachment': port.interface_id
        }

    def filter_net(self, filter_opts, net):
        return net

    def filter_port(self, filter_opts, port):
        return port

    def validate_port_state(self, port_state):
        if port_state.upper() not in ('ACTIVE', 'DOWN'):
            raise exc.StateInvalid(port_state=port_state)
        return True

    def validate_attachment(self, tenant_id, network_id, port_id,
                             remote_interface_id):
        for port in db.port_list(network_id):
            if port['interface_id'] == remote_interface_id:
                raise exc.AlreadyAttached(net_id=network_id,
                                          port_id=port_id,
                                          att_id=port['interface_id'],
                                          att_port_id=port['uuid'])

    def get_all_networks(self, tenant_id, **kwargs):
        """
        Returns a dictionary containing all <network_uuid, network_name> for
        the specified tenant using local persistent store.

        :param tenant_id: unique identifier for the tenant whose networks
            are being retrieved by this method
        :param **kwargs: options to be passed to the plugin. The following
            keywork based-options can be specified:
            filter_opts - options for filtering network list
        :returns: a list of mapping sequences with the following signature:
                     [ {'net-id': uuid that uniquely identifies
                                      the particular quantum network,
                        'net-name': a human-readable name associated
                                      with network referenced by net-id
                        'net-op-status': network op_status
                       },
                       ....
                       {'net-id': uuid that uniquely identifies the
                                       particular quantum network,
                        'net-name': a human-readable name associated
                                       with network referenced by net-id
                        'net-op-status': network op_status
                       }
                    ]
        :raises: None
        """
        LOG.debug("QuantumRestProxy: get_all_networks() called")

        filter_fn = None
        filter_opts = kwargs.get('filter_opts', None)
        if filter_opts is not None and len(filter_opts) > 0:
            filter_fn = self.filter_net
            LOG.debug("QuantumRestProxy: filter_opts ignored: %s" %
                      filter_opts)

        nets = []
        for net in db.network_list(tenant_id):
            if filter_fn is not None and \
               filter_fn(filter_opts, net) is None:
                continue
            net_item = {
                'net-id': str(net.uuid),
                'net-name': net.name,
                'net-op-status': net.op_status,
            }
            nets.append(net_item)
        return nets

    def get_network_details(self, tenant_id, net_id):
        """
        Retrieves a list of all the remote vifs that
        are attached to the network.

        :returns: a sequence of mappings with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                particular quantum network
                     'net-name': a human-readable name associated
                                 with network referenced by net-id
                     'net-ports': [{"port-id": "vif1"},
                                   {"port-id": "vif2"},...,
                                   {"port-id": "vifn"}]
                    }
        :raises: exception.NetworkNotFound
        """
        LOG.debug("QuantumRestProxy: get_network_details() called")
        net = self.get_network(tenant_id, net_id)
        ports = self.get_all_ports(tenant_id, net_id)
        return {
            'net-id': str(net.uuid),
            'net-name': net.name,
            'net-op-status': net.op_status,
            'net-ports': ports,
        }

    def create_network(self, tenant_id, net_name, **kwargs):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.

        :returns: a sequence of mappings with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                     particular quantum network,
                     'net-name': a human-readable name associated
                                    with network referenced by net-id
                    }
        :raises:
        """
        LOG.debug("QuantumRestProxy: create_network() called")

        # create in DB
        new_net = db.network_create(tenant_id, net_name)
        db.network_update(new_net.uuid, net_name,
                          op_status=OperationalStatus.UP)
        net_id = str(new_net.uuid)

        # create on networl ctrl
        try:
            resource = '/tenants/%s/networks' % tenant_id
            data = {
                "network": {
                    "id": net_id,
                    "name": net_name,
                    "gateway": self.nova.get_gateway(net_id),
                }
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                'QuantumRestProxy: Unable to create remote network: %s' %
                e.message)
            db.network_destroy(net_id)
            raise

        # return created network
        return {
                'net-id': net_id,
                'net-name': net_name,
        }

    def update_network(self, tenant_id, net_id, **kwargs):
        """
        Updates the attributes of a particular Virtual Network.

        :returns: a sequence of mappings representing the new network
                    attributes, with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                 particular quantum network
                     'net-name': the new human-readable name
                                  associated with network referenced by net-id
                    }
        :raises: exception.NetworkNotFound
        """
        LOG.debug("QuantumRestProxy.update_network() called")
        orig_net = self.get_network(tenant_id, net_id)

        # update DB
        net = db.network_update(net_id, tenant_id, **kwargs)

        # update network on network controller
        try:
            if kwargs:
                resource = '/tenants/%s/networks/%s' % (tenant_id, net_id)
                data = {
                    "network": kwargs,
                }
                ret = self.servers.put(resource, data)
                if not self.servers.action_success(ret):
                    raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                'QuantumRestProxy: Unable to update remote network: %s' %
                e.message)
            # reset network to original state
            orig_net = dict((k.split('-')[-1], v)
                for k, v in orig_net.items())
            if 'id' in orig_net:
                orig_net.pop('id')
            db.network_update(net_id, tenant_id, **orig_net)
            raise

        # return updated network
        return net

    def delete_network(self, tenant_id, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.

        :returns: a sequence of mappings with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                 particular quantum network
                    }
        :raises: exception.NetworkInUse
        :raises: exception.NetworkNotFound
        """
        LOG.debug("QuantumRestProxy: delete_network() called")
        net = self.get_network(tenant_id, net_id)
        for port in db.port_list(net_id):
            if port['interface_id']:
                raise exc.NetworkInUse(net_id=net_id)

        # Delete from DB
        db.network_destroy(net_id)

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = '/tenants/%s/networks/%s' % (tenant_id, net_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                'QuantumRestProxy: Unable to update remote network: %s' %
                e.message)

        # return deleted network
        return net

    def get_all_ports(self, tenant_id, net_id, **kwargs):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        :param tenant_id: unique identifier for the tenant for which this
            method is going to retrieve ports
        :param net_id: unique identifiers for the network whose ports are
            about to be retrieved
        :param **kwargs: options to be passed to the plugin. The following
            keywork based-options can be specified:
            filter_opts - options for filtering network list
        :returns: a list of mapping sequences with the following signature:
                     [ {'port-id': uuid representing a particular port
                                    on the specified quantum network
                       },
                       ....
                       {'port-id': uuid representing a particular port
                                     on the specified quantum network
                       }
                    ]
        :raises: exception.NetworkNotFound
        """
        LOG.debug("QuantumRestProxy: get_all_ports() called")
        db.validate_network_ownership(tenant_id, net_id)

        filter_fn = None
        filter_opts = kwargs.get('filter_opts', None)
        if filter_opts is not None and len(filter_opts) > 0:
            filter_fn = self.filter_port
            LOG.debug("QuantumRestProxy: filter_opts ignored: %s" %
                      filter_opts)

        port_ids = []
        ports = db.port_list(net_id)
        for port in ports:
            if filter_fn is not None and \
               filter_fn(filter_opts, port) is None:
                continue
            d = {
                'port-id': str(port.uuid),
            }
            port_ids.append(d)
        return port_ids

    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the port on
                                 specified quantum network
                     'attachment': uuid of the virtual interface
                                   bound to the port, None otherwise
                     'port-state': port state
                     'port-op-state': port operation state
                    }
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        LOG.debug("QuantumRestProxy: get_port_details() called")
        port = self.get_port(tenant_id, net_id, port_id)
        return self.make_port_dict(port)

    def create_port(self, tenant_id, net_id, port_state=None, **kwargs):
        """
        Creates a port on the specified Virtual Network.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the created port
                                   on specified quantum network
                    }
        :raises: exception.NetworkNotFound
        :raises: exception.StateInvalid
        """
        LOG.debug("QuantumRestProxy: create_port() called")
        self.get_network(tenant_id, net_id)

        # Update DB
        port = db.port_create(net_id, port_state,
                    op_status=OperationalStatus.DOWN)
        port_id = str(port.uuid)

        # create on networl ctrl
        try:
            resource = '/tenants/%s/networks/%s/ports' % (
                    tenant_id, net_id)
            data = {
                "port": {
                    "id": port_id,
                    "state": port_state,
                }
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                'QuantumRestProxy: Unable to create remote port: %s' %
                e.message)
            db.port_destroy(port_id, net_id)
            raise

        return self.make_port_dict(port)

    def update_port(self, tenant_id, net_id, port_id, **kwargs):
        """
        Updates the attributes of a specific port on the
        specified Virtual Network.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the
                                 updated port on specified quantum network
                     'port-state': update port state( UP or DOWN)
                    }
        :raises: exception.StateInvalid
        :raises: exception.PortNotFound
        """
        LOG.debug("QuantumRestProxy: update_port() called")
        self.get_network(tenant_id, net_id)
        orig_port = self.get_port(tenant_id, net_id, port_id)

        # Update DB
        port = db.port_update(port_id, net_id, **kwargs)

        # update on networl ctrl
        try:
            resource = '/tenants/%s/networks/%s/ports/%s' % (
                    tenant_id, net_id, port_id)
            data = {
                    "port": kwargs,
            }
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                'QuantumRestProxy: Unable to create remote port: %s' %
                e.message)
            # reset port to original state
            orig_port = dict((k.split('-')[-1], v)
                for k, v in orig_port.items())
            if 'id' in orig_port:
                orig_port.pop('id')
            db.port_update(net_id, tenant_id, **orig_port)
            raise

        return self.make_port_dict(port)

    def delete_port(self, tenant_id, net_id, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the deleted port
                                 on specified quantum network
                    }
        :raises: exception.PortInUse
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        LOG.debug("QuantumRestProxy: delete_port() called")
        net = self.get_network(tenant_id, net_id)
        port = self.get_port(tenant_id, net_id, port_id)
        if port['interface_id']:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['interface_id'])

        # Delete from DB
        try:
            port = db.port_destroy(port_id, net_id)
        except Exception, e:
            raise Exception("Failed to delete port: %s" % str(e))

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = '/tenants/%s/networks/%s/ports/%s' % (
                    tenant_id, net_id, port_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                'QuantumRestProxy: Unable to update remote port: %s' %
                e.message)

        return self.make_port_dict(port)

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.

        :returns: None
        :raises: exception.NetworkNotFound
        :raises: exception.PortNotFound
        :raises: exception.AlreadyAttached
                    (? should the network automatically unplug/replug)
        """
        LOG.debug("QuantumRestProxy: plug_interface() called")
        port = self.get_port(tenant_id, net_id, port_id)
        self.validate_attachment(tenant_id, net_id, port_id,
                                  remote_interface_id)
        if port['interface_id']:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['interface_id'])

        # Update DB
        db.port_set_attachment(port_id, net_id, remote_interface_id)

        # update attachment on network controller
        try:
            net_name = self.get_network(tenant_id, net_id).name
            gateway = self.nova.get_gateway(net_id)
            mac = self.nova.get_mac(remote_interface_id)

            if gateway is not None:
                resource = '/tenants/%s/networks/%s' % (
                        tenant_id, net_id)
                data = {
                    "network": {
                        "id": net_id,
                        "gateway": gateway,
                        "name": net_name,
                    }
                }
                ret = self.servers.put(resource, data)
                if not self.servers.action_success(ret):
                    raise RemoteRestError(ret[2])

            if mac is not None:
                resource = '/tenants/%s/networks/%s/ports/%s/attachment' % (
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
                'QuantumRestProxy: Unable to update remote network: %s' %
                e.message)
            # undo the connect
            db.port_unset_attachment(port_id, net_id)
            raise

    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.

        :returns: None
        :raises: exception.NetworkNotFound
        :raises: exception.PortNotFound
        """
        LOG.debug("QuantumRestProxy: unplug_interface() called")
        self.get_port(tenant_id, net_id, port_id)

        # Update DB
        db.port_unset_attachment(port_id, net_id)

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = '/tenants/%s/networks/%s/ports/%s/attachment' % (
                    tenant_id, net_id, port_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                'QuantumRestProxy: Unable to update remote port: %s' %
                e.message)

    def send_all_data(self):
        """
        Pushes all data to network ctrl (networks/ports, ports/attachments)
        to give the controller an option to re-sync it's persistent store
        with quantum's current view of that data.
        """
        networks = {}
        ports = {}

        nova_networks = self.nova.get_networks() or []
        for (tenant_id, net_id) in nova_networks:
            net = self.get_network_details(tenant_id, net_id)
            networks[net_id] = {
                'id': net.get('net-id'),
                'name': net.get('net-name'),
                'gateway': self.nova.get_gateway(net_id),
                'op-status': net.get('net-op-status'),
            }

            ports = []
            net_ports = net.get('net-ports') or []
            for port in net_ports:
                port_id = port.get('port-id')
                port = self.get_port_details(tenant_id, net_id, port_id)
                port_details = {
                    'id': port.get('port-id'),
                    'attachment': {
                        'id': port.get('attachment'),
                    },
                    'state': port.get('port-state'),
                    'op-status': port.get('port-op-status'),
                    'mac': None
                }
                if port['attachment']:
                    port_details['attachment']['mac'] = \
                        self.nova.get_mac(port['attachment'])
                ports.append(port_details)
            networks[net_id]['ports'] = ports
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
