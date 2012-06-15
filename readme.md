# Quantum REST Proxy Plug-in 

## Overview

This module provides a generic quantum plugin 'QuantumRestProxy' that
translates quantum function calls to authenticated REST request to a
set of redundant external network controllers.

This allows the network controller specific code to be decoupled from this
plugin. This allows for:
1. independent authentication and redundancy solutions for quantum and the
   network ccontroller since they are now decoupled.
2. independent upgrade/development cycles for quantum and network controller
   since it limits the proxy code upgrade requirement to quantum release cycle
   (and the network controller specific code upgrade requirement to network
   controller release cycle).

It also keeps a local persistent store of quantum state that has been
setup using that API. This allows us to:
1. independently update/recover the external network controller(s) as their
   state can now be updated to be in sync with the state previously
   programmed via the API.
2. provide local response for query operations and fail-fast when it can be
   determined based on previously configured state.

## Downstream REST API

Downstream REST API used by this proxy is almost same as the API as defined
for quantum itself (more specifically, the JSON subset with some additional
parameters, e.g. gateway on network-create request and macaddr on port-attach
request). In addition, it also requires support for an additional PUT to do a
bulk dump of all persistent data; this is used for state synchronization (if
supported).

## Usage of this plugin

### System known to use this plugin

#### Big Switch Networks Controller

Big Switch Networks controller uses this plugin to provide access to their
network virtualization solution. It allows you to create SDN based flexible
and secure connectivity between VMs.

This plugin is a part of Big Switch Networks solution that consists of 4
components:
1. An openstack controller running the nova and quantum services
2. A Big Switch Controller running Big Switch Networks's BVS application
3. This plugin, which translates nova/quantum api to generic REST requests
4. And an OpenVswitch (OVS) running on each of the the nova-compute nodes

> **NOTE:**
>     There might also be other physical/virtual switches or middle boxes
>     in your network, refer to Big Switch Networks documentation regarding
>     using them transparently with this plugin.

#### Floodlight Openflow Controller

Floodlight controller uses this plugin to provide openflow/VLAN based virtual
networks. Please refer to Floodlight documentation on configuration/usage in
that context.

### Configuration

The sections below describe how to configure and run the a system using this
plugin.

#### Nova configuration (controller node)

Configure nova-network to use quantum network manager. In the nova.conf add:
>   network_manager=nova.network.quantum.manager.QuantumManager

#### Nova configuration (compute nodes)

Configure the vif driver, and libvirt/vif type to use OVS. In nova.conf add:
>   connection_type=libvirt
>   libvirt_ovs_bridge=br-int
>   libvirt_vif_type=ethernet
>   libvirt_vif_driver=nova.virt.libvirt.vif.LibvirtOpenVswitchDriver
>   linuxnet_interface_driver=nova.network.linux_net.LinuxOVSInterfaceDriver
 
Configure VMs to use DHCP to accquire control network address. In nova.conf add:
>    quantum_use_dhcp=True

Apply nova.patch for LinuxNetNoNatL3 and make following updates to nova.conf:
>   l3_lib=nova.network.l3.LinuxNetNoNatL3
>   firewall_driver=nova.virt.firewall.NoopFirewallDriver

#### Quantum configuration (quantum controller node)

Configure quantum and restproxy. If an ubuntu server is hosting the quantum
controller, you can do it with the script provided in scripts dir (after
editing it for mysql username/password etc):
    $ <plugin-dir>/scripts/install-plugin.sh <network-controllers>

On non-ubuntu servers, do the following:
1. Edit etc/plugins.ini and set provider as:
>    [PLUGIN]
>    provider = quantum.plugins.restproxy.plugins.QuantumRestProxy

2. Edit /etc/quantum/plugins/restproxy/restproxy.ini as required.
   In particular, the configured logfile must be writable by restproxy
   (in this example /var/log/restproxy.log)
>   debug=False
>   use_syslog=False
>   log_file=restproxy.log
>   log_dir=/var/log
>   proxydb=mysql://root:pass@localhost/restproxy
>   novadb=mysql://root:pass@localhost/nova
>   servers=192.168.1.100:80,192.168.1.101:80
>   serverauth=user:pass
>   serverssl=False

3. MySQL should be installed on the host. Initialize MySQL as follows
   (where $PASS = mysql password):
>    $ mysql -u root -p$PASS -e 'DROP DATABASE IF EXISTS restproxy;'
>    $ mysql -u root -p$PASS -e 'CREATE DATABASE IF NOT EXISTS restproxy;'

  
#### OVS configuration (compute nodes)

Install OVS on nova compute nodes. If you are using an ubuntu server for nova
compute node, you can use the install script provided in scripts dir to do it
as follows:
    $ <plugin-dir>/scripts/install-node.sh

On other platforms, please refer to the OVS documentation, then do the
equivalent to the following:
>   NETWORK_CONTROLERS=<comma-seperated-list-of-network-ctrls>
>   sudo ovs-vsctl --no-wait -- --if-exists del-br br-int
>   sudo ovs-vsctl --no-wait add-br br-int
>   sudo ovs-vsctl --no-wait br-set-external-id br-int bridge-id br-int
>   for ctrl in `echo ${NETWORK_CONTROLERS} | tr ',' ' '`
>   do
>       sudo ovs-vsctl set-controller br-int "tcp:${ctrl}:6633"
>   done

### Running Tests

To run tests related to the Plugin run the following from the top level Quantum
directory:
  PLUGIN_DIR=quantum/plugins/restproxy ./run_tests.sh -N
