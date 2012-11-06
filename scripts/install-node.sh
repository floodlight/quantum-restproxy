#!/bin/sh
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011, Big Switch Networks, Inc.
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
#

# USAGE
# Install OVS on nova compute nodes. Use as:
#   ./install.node.sh <comma-separated-list-of-controllers>
#
# e.g.
#   ./install.node.sh 192.168.1.1,192.168.1.2
USAGE="$0  <comma-separated-list-of-controllers>"


# Globals
set -e
NETWORK_CONTROLERS=
OVS_BRIDGE=br-int


# Process args
NETWORK_CONTROLERS=$1
echo -n "Installing OVS managed by the openflow controllers:"
echo ${NETWORK_CONTROLERS}
if [ "${NETWORK_CONTROLERS}"x = ""x ] ; then
    echo "USAGE: $USAGE" 2>&1
    echo "  >  No Network Controller specified." 1>&2
    exit 1
fi


# install openvswitch
kernel_version=`cat /proc/version | cut -d " " -f3`
sudo apt-get -y install \
    openvswitch-switch openvswitch-datapath-dkms \
    linux-headers-$kernel_version bridge-utils


# Create local OVS bridge and configure it
sudo ovs-vsctl --no-wait -- --if-exists del-br ${OVS_BRIDGE}
sudo ovs-vsctl --no-wait add-br ${OVS_BRIDGE}
sudo ovs-vsctl --no-wait br-set-external-id ${OVS_BRIDGE} bridge-id br-int

ctrls=
for ctrl in `echo ${NETWORK_CONTROLERS} | tr ',' ' '`
do
    ctrls="${ctrls} tcp:${ctrl}:6633"
done
echo "Adding Network conttrollers: " ${ctrls}
sudo ovs-vsctl --no-wait set-controller ${OVS_BRIDGE} ${ctrls}


# Done
echo "$0 Done."
echo
