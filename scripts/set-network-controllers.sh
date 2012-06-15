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

# USAGE:
# Set up quantum configuration for network controller. Use as:
#   set-network-controllers.sh <network-ctrls> [<auth-params> [<use-ssl>]]
#
# e.g.:
#   set-network-controllers.sh 192.168.2.100:80,192.168.2.101:80 user:pass true
#
USAGE="$0 <network-ctrls> [<auth-params> [<use-ssl>]]"


# Globals
set -e
NETWORK_CTRL_SERVERS="$1"
NETWORK_CTRL_AUTH="$2"
NETWORK_CTRL_SSL=`echo $3 | tr A-Z a-z`
RESTPROXY_INI_FILE=/etc/quantum/plugins/restproxy/restproxy.ini


# validate parameters
if [ "${NETWORK_CTRL_SERVERS}"x = ""x ] ; then
    echo "USAGE: $USAGE" 2>&1
    echo "  >  No Network Controller specified." 1>&2
    exit 1
fi
if [ "${NETWORK_CTRL_SSL}"x != ""x -a \
     "${NETWORK_CTRL_SSL}"x != "true"x -a \
     "${NETWORK_CTRL_SSL}"x != "false"x ] ; then
    echo "USAGE: $USAGE" 2>&1
    echo "  >  parameter 'use-ssl' must be 'true' or 'false'," \
         " not '${NETWORK_CTRL_SSL}'" 1>&2
    exit 2
fi


# set parameters
sudo sed -i -e "s/^\s*servers\s*=.*$/servers = ${NETWORK_CTRL_SERVERS}/g" \
            -e "s/^\s*serverauth\s*=.*$/serverauth = ${NETWORK_CTRL_AUTH}/g" \
            -e "s/^\s*serverssl\s*=.*$/serverssl = ${NETWORK_CTRL_SSL}/g" \
            ${RESTPROXY_INI_FILE}

# Done
echo "$0 Done."
echo
