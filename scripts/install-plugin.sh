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
#   ./install-plugin.sh <network-ctrls> [<auth-params> [<use-ssl>]]
#
# e.g.:
#   ./install-plugin.sh 192.168.2.100:80,192.168.2.101:80 user:pass true
#
USAGE="$0 <network-ctrls> [<auth-params> [<use-ssl>]]"


# Globals
set -e
NETWORK_CTRL_SERVERS="$1"
NETWORK_CTRL_AUTH="$2"
NETWORK_CTRL_SSL=`echo $3 | tr A-Z a-z`
MYSQL_USER=root
MYSQL_PASSWORD=nova
QUANTUM_INI_FILE=/etc/quantum/plugins.ini
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


# setup quantum to use restproxy
if [ -f "${QUANTUM_INI_FILE}" ] ; then
    PLUGIN=quantum.plugins.restproxy.plugins.QuantumRestProxy
    sudo sed -i -e "s/^\s*provider\s*=.*$/provider = $PLUGIN/g" \
        ${QUANTUM_INI_FILE}
else
    echo "ERROR: Did not find the Quantum INI file: ${QUANTUM_INI_FILE}" 1>&2
    exit 3
fi


# setup mysql for restproxy
mysql_cmd() {
    if [ "${MYSQL_PASSWORD}"x = ""x ]
    then
        mysql -u ${MYSQL_USER} -e "$1"
    else
        mysql -u ${MYSQL_USER} -p${MYSQL_PASSWORD} -e "$1"
    fi
}
mysql_cmd 'DROP DATABASE IF EXISTS restproxy;'
mysql_cmd 'CREATE DATABASE IF NOT EXISTS restproxy;'


# setup proxy configuration
MYSQL_AUTH="${MYSQL_USER}"
[ "${MYSQL_PASSWORD}"x = ""x ] || MYSQL_AUTH="${MYSQL_USER}:${MYSQL_PASSWORD}"
cat <<EOF > /tmp/restproxy.ini
[restproxy]
#
# Configure restproxy
#
# The following parameters are supported:
#   debug       :   true | false                (Default: false)
#   use_syslog  :   true | false                (Default: false)
#   log_file    :   <name of file>              (Default: None, use stdout)
#   log_dir     :   <dir-name>
#                   The plugin must have write permissions to that file/dir
#   log_format  :   <log format>
#   log_date_format: <log date format>
#   servers     :   <host:port>[,<host:port>]*  (Error if not set)
#   serverauth  :   <username:password>         (default: no auth)
#   serverssl   :   true | false                (default: false)
#   proxydb     :   <db-string> (default: mysql://root@localhost/restproxy)
#   novadb      :   <db-string> (default: mysql://root@localhost/nova)
#
debug = false
use_syslog = false
#log_file = restproxy.log
#log_dir = /var/log
proxydb = mysql://${MYSQL_AUTH}@localhost/restproxy
novadb = mysql://${MYSQL_AUTH}@localhost/nova

#
# Network controllers
#
servers = ${NETWORK_CTRL_SERVERS}
serverauth = ${NETWORK_CTRL_AUTH}
serverssl = ${NETWORK_CTRL_SSL}
EOF

sudo mkdir -p `dirname ${RESTPROXY_INI_FILE}`
sudo cp /tmp/restproxy.ini ${RESTPROXY_INI_FILE}

# Done
echo "$0 Done."
echo
