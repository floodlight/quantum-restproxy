#! /usr/bin/env python
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
#   ./sync_network.py
#


import sys
import warnings


with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from quantum.plugins.restproxy.plugin import QuantumRestProxyV2
from quantum.openstack.common import cfg


def do_send_all_data():
    """Send all data to the configured network controller
       retunrs: None on success, else the reason for error (string)
    """
    try:
        rproxy = QuantumRestProxyV2()
        print "INFO: Using servers: ", cfg.CONF.RESTPROXY.servers
        rproxy._send_all_data()
    except Exception as e:
        return e.message
    return None

if __name__ == "__main__":
    cfg.CONF(args = [
        '--config-file',
        '/etc/quantum/plugins/restproxy/restproxy.ini'
        ], project='quantum')
    ret = do_send_all_data()
    if ret is not None:
        print "ERROR: In sending data to network controller"
        print "       " + str(ret)
        sys.exit(1)
    print "Sync Done. All data (re)sent to the network controller"
    sys.exit(0)
