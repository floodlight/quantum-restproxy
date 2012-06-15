#!/usr/bin/env python
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2010 OpenStack, LLC
# Copyright 2012, Big Switch Networks, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.


"""Unittest runner for QuantumRestProxy plugin

This file should be run from the top dir in the quantum directory
To run all tests::
  ./run_tests.sh
"""

import multiprocessing
import os
import sys
import warnings
from nose import config
from nose import core


sys.path.append(os.getcwd())
sys.path.append(os.path.dirname(__file__))


from quantum.api.api_common import OperationalStatus
from quantum.common.test_lib import run_tests, test_config
from quantum.plugins.restproxy.tests.test_server import TestNetworkCtrl
import quantum.tests.unit


if __name__ == '__main__':
    PLUGIN_DIR = 'quantum/plugins/restproxy'
    PLUGIN_MOD = 'quantum.plugins.restproxy.plugins.QuantumRestProxy'
    os.environ['PLUGIN_DIR'] = PLUGIN_DIR
    os.environ['PLUGIN_MOD'] = PLUGIN_MOD
    exit_status = False

    restproxy_netctrl = TestNetworkCtrl(port=8899,
        default_status='200 OK',
        default_response='{"status":"200 OK"}')
    restproxy_proc = multiprocessing.Process(
        target=restproxy_netctrl.run, args=())
    restproxy_proc.daemon = True
    restproxy_proc.start()

    restproxy_config = None
    restproxy_config_data = \
"""# test config
[restproxy]
debug=True
use_syslog=False
log_dir=/tmp
log_file=restproxy.log
proxydb=sqlite:///:memory:
novadb=sqlite:///:memory:
servers=localhost:%d
serverauth=
serverssl=
""" % restproxy_netctrl.port

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=RuntimeWarning)
        restproxy_config = os.tempnam('/tmp', 'restproxy-config-')
    with open(restproxy_config, "w") as fd:
        print >>fd, restproxy_config_data
    os.environ['RESTPROXY_CONFIG'] = restproxy_config

    test_config['plugin_name'] = PLUGIN_MOD
    test_config['default_net_op_status'] = OperationalStatus.UP
    test_config['default_port_op_status'] = OperationalStatus.DOWN

    # if a single test case was specified,
    # we should only invoked the tests once
    invoke_once = len(sys.argv) > 1

    cwd = os.getcwd()
    c = config.Config(stream=sys.stdout,
                      env=os.environ,
                      verbosity=3,
                      includeExe=True,
                      traverseNamespace=True,
                      plugins=core.DefaultPluginManager())
    c.configureWhere(quantum.tests.unit.__path__)
    exit_status = run_tests(c)

    if invoke_once:
        os.remove(restproxy_config)
        sys.exit(exit_status0)

    os.chdir(cwd)
    working_dir = os.path.abspath(PLUGIN_DIR)
    c = config.Config(stream=sys.stdout,
                      env=os.environ,
                      verbosity=3,
                      workingDir=working_dir)
    exit_status = exit_status or run_tests(c)

    os.remove(restproxy_config)
    sys.exit(exit_status)
