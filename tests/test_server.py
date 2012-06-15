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
Test server mocking a REST based network ctrl. Used for QuantumRestProxy tests
"""

import json
import re
from wsgiref.simple_server import make_server
from wsgiref.util import request_uri, application_uri


class TestNetworkCtrl(object):
    def __init__(self, host='', port=8000,
                 default_status='404 Not Found',
                 default_response='404 Not Found',
                 debug=False):
        self.host = host
        self.port = port
        self.default_status = default_status
        self.default_response = default_response
        self.debug = debug
        self.debug_env = False
        self.debug_resp = False
        self.matches = []

    def match(self,
            prior, method_regexp, uri_regexp,
            handler, data=None, multi=True):
        """
        Adds to the list of exptected inputs. The incomming request is
        matched in the order of priority. For same priority, match the
        oldest match request first.

        :param prior: intgere priority of this match (e.g. 100)
        :param method_regexp: regexp to match method (e.g. 'PUT|POST')
        :param uri_regexp: regexp to match uri (e.g. '/quantum/v?.?/')
        :param handler: function with signature:
            lambda(method, uri, body, **kwargs) : status, body
              where
                  - method: HTTP method for this request
                  - uri: URI for this HTTP request
                  - body: body of this HTTP request
                  - kwargs are:
                      - data: data object that was in the match call
                      - node: TestNetworkCtrl object itself
                      - id: offset of the matching tuple
              and return values is:
                (status, body) where:
                - status: HTTP resp status (e.g. '200 OK').
                          If None, use default_status
                - body: HTTP resp body. If None, use ''
        """
        assert int(prior) == prior, 'Priority should an integer be >= 0'
        assert prior >= 0, 'Priority should an integer be >= 0'

        lo, hi = 0, len(self.matches)
        while lo < hi:
            mid = (lo + hi) // 2
            if prior < self.matches[mid]:
                hi = mid
            else:
                lo = mid + 1
        self.matches.insert(lo,
                (prior, method_regexp, uri_regexp, handler, data, multi))

    def remove_id(self, id_):
        assert id_ >= 0, 'remove_id: id < 0'
        assert id_ <= len(self.matches), 'remove_id: id > len()'
        self.matches.pop(id_)

    def remove_match(self, prior, method_regexp, uri_regexp):
        for i in self.matches:
            if (i[0], i[1], i[2]) == (method_regexp, uri_regexp, idstr):
                self.remove_id(i)
                break

    def request_handler(self, method, uri, body):
        retstatus = self.default_status
        retbody = self.default_response
        for i in xrange(len(self.matches)):
            (prior, method_regexp, uri_regexp, handler, data, multi) = \
                    self.matches[i]
            if re.match(method_regexp, method) and re.match(uri_regexp, uri):
                kwargs = {
                    'data': data,
                    'node': self,
                    'id': i,
                }
                retstatus, retbody = handler(method, uri, body, **kwargs)
                if multi is False:
                    self.remove_id(i)
                break
        if retbody is None:
            retbody = ''
        return (retstatus, retbody)

    def server(self):
        def app(environ, start_response):
            uri = environ['PATH_INFO']
            method = environ['REQUEST_METHOD']
            headers = [('Content-type', 'text/json')]
            content_len_str = environ['CONTENT_LENGTH']

            content_len = 0
            request_data = None
            if content_len_str:
                content_len = int(content_len_str)
                request_data = environ.get('wsgi.input').read(content_len)
                if request_data:
                    try:
                        request_data = json.loads(request_data)
                    except:
                        # OK for it not to be json! Ignore it
                        pass

            if self.debug:
                print '\n'
                if self.debug_env:
                    print '%s:' % 'environ:'
                    for (key, value) in sorted(environ.iteritems()):
                        print '  %16s : %s' % (key, value)

                print '%s %s' % (method, uri)
                if request_data:
                    print '%s' % (
                          json.dumps(request_data, sort_keys=True, indent=4))

            status, body = self.request_handler(method, uri, None)
            body_data = None
            if body:
                try:
                    body_data = json.loads(body)
                except:
                    # OK for it not to be json! Ignore it
                    pass

            start_response(status, headers)
            if self.debug:
                if self.debug_env:
                    print '%s: %s' % ('Response',
                          json.dumps(body_data, sort_keys=True, indent=4))
            return body
        return make_server(self.host, self.port, app)

    def run(self):
        print "Serving on port %d ..." % self.port
        try:
            self.server().serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    import sys

    port = 8899
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    debug = False
    if len(sys.argv) > 2:
        if sys.argv[2].lower() in ['debug', 'true']:
            debug = True

    ctrl = TestNetworkCtrl(port=port,
                           default_status='200 OK',
                           default_response='{"status":"200 OK"}',
                           debug=debug)
    ctrl.match(100, 'GET', '/test', \
               lambda m, u, b, **k: ('200 OK', '["200 OK"]'))
    ctrl.run()
