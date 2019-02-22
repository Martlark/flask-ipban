# Copyright 2019 Andrew Rowe.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import

import unittest

import flask

from flask_ipban.ip_ban import IpBan

page_text = 'Hello, world'


def hello_world():
    return page_text


class TestIpBan(unittest.TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.ipBan = IpBan(self.app)
        self.client = self.app.test_client()

        self.app.route('/')(hello_world)

    def testDefaults(self):
        # HTTPS request.
        response = self.client.get('/')
        self.assertEquals(response.status_code, 200)
