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

import re
import time
import unittest

import flask

from flask_ipban.ip_ban import IpBan

page_text = 'Hello, world'
localhost = '127.0.0.1'

def hello_world():
    return page_text


class TestIpBan(unittest.TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.ban_seconds = 2
        self.ip_ban = IpBan(self.app, ban_seconds=self.ban_seconds, ban_count=5)
        self.client = self.app.test_client()

        self.app.route('/')(hello_world)

    def testDefaults(self):
        # HTTPS request.
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def testAddRemoveIpWhitelist(self):
        self.assertEqual(self.ip_ban.ip_whitelist_add(localhost), 1)
        for x in range(self.ip_ban.ban_count*2):
            response = self.client.get('/doesnotexist')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.ip_ban.ip_whitelist_remove(localhost))
        for x in range(self.ip_ban.ban_count*2):
            response = self.client.get('/doesnotexist')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.ip_ban.ip_whitelist_remove(localhost))

    def testAddRemoveUrlWhitelist(self):
        test_pattern = '^/no_exist/[0-9]+$'
        test_url = '/no_exist'
        self.assertTrue(re.match(test_pattern, test_url+'/123'))
        self.assertFalse(re.match(test_pattern, test_url))

        self.assertEqual(self.ip_ban.url_pattern_add(test_pattern), 1)
        for x in range(self.ip_ban.ban_count*2):
            self.client.get('{}/{}'.format(test_url, x))
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

        self.assertTrue(self.ip_ban.url_pattern_remove(test_pattern))
        for x in range(self.ip_ban.ban_count*2):
            self.client.get('{}/{}'.format(test_url, x))
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)

        self.assertFalse(self.ip_ban.url_pattern_remove(localhost))

    def testBlock(self):
        self.assertEqual(self.ip_ban.block([localhost, '123.1.1.3']), 2)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)

    def testTimeout(self):
        test_url = '/doesnotexist'
        for x in range(self.ip_ban.ban_count*2):
            self.client.get('{}/{}'.format(test_url, x))
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)
        time.sleep(self.ban_seconds+1)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def testBlockPermanent(self):
        self.ip_ban.block([localhost], permanent=True)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)
        time.sleep(self.ban_seconds+2)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)

    def testAdd(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.ip_ban.add(ip=localhost, url='/', reason='spite')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        for x in range(self.ip_ban.ban_count+1):
            self.ip_ban.add(ip=localhost, url='/', reason='spite')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)
