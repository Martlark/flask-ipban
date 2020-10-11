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

page_text = 'Hello, world. {}'
localhost = '127.0.0.1'


def hello_world(parameter=None):
    return page_text.format(parameter)


class TestIpBan(unittest.TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.ban_seconds = 2
        self.ip_ban = IpBan(self.app, ban_seconds=self.ban_seconds, ban_count=5, secret_key='yo-yo-yo', ipc=False)
        self.ip_ban.ip_whitelist_remove(localhost)
        self.client = self.app.test_client()

        self.app.route('/')(hello_world)

    def test_cidr(self):
        self.assertFalse(self.ip_ban.test_pattern_blocklist(ip='192.0.2.1'))
        self.ip_ban.block_cidr('192.0.2.0/28')
        self.assertTrue(self.ip_ban.test_pattern_blocklist(ip='192.0.2.1'))
        self.assertFalse(self.ip_ban.test_pattern_blocklist(ip='203.0.2.1'))

    def testAddRemoveIpWhitelist(self):
        self.assertEqual(self.ip_ban.ip_whitelist_add(localhost), 1)
        for x in range(self.ip_ban.ban_count * 2):
            response = self.client.get('/doesnotexist')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.ip_ban.ip_whitelist_remove(localhost))
        for x in range(self.ip_ban.ban_count * 2):
            response = self.client.get('/doesnotexist')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.ip_ban.ip_whitelist_remove(localhost))

    def testAddRemoveIpWhitelistByList(self):
        self.assertEqual(self.ip_ban.ip_whitelist_add([localhost]), 1)
        for x in range(self.ip_ban.ban_count * 2):
            response = self.client.get('/doesnotexist')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.ip_ban.ip_whitelist_remove([localhost]))
        for x in range(self.ip_ban.ban_count * 2):
            response = self.client.get('/doesnotexist')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.ip_ban.ip_whitelist_remove(localhost))

    def testAddRemoveUrlWhitelist(self):
        test_pattern = '^/no_exist/[0-9]+$'
        test_url = '/no_exist'
        self.assertTrue(re.match(test_pattern, test_url + '/123'))
        self.assertFalse(re.match(test_pattern, test_url))
        existing_count = len(self.ip_ban._url_whitelist_patterns)
        self.assertEqual(self.ip_ban.url_pattern_add(test_pattern), existing_count + 1)
        for x in range(self.ip_ban.ban_count * 2):
            self.client.get('{}/{}'.format(test_url, x))
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

        self.assertTrue(self.ip_ban.url_pattern_remove(test_pattern))
        for x in range(self.ip_ban.ban_count * 2):
            self.client.get('{}/{}'.format(test_url, x))
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)

        self.assertFalse(self.ip_ban.url_pattern_remove(localhost))

    def testUrlWhitelistString(self):
        test_url = '/no_exist'

        existing_count = len(self.ip_ban._url_whitelist_patterns)
        self.assertEqual(self.ip_ban.url_pattern_add(test_url, 'string'), existing_count + 1)
        for x in range(self.ip_ban.ban_count * 2):
            response = self.client.get('{}?{}'.format(test_url, x))
            self.assertEqual(response.status_code, 404)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def testBlock(self):
        self.assertEqual(self.ip_ban.block([localhost, '123.1.1.3']), 2)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)

    def testTimeout(self):
        test_url = '/doesnotexist'
        for x in range(self.ip_ban.ban_count * 2):
            self.client.get('{}/{}'.format(test_url, x))
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)
        time.sleep(self.ban_seconds + 1)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def testManualBlockTimeout(self):
        self.ip_ban.block([localhost])
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)
        time.sleep(self.ban_seconds + 1)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def testBlockPermanent(self):
        self.ip_ban.block([localhost], permanent=True)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)
        time.sleep(self.ban_seconds + 2)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)

    def testAdd(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.ip_ban.add(ip=localhost, url='/')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        for x in range(self.ip_ban.ban_count + 1):
            self.ip_ban.add(ip=localhost, url='/')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)

    def testKeepOnBlocking(self):
        # block should not timeout if spamming continues
        test_url = '/doesnotexist'
        for x in range(self.ip_ban.ban_count * 2):
            self.client.get('{}/{}'.format(test_url, x))
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)
        for x in range(self.ban_seconds * 2):
            time.sleep(1)
            response = self.client.get('/')
            self.assertEqual(response.status_code, 403)

    def testAddRemoveUrlBlocklist(self):
        test_pattern = '^/bad/[0-9]+$'
        test_url = '/bad'

        self.app.route('/good/<int:parameter>')(hello_world)

        self.assertTrue(re.match(test_pattern, test_url + '/123'))
        self.assertFalse(re.match(test_pattern, test_url))

        # no block
        response = self.client.get('/good/{}'.format(456))
        self.assertEqual(response.status_code, 200)

        # getting index page is blocked after block 404 url get
        self.assertEqual(self.ip_ban.url_block_pattern_add(test_pattern), 1)
        response = self.client.get('{}/{}'.format(test_url, 123))
        self.assertEqual(response.status_code, 404)
        # should now be banned
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)

        # ban removed after timeout
        time.sleep(self.ban_seconds + 1)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        response = self.client.get('{}/{}'.format(test_url, 123))
        self.assertEqual(response.status_code, 404)

        # ban remains even after pattern removed
        # caused by previous 404
        self.assertTrue(self.ip_ban.url_block_pattern_remove(test_pattern))
        response = self.client.get('{}/{}'.format(test_url, 456))
        self.assertEqual(response.status_code, 403)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)

        # ban removed after timeout
        time.sleep(self.ban_seconds + 1)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        response = self.client.get('{}/{}'.format(test_url, 123))
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

        # already removed
        self.assertFalse(self.ip_ban.url_block_pattern_remove(localhost))

    def testLoadNuisances(self):
        self.app.route('/regextest/page.<parameter>')(hello_world)
        # test is ok before nuisances loaded
        response = self.client.get('/regextest/page.{e}?yolo={e}'.format(e='jsp'))
        self.assertEqual(response.status_code, 200)
        self.ip_ban.load_nuisances()

        # test blocked extensions
        for e in ['php', 'jsp', 'aspx', 'do', 'cgi']:
            self.assertTrue(self.ip_ban.test_pattern_blocklist('/regextest/page.{}'.format(e)), e)
            # and with parameters
            self.assertTrue(self.ip_ban.test_pattern_blocklist('/regextest/page.{e}?extension={e}'.format(e=e)), e)

        # test blocked url strings and patterns
        for e in ['/admin/assets/js/views/login.js', '/vip163mx00.mxmail.netease.com:25', '/manager/html',
                  '/wp-login.php']:
            self.assertTrue(self.ip_ban.test_pattern_blocklist(e), e)

        # test blocked ip
        for e in ['185.53.91.24']:
            self.assertTrue(self.ip_ban.test_pattern_blocklist(e, ip=e), e)

        self.assertFalse(self.ip_ban.test_pattern_blocklist(e, ip=localhost), e)
        # test real blocking
        e = 'jsp'
        response = self.client.get('/regextest/page.{}'.format(e))
        self.assertEqual(response.status_code, 200, e)
        # goto 404
        response = self.client.get('/doesnotexist/page.{}'.format(e))
        self.assertEqual(response.status_code, 404, e)
        # this ip is now blocked
        response = self.client.get('/')
        self.assertEqual(response.status_code, 403)

    def test_remove(self):
        self.ip_ban.block(['100.200.300.400'])
        self.assertFalse(self.ip_ban.remove('1.2.3.4'))
        self.assertTrue(self.ip_ban.remove('100.200.300.400'))
        self.ip_ban.block([localhost])
        response = self.client.get('/')
        self.assertEqual(403, response.status_code)
        self.assertTrue(self.ip_ban.remove(localhost))
        response = self.client.get('/')
        self.assertEqual(200, response.status_code)


if __name__ == '__main__':
    runner = unittest.TextTestRunner(failfast=True)
    runner.run()
