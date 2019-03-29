from __future__ import absolute_import

import os
import tempfile

import flask
import unittest

from flask_ipban.ip_ban import IpBan

page_text = 'Hello, world. {}'


def hello_world(parameter=None):
    return page_text.format(parameter)


persist_dir = os.path.join(tempfile.gettempdir(), 'flask-ip-ban-testing')


class IpBanPersistence1(unittest.TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.ban_seconds = 2
        self.ip_ban = IpBan(self.app, ban_seconds=self.ban_seconds, ban_count=5, persist=True, record_dir=persist_dir)
        self.client = self.app.test_client()

        self.app.route('/')(hello_world)

    def runTest(self):
        self.ip_ban.block(['123.456.765.111'])


class IpBanPersistence2(unittest.TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.ban_seconds = 2
        self.ip_ban = IpBan(self.app, ban_seconds=self.ban_seconds, ban_count=5, persist=True, record_dir=persist_dir)
        self.client = self.app.test_client()

        self.app.route('/')(hello_world)

    def runTest(self):
        self.assertTrue('123.456.765.111' in self.ip_ban._ip_ban_list)


def suite():
    s = unittest.TestSuite()
    s.addTest(IpBanPersistence1())
    s.addTest(IpBanPersistence2())
    return s


if __name__ == '__main__':
    runner = unittest.TextTestRunner(failfast=True)
    runner.run(suite())
