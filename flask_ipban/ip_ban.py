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

import logging
import os
import random
import re
import tempfile
import threading
from datetime import datetime

import yaml
from flask import Flask, request, abort


class IpBan:
    """
    Implements a simple list of ip addresses that
    seem to be trying credential stuffing.  Blocks items from that list
    once they exceed the ban count.

    Optional config by env variable
    ======
    IP_BAN_LIST_COUNT - number of observations before 403 exception
    IP_BAN_LIST_SECONDS - number of seconds to retain memory of IP

    """

    def __init__(self, app=None, ban_count=20, ban_seconds=3600, persist=False, record_dir=None, ipc=True):
        """
        start
        :param app: (optional when using init_app) flask application with logger defined
        :param ban_count: (optional) number of observations before ban
        :param ban_seconds: (optional) number minutes of silence before ban rescinded (0 is never rescind)
        :param persist: (optional) persists the ban records between app starts by storing in a temp folder
        :param record_dir: (optional default is flask-ip-ban in the temp folder) a record directory that stores ban records for ipc sync and persistence.
        :param ipc: enable ipc communication
        """
        self.ban_count = int(os.environ.get('IP_BAN_LIST_COUNT', ban_count))  # type: int
        self.ban_seconds = int(os.environ.get('IP_BAN_LIST_SECONDS', ban_seconds))  # type: int
        self._app = None

        self._ip_whitelist = {}
        self._ip_ban_list = {}
        self._url_whitelist_patterns = {}
        self._url_blocklist_patterns = {}
        self._instance_id = str(random.randint(0, 999999999999))  # type: str
        self._persist = persist  # type: bool
        self._ipc = ipc  # type: bool
        self._ip_record_dir = record_dir or os.path.join(tempfile.gettempdir(), 'flask-ip-ban')  # type: str
        self._ip_record_timer_seconds = 5.0  # type: float
        self._last_updatetime = datetime.now()
        self._logger = logging

        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        initialise using app as parameter
        :param app: flask app with logger defined
        :return:
        """
        self._app = app
        self._logger = app.logger
        self._ip_record_setup()
        app.after_request(self._after_request)
        app.before_request(self._before_request_check)

    def ip_record_clean(self):
        """
        clean out old ip record file
        :return: None
        """
        for f in os.listdir(self._ip_record_dir):
            file_name = os.path.join(self._ip_record_dir, f)
            try:
                if os.path.isfile(file_name):
                    os.unlink(file_name)
            except:
                pass

    def _ip_record_timer_func(self):
        """
        timer func to start and restart IPC update method
        """
        if not self._ipc:
            return

        self._ip_record_read_updates()
        self._ip_record_timer = threading.Timer(self._ip_record_timer_seconds, self._ip_record_timer_func)
        self._ip_record_timer.start()

    def _ip_record_write(self, ip, record_type='add', count=0):
        if not self._ipc and not self._persist:
            return

        file_name = os.path.join(self._ip_record_dir, '{}-{}-{}.{}'.format(self._instance_id, ip, count, record_type))
        if os.path.exists(file_name):
            # touch it
            os.utime(file_name, None)
        else:
            with open(file_name, 'w') as f:
                f.write(ip)

    def _ip_record_setup(self):
        """
        setup the ip record db and start IPC timer
        :return:
        """
        if not os.path.isdir(self._ip_record_dir):
            os.makedirs(self._ip_record_dir)

        if self._persist:
            self._ip_record_read_updates(force=True)
        else:
            self.ip_record_clean()

        if self._ipc:
            self._ip_record_timer = threading.Timer(self._ip_record_timer_seconds, self._ip_record_timer_func)
            self._ip_record_timer.start()

    def _ip_record_remove(self, ip, record_types):
        """
        Remove the given record type extensions for the given ip
        :param ip: ip to remove
        :param record_types: list of file extensions to remove ie: ['.add', '.remove']
        :return:
        """
        if not self._ipc and not self._persist:
            return

        self._logger.warning('Removing {} for records {}'.format(ip, record_types))
        for filename in os.listdir(self._ip_record_dir):
            try:
                full_name = os.path.join(self._ip_record_dir, filename)
                extension = os.path.splitext(filename)[1]
                if os.path.isfile(full_name):
                    if '-' + ip + '-' in filename and extension in record_types:
                        os.unlink(full_name)
            except Exception as e:
                self._logger.exception(e)

    def _ip_record_read_updates(self, force=False):
        """
        Read other process and persistence ip records.  Only reads records that are newer than previous run.
        :param force: force update
        :return:
        """
        if not self._ipc and not self._persist:
            return

        # self._logger.warning('Reading ip record updates')
        for filename in os.listdir(self._ip_record_dir):
            try:
                full_name = os.path.join(self._ip_record_dir, filename)
                if not filename.startswith(self._instance_id + '-'):
                    if os.path.isfile(full_name):
                        mtime = datetime.fromtimestamp(os.path.getmtime(full_name))
                        if mtime > self._last_updatetime or force:
                            with open(full_name, 'r') as f:
                                ip = f.readline()
                                self._logger.warning('Reading ip {} from record {}'.format(ip, filename))
                                if filename.endswith('.add'):
                                    self.add(ip, url=' ', no_write=True)
                                elif filename.endswith('.block'):
                                    self.block([ip], no_write=True, timestamp=mtime)
                                elif filename.endswith('.permanent'):
                                    self.block([ip], permanent=True, no_write=True)
                                elif filename.endswith('.remove'):
                                    self.remove(ip, no_write=True)
                                    self._ip_record_remove(ip, record_types=['.block', '.permanent', '.add'])
                                else:
                                    raise Exception('unknown ip record type for file: {}'.format(filename))
            except Exception as e:
                self._logger.exception(e)
        self._last_updatetime = datetime.now()

    def _after_request(self, response):
        """
        method to call after a request to allow recording of 404 errors
        :param response:
        :return:
        """
        if response.status_code == 404:
            self.add()
        return response

    def block(self, ip_list, permanent=False, no_write=False, timestamp=None):
        """
        add a list of ip address to the block list
        :param ip_list: list of ip addresses to block
        :param permanent: (optional) True=do not allow entries to expire
        :param no_write: do not write an _ip_record
        :param timestamp; use this timestamp instead of utcnow()
        :returns number of entries in the block list
        """
        if not isinstance(ip_list, list):
            ip_list = [ip_list]

        if not timestamp:
            timestamp = datetime.utcnow()

        for ip in ip_list:
            entry = self._ip_ban_list.get(ip)
            if entry:
                entry['timestamp'] = timestamp
                entry['count'] = self.ban_count * 2
                entry['permanent'] = entry.get('permanent') or permanent  # retain permanent on extra blocks
            else:
                self._ip_ban_list[ip] = dict(timestamp=timestamp, count=self.ban_count * 2, permanent=permanent)
            self._logger.info('{ip} added to ban list.'.format(ip=ip))
            self._ip_record_remove(ip, record_types=['.remove'])
            if not no_write:
                self._ip_record_write(ip, record_type='permanent' if permanent else 'block')
        return len(self._ip_ban_list)

    def test_pattern_blocklist(self, url, ip=None):
        """
        return true if the url or ip pattern matches an existing block
        :param url: the url to check
        :param ip: (optional) an ip to check
        :return:
        """
        query_path = url.split('?')[0]
        for pattern, item in self._url_blocklist_patterns.items():

            if item['match_type'] == 'regex' and item['pattern'].match(query_path):
                self._logger.warning('Url {} matches block pattern {}'.format(url, pattern))
                return True
            elif item['match_type'] == 'string' and pattern == query_path:
                self._logger.warning('Url {} matches block string {}'.format(url, pattern))
                return True
            elif ip and item['match_type'] == 'ip' and pattern == ip:
                self._logger.warning('ip block match {}'.format(ip))
                return True

        return False

    def _before_request_check(self):
        """
        raise 403 exception if ip in request has made too many 404 or failed login attempts
        checks url, blocklist and ip lists
        """

        if self._is_excluded():
            return

        ip = request.environ.get('REMOTE_ADDR')
        url = request.environ.get('PATH_INFO')

        entry = self._ip_ban_list.get(ip)

        if entry and entry.get('count', 0) > self.ban_count:
            utc_now = datetime.utcnow()
            delta = utc_now - entry.get('timestamp', utc_now)

            if entry.get('permanent', False):
                abort(403)

            if delta.seconds < self.ban_seconds or self.ban_seconds == 0:
                self._logger.warning('IP is in ban list {}.  Url: {}'.format(ip, url))
                entry['timestamp'] = datetime.utcnow()
                entry['count'] += 1
                self._ip_record_write(ip, count=entry['count'])
                abort(403)
            else:
                self._logger.warning('IP expired from ban list {}.  Url: {}'.format(ip, url))
                self._ip_ban_list[ip]['count'] = 0

    def ip_whitelist_add(self, ip):
        """
        add the ip to the list of ips to whitelist
        :param ip: the ip to add
        :return: number of entries in the ip whitelist
        """
        self._ip_whitelist[ip] = True
        return len(self._ip_whitelist)

    def ip_whitelist_remove(self, ip):
        """
        remove an entry from the ip whitelist
        :param ip: address to remove
        :return: True if found and removed
        """
        if ip in self._ip_whitelist:
            del self._ip_whitelist[ip]
            return True
        return False

    def url_pattern_add(self, url_pattern, match_type='regex'):
        """
        add or replace the pattern to the list of url patterns to ignore
        :param url_pattern: regex pattern to match with requested url
        :param match_type: string or regex - determines the pattern matching scheme
        :return: length of the whitelist
        """
        self._url_whitelist_patterns[url_pattern] = dict(pattern=re.compile(url_pattern), match_type=match_type)
        return len(self._url_whitelist_patterns)

    def url_pattern_remove(self, url_pattern):
        """
        remove the given regex pattern from the url whitelist
        :param url_pattern:
        :return: true if removed
        """
        if url_pattern in self._url_whitelist_patterns:
            del self._url_whitelist_patterns[url_pattern]
            return True
        return False

    def url_block_pattern_add(self, url_pattern, match_type='regex'):
        """
        add or replace the pattern to the list of url patterns to block
        :param match_type: regex or string - determines the match strategy to use
        :param url_pattern: regex pattern to match with requested url
        :return: length of the blocklist
        """
        self._url_blocklist_patterns[url_pattern] = dict(pattern=re.compile(url_pattern), match_type=match_type)
        return len(self._url_blocklist_patterns)

    def url_block_pattern_remove(self, url_pattern):
        """
        remove the given regex pattern from the url blocklist
        NOTE: any existing blocked caused by this pattern is not removed
        :param url_pattern:
        :return: true if removed
        """
        if url_pattern in self._url_blocklist_patterns:
            del self._url_blocklist_patterns[url_pattern]
            return True
        return False

    def _is_excluded(self, ip=None, url=None):
        """
        return true if this ip or url should not be checked
        :return: true if no checking required
        """

        if not ip:
            ip = request.environ.get('REMOTE_ADDR')
        if not url:
            url = request.environ.get('PATH_INFO')

        for key, item in self._url_whitelist_patterns.items():
            if item['match_type'] == 'regex' and item['pattern'].match(url):
                return True
            elif item['match_type'] == 'string' and key == url:
                return True

        if ip in self._ip_whitelist:
            return True

        return False

    def add(self, ip=None, url=None, reason='404', no_write=False):
        """
        increment ban count ip of the current request in the banned list
        :return:
        :param ip: optional ip to add
        :param url: optional url to display/store
        :param reason: optional reason for ban, default is 404
        :param no_write: do not write out to record file
        :return True if entry added/updated
        """
        if not ip:
            ip = request.environ.get('REMOTE_ADDR')

        if not url:
            url = request.environ.get('PATH_INFO')

        if self._is_excluded(ip=ip, url=url):
            return False

        entry = self._ip_ban_list.get(ip)
        # check url block list if no existing entry
        # or existing entry has expired
        if not entry or (entry and entry.get('count', 0) < self.ban_count):
            if self.test_pattern_blocklist(url, ip=ip):
                self.block([ip])
                if not no_write:
                    self._ip_record_write(ip)
                return True

        if entry:
            entry['timestamp'] = datetime.utcnow()
            entry['count'] += 1
        else:
            self._ip_ban_list[ip] = dict(timestamp=datetime.utcnow(), count=1, url=url)
            entry = self._ip_ban_list[ip]

        self._logger.info(
            '{}. {} {} added/updated ban list. Count: {}'.format(reason, ip, url, entry['count']))
        if not no_write:
            self._ip_record_write(ip, count=entry['count'])
        return True

    def remove(self, ip, no_write=False):
        """
        remove from the ban list
        :param ip: ip to remove
        :param no_write: do not write a remove record.  Prevents self dealing
        :return True if entry removed
        """

        if not no_write:
            self._ip_record_write(ip, record_type='remove')
        self._ip_record_remove(ip, record_types=['.block', '.permanent', '.add'])

        entry = self._ip_ban_list.get(ip)
        if not entry:
            return False

        del self._ip_ban_list[ip]
        return True

    def load_nuisances(self, file_name=None):
        """
        load a yaml file of nuisance urls that are commonly used by vulnerability scanners.
        Once loaded any access to one of these urls that produces a 404 will ban the source ip.
        Each call to load_nuisances will add to the current list of nuisances
        :param file_name: a file name of your own nuisance ips
        :return: the number of nuisances added from this file
        """
        if not file_name:
            file_name = os.path.join(os.path.dirname(__file__), 'nuisance.yaml')

        added_count = 0
        with open(file_name) as f:
            y = yaml.load(f, Loader=yaml.SafeLoader)

            for match_type in ['ip', 'string', 'regex']:
                for value in y[match_type]:
                    try:
                        self.url_block_pattern_add(value, match_type)
                        added_count += 1
                    except Exception as e:
                        self._logger.warning(
                            'Exception {exception} adding pattern {value}'.format(value=value, exception=str(e)))

        return added_count


if __name__ == '__main__':
    import sys

    app = Flask(__name__)

    ip_ban = IpBan(app=app, ban_count=4, ban_seconds=20, persist=True,
                   record_dir='/tmp/flask-ip-ban-test-app')
    ip_ban.url_pattern_add('/unblock', match_type='string')
    ip_ban.load_nuisances()


    def route_block():
        ip_ban.block(['127.0.0.1'])
        return '<h1>You are now blocked</h1>'


    def route_remove():
        ip_ban.remove('127.0.0.1')
        return '<h1>You are now free</h1>'


    def route_block_perm():
        ip_ban.block(['127.0.0.1'], permanent=True)
        return '<h1>You are now blocked</h1>'

    def route_unblock():
        ip_ban.remove('127.0.0.1')
        return '<h1>You are now un blocked</h1>'


    def route_hello():
        return '''<h1>ip ban app - timeout: 20 seconds - ban count: 4</h1>
        <a href='/ban'>Block 127.0.0.1</a>
        <a href='/ban_perm'>Block perm 127.0.0.1</a>
        <a href='/remove'>remove 127.0.0.1</a>
        <a href='/doesnotexist'>404</a>
        <a href='/unblock'>unblock</a>
        '''


    app.route('/')(route_hello)
    app.route('/ban')(route_block)
    app.route('/ban_perm')(route_block_perm)
    app.route('/remove')(route_remove)
    app.route('/unblock')(route_unblock)
    port = 8887
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    app.run(host='127.0.0.1', port=port, debug=True)
