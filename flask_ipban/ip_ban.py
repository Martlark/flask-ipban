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
import pickle
import re
import tempfile
from datetime import datetime

import yaml
from flask import request, abort


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

    def __init__(self, app=None, ban_count=20, ban_seconds=3600, persist=False, persist_file_name=None):
        """
        start
        :param app: (optional when using init_app) flask application with logger defined
        :param ban_count: (optional) number of observations before ban
        :param ban_seconds: (optional) number minutes of silence before ban rescinded (0 is never rescind)
        """
        self._ip_whitelist = {}
        self._ip_ban_list = {}
        self._url_whitelist_patterns = {}
        self._url_blocklist_patterns = {}
        self.ban_count = int(os.environ.get('IP_BAN_LIST_COUNT', ban_count))
        self.ban_seconds = int(os.environ.get('IP_BAN_LIST_SECONDS', ban_seconds))
        self._app = None
        self._persist = persist
        self._persist_file_name = os.path.join(tempfile.gettempdir(), 'flask-ip-ban-persistence.pickle')
        if persist_file_name:
            self._persist_file_name = persist_file_name

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
        self._persist_read()
        app.after_request(self._after_request)
        app.before_request(self._before_request_check)

    def _persist_write(self):
        if self._persist:
            try:
                with open(self._persist_file_name, 'wb') as f:
                    pickle.dump(self._ip_ban_list, f, protocol=pickle.HIGHEST_PROTOCOL)
            except Exception as e:
                self._logger.exception('error writing persistence file {}. {}'.format(self._persist_file_name, e))

    def _persist_read(self):
        if self._persist:
            try:
                with open(self._persist_file_name, 'rb') as f:
                    self._ip_ban_list = pickle.load(f)
            except Exception as e:
                self._logger.exception('error reading persistence file {}. {}'.format(self._persist_file_name, e))

    def _after_request(self, response):
        if response.status_code == 404:
            self.add()
        return response

    def block(self, ip_list, permanent=False):
        """
        add a list of ip address to the block list
        :param ip_list: list of ip addresses to block
        :param permanent: (optional) True=do not allow entries to expire
        :returns number of entries in the block list
        """
        for ip in ip_list:
            entry = self._ip_ban_list.get(ip)
            if entry:
                entry['timestamp'] = datetime.utcnow()
                entry['count'] = self.ban_count * 2
                entry['permanent'] = permanent
            else:
                self._ip_ban_list[ip] = dict(timestamp=datetime.utcnow(), count=self.ban_count * 2, permanent=permanent)
            self._persist_write()
            self._logger.info('{ip} added to ban list.'.format(ip=ip))
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
                self._persist_write()
                abort(403)
            else:
                self._logger.warning('IP expired from ban list {}.  Url: {}'.format(ip, url))
                self._ip_ban_list[ip]['count'] = 0
                self._persist_write()

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

    def add(self, ip=None, url=None, reason='404'):
        """
        increment ban count ip of the current request in the banned list
        :param ip: optional ip to add
        :param url: optional url to display/store
        :param reason: optional reason for ban, default is 404
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
                return True

        if entry:
            entry['timestamp'] = datetime.utcnow()
            entry['count'] += 1
        else:
            self._ip_ban_list[ip] = dict(timestamp=datetime.utcnow(), count=1, url=url)
            entry = self._ip_ban_list[ip]

        self._persist_write()
        self._logger.info(
            '{}. {} {} added/updated ban list. Count: {}'.format(reason, ip, url, entry['count']))
        return True

    def remove(self, ip):
        """
        remove from the ban list
        :param ip: ip to remove
        :return True if entry removed
        """

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
