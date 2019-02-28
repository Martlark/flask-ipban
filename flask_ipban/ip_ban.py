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

import os
import pickle
import re
import tempfile
from urllib.parse import urlparse
from datetime import datetime

from flask import request, abort


class IpBan:
    """
    implements a simple list of ip addresses that
    seem to be trying credential stuffing.

    Optional config by env variable
    ======
    IP_BAN_LIST_COUNT - number of entries before 403 exception
    IP_BAN_LIST_SECONDS - number of minutes to retain memory of IP

    """

    def __init__(self, app=None, ban_count=50, ban_seconds=3600, persist=False, persist_file_name=None):
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
        self.app = None
        self._persist = persist
        self._persist_file_name = os.path.join(tempfile.gettempdir(), 'flask-ip-ban-persistence.pickle')
        if persist_file_name:
            self._persist_file_name = persist_file_name

        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        initialise using app as parameter
        :param app: flask app with logger defined
        :return:
        """
        self.app = app
        self._persist_read()
        app.after_request(self.after_request)
        app.before_request(self.before_request_check)

    def _persist_write(self):
        if self._persist:
            try:
                with open(self._persist_file_name, 'wb') as f:
                    pickle.dump(self._ip_ban_list, f, protocol=pickle.HIGHEST_PROTOCOL)
            except Exception as e:
                self.app.logger.exception('error writing persistence file {}. {}'.format(self._persist_file_name, e))

    def _persist_read(self):
        if self._persist:
            try:
                with open(self._persist_file_name, 'rb') as f:
                    self._ip_ban_list = pickle.load(f)
            except Exception as e:
                self.app.logger.exception('error reading persistence file {}. {}'.format(self._persist_file_name, e))

    def after_request(self, response):
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
                entry['permanent'] = True
            else:
                self._ip_ban_list[ip] = dict(timestamp=datetime.utcnow(), count=self.ban_count * 2, permanent=permanent)
            self._persist_write()
            self.app.logger.info('{ip} added to ban list.'.format(ip=ip))
        return len(self._ip_ban_list)

    def test_pattern_blocklist(self, url):
        query = urlparse(url)
        for pattern, item in self._url_blocklist_patterns.items():

            if item['match_type'] == 'regex' and item['pattern'].match(query.path):
                return True

            if item['match_type'] == 'string' and pattern == query.path:
                return True
        return False

    def before_request_check(self):
        """
        raise 403 exception if ip in request has made too many 404 or failed login attempts
        checks url, blocklist and ip lists
        """

        if self._is_excluded():
            return

        ip = request.environ.get('REMOTE_ADDR')
        url = request.environ.get('PATH_INFO')

        entry = self._ip_ban_list.get(ip)

        # check url block list if no existing entry
        # or existing entry has expired
        if not entry or (entry and entry.get('count', 0) == 0):
            if self.test_pattern_blocklist(url):
                self.block([ip])
                abort(403)

        if entry and entry.get('count', 0) > self.ban_count:
            utc_now = datetime.utcnow()
            delta = utc_now - entry.get('timestamp', utc_now)

            if entry.get('permanent', False):
                abort(403)

            if delta.seconds < self.ban_seconds or self.ban_seconds == 0:
                self.app.logger.warning('IP is in ban list {}.  Url: {}'.format(ip, url))
                entry['timestamp'] = datetime.utcnow()
                self._persist_write()
                abort(403)
            else:
                self.app.logger.warning('IP expired from ban list {}.  Url: {}'.format(ip, url))
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

    def url_pattern_add(self, url_pattern):
        """
        add or replace the pattern to the list of url patterns to ignore
        :param url_pattern: regex pattern to match with requested url
        :return: length of the whitelist
        """
        self._url_whitelist_patterns[url_pattern] = re.compile(url_pattern)
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

        for key, compiled in self._url_whitelist_patterns.items():
            if compiled.match(url):
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
        :return True if entry added
        """
        if not ip:
            ip = request.environ.get('REMOTE_ADDR')

        if not url:
            url = request.environ.get('PATH_INFO')

        if self._is_excluded(ip=ip, url=url):
            return

        entry = self._ip_ban_list.get(ip)
        if entry:
            entry['timestamp'] = datetime.utcnow()
            entry['count'] += 1
        else:
            self._ip_ban_list[ip] = dict(timestamp=datetime.utcnow(), count=1, url=url)
            entry = self._ip_ban_list[ip]

        self._persist_write()
        self.app.logger.info(
            '{}. {} {} added/updated ban list. Count: {}'.format(reason, ip, url, entry['count']))
        return True

    def load_nuisances(self, file_name=None):
        if not file_name:
            file_name = os.path.join(os.path.dirname(__file__), 'nuisance.txt')

        added_count = 0
        line_count = 0
        match_type = 'regex'
        with open(file_name) as f:
            for line in f:
                line_count += 1
                line = line.strip()
                if line.startswith('#') or len(line) < 3:
                    pass  # comment or not long enough
                else:
                    if line == '==regex==':
                        match_type = 'regex'
                    elif line == '==string==':
                        match_type = 'string'
                    else:
                        try:
                            self.url_block_pattern_add(line, match_type)
                            added_count += 1
                        except Exception as e:
                            self.app.logger.warning('line {}. Exception adding pattern {}'.format(line_count, str(e)))
        return added_count
