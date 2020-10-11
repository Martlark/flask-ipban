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
import ipaddress
import os
import re
from datetime import datetime

import yaml
from flask import request, abort

from flask_ipban.abuse_ipdb import AbuseIPDB
from flask_ipban.ip_record import IpRecord


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

    VERSION = '1.1.2'

    def __init__(self, app=None, ban_count=20, ban_seconds=3600 * 24, persist=False, record_dir=None, ipc=False,
                 secret_key=None, ip_header=None, abuse_IPDB_config=None):
        """
        start

        :param app: (optional when using init_app) flask application with logger defined
        :param ban_count: (optional) number of observations before ban
        :param ban_seconds: (optional) number minutes of silence before ban rescinded (0 is never rescind)
        :param persist: (optional) persists the ban records between app starts by storing in a temp folder
        :param record_dir: (optional default is flask-ip-ban in the temp folder) a record directory that stores ban records for ipc sync and persistence.
        :param ipc: enable ipc communication
        :param secret_key: optional secret key for signing ipc records.  Default is to use flask secret key
        :param ip_header: name of request header that contains the ip for use behind proxies when in docker/kube hosted env
        :param abuse_IPDB_config: config {key=,report=False,load=False} to a AbuseIPDB.com account.  Blocked ip addresses via url nuisance matching will be reported.
        """
        self.ban_count = int(os.environ.get('IP_BAN_LIST_COUNT', ban_count))  # type: int
        self.ban_seconds = int(os.environ.get('IP_BAN_LIST_SECONDS', ban_seconds))  # type: int

        self._ip_whitelist = {'127.0.0.1': True}
        # self._ip_whitelist = {}
        self._ip_ban_list = {}
        self._cidr_entries = {}
        # initialise with well known search bot links
        self._url_whitelist_patterns = {
            '^/.well-known/': dict(pattern=re.compile('^/.well-known'), match_type='regex'),
            '/favicon.ico': dict(pattern=re.compile(''), match_type='string'),
            '/robots.txt': dict(pattern=re.compile(''), match_type='string'),
            '/ads.txt': dict(pattern=re.compile(''), match_type='string'),
        }
        self._url_blocklist_patterns = {}
        self.app = None
        self._logger = None
        self.abuse_reporter = None
        self.ip_header = ip_header
        self.abuse_IPDB_config = abuse_IPDB_config or {}
        self.init = True

        self.ip_record = IpRecord(self, record_dir, persist, ipc, secret_key)

        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        initialise using app as parameter

        :param app: flask app with logger defined
        :return:
        """
        self._logger = app.logger
        self.app = app
        app.after_request(self._after_request)
        app.before_request(self._before_request_check)
        self.ip_record.start(app)
        self.abuse_reporter = AbuseIPDB(logger=self._logger, ip_ban=self, key=self.abuse_IPDB_config.get('key'),
                                        report=self.abuse_IPDB_config.get('report'),
                                        load=self.abuse_IPDB_config.get('load'),
                                        debug=self.app.debug or self.abuse_IPDB_config.get('debug'))
        self.init = False

    def import_IPDB_black_list(self):
        """
        load up a list of ip addresses in the AbuseIPDB database.
        Note: free rate limit is 5 per day
        Note: can take a long time for the default 10000 entries

        :return:
        """
        if self.abuse_reporter and self.abuse_IPDB_key:
            self.abuse_reporter.import_black_list()

    def _after_request(self, response):
        """
        method to call after a request to allow recording of 404 errors

        :param response:
        :return:
        """
        if response.status_code == 404:
            self.add()
        return response

    def block(self, ip_list, permanent=False, no_write=False, timestamp=None, url='block'):
        """
        add a list of ip addresses to the block list

        :param ip_list: list of ip addresses to block
        :param permanent: (optional) True=do not allow entries to expire
        :param no_write: do not write an _ip_record
        :param timestamp; use this timestamp instead of now()
        :param url: url or reason to block
        :returns number of entries in the block list
        """
        if not isinstance(ip_list, list):
            ip_list = [ip_list]

        if not timestamp:
            timestamp = datetime.now()

        for ip in ip_list:
            entry = self._ip_ban_list.get(ip)
            if entry:
                entry['timestamp'] = timestamp
                entry['count'] = self.ban_count * 2
                entry['permanent'] = entry.get('permanent') or permanent  # retain permanent on extra blocks

                if not (no_write or self.init):
                    self._logger.warning('{ip} added to ban list.'.format(ip=ip))
            else:
                self._ip_ban_list[ip] = dict(timestamp=timestamp, count=self.ban_count * 2, permanent=permanent,
                                             url=url)

                if not (no_write or self.init):
                    self._logger.info('{ip} updated in ban list.'.format(ip=ip))

            self.ip_record.remove(ip, record_types=['.remove'])
            if not no_write:
                self.ip_record.write(ip, record_type='permanent' if permanent else 'block')
        return len(self._ip_ban_list)

    def get_ip(self):
        """
        return the ip for the current request from flask or from
        the request header if behind a proxy

        :return:
        """
        ip = None
        if self.ip_header:
            ip = request.headers.get(self.ip_header)
        return ip or request.environ.get('REMOTE_ADDR')

    def test_pattern_blocklist(self, url='', ip=None):
        """
        return true if the url or ip pattern matches an existing block

        :param url: (optional) the url to check
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

        if ip:
            ip_address = ipaddress.ip_address(ip)
            for c, c_ip in self._cidr_entries.items():
                if ip_address in c_ip:
                    self._logger.warning(f'ip block match {ip}. CIDR: {c}')
                    return True

        return False

    def _before_request_check(self):
        """
        raise 403 exception if ip in request has made too many 404 or failed login attempts
        checks url, blocklist and ip lists

        """

        self.ip_record.update_from_other_instances()

        if self._is_excluded():
            return

        ip = self.get_ip()
        url = request.environ.get('PATH_INFO')

        entry = self._ip_ban_list.get(ip)

        if entry and entry.get('count', 0) > self.ban_count:
            now = datetime.now()
            delta = now - entry.get('timestamp', now)

            if entry.get('permanent', False):
                abort(403)

            if delta.seconds < self.ban_seconds or self.ban_seconds == 0:
                self._logger.debug('IP updated in ban list {}.  Url: {}'.format(ip, url))
                entry['timestamp'] = datetime.now()
                entry['count'] += 1
                self.ip_record.write(ip, count=entry['count'])
                abort(403)
            else:
                self._logger.debug('IP expired from ban list {}.  Url: {}'.format(ip, url))
                entry['count'] = 0

    def block_cidr(self, cidr):
        self._cidr_entries[cidr] = ipaddress.ip_network(cidr)

    def ip_whitelist_add(self, ip_list):
        """
        add the ip to the list of ips to whitelist

        :param ip_list: list of ip addresses to add
        :return: number of entries in the ip whitelist
        """
        if not isinstance(ip_list, list):
            ip_list = [ip_list]
        for ip in ip_list:
            self._ip_whitelist[ip] = True
        return len(self._ip_whitelist)

    def ip_whitelist_remove(self, ip_list):
        """
        remove an entry from the ip whitelist

        :param ip_list: list of ip addresses to remove
        :return: True if found and removed
        """
        if not isinstance(ip_list, list):
            ip_list = [ip_list]
        for ip in ip_list:
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
            ip = self.get_ip()
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

    def display(self, option='html'):
        s = ''
        if option == 'html':
            s += '<table class="table"><thead>\n'
            s += '<tr><th>ip</th><th>count</th><th>permanent</th><th>url</th><th>timestamp</th></tr>\n'
            s += '</thead><tbody>\n'
            for k, r in self._ip_ban_list.items():
                s += '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n'.format(k, r['count'],
                                                                                                 r.get('permanent', ''),
                                                                                                 r.get('url', ''),
                                                                                                 r['timestamp'])
            s += '</tbody></table>'
        elif option == 'csv':
            for k, r in self._ip_ban_list.items():
                s += '{},{},{},{}\n'.format(k, r['count'], r.get('permanent', ''),
                                            r['timestamp'])

        return s

    def add(self, ip=None, url=None, no_write=False, timestamp=None):
        """
        increment ban count ip of the current request in the banned list

        :return:
        :param ip: optional ip to add (ip ban will by default use current ip)
        :param url: optional url to display/store
        :param no_write: do not write out to record file
        :param timestamp: entry time to set
        :return True if entry added/updated
        """
        if not ip:
            ip = self.get_ip()

        if not url:
            url = request.environ.get('PATH_INFO')

        if self._is_excluded(ip=ip, url=url):
            return False

        entry = self._ip_ban_list.get(ip)
        # check url block list if no existing entry
        # or existing entry has expired
        if not entry or (entry and entry.get('count', 0) < self.ban_count):
            if self.test_pattern_blocklist(url, ip=ip):
                self.block([ip], no_write=no_write, url=url)
                if not no_write and url and self.abuse_IPDB_config.get('key'):
                    # report if this is the first time ip seen and not a report from another instance
                    self.abuse_reporter.report_ip(ip, reason='Flask-IPban - exploit URL requested:{}'.format(url))
                return True

        if timestamp and timestamp > datetime.now():
            timestamp = datetime.now()

        timestamp = timestamp or datetime.now()

        if entry:
            entry['count'] += 1
        else:
            self._ip_ban_list[ip] = dict(timestamp=timestamp, count=1, url=url)
            entry = self._ip_ban_list[ip]

        entry['timestamp'] = timestamp

        if not self.init:
            self._logger.info(
                '{} {} added/updated ban list. Count: {}'.format(ip, url, entry['count']))
        if not no_write:
            self.ip_record.write(ip, count=entry['count'])
        return True

    def remove(self, ip, no_write=False):
        """
        remove from the ban list

        :param ip: ip to remove
        :param no_write: do not write a remove record.  Prevents self dealing
        :return True if entry removed
        """

        if not no_write:
            self.ip_record.write(ip, record_type='remove')
        self.ip_record.remove(ip, record_types=['.block', '.permanent', '.add'])

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
                        self._logger.exception(
                            'Exception {exception} adding pattern {value}'.format(value=value, exception=str(e)))

        return added_count


if __name__ == '__main__':
    from flask import Flask
    import sys
    import logging

    """
    small flask application for testing of functions.
    """

    secret_key = 'abscdefghijklj430urojfdshfdsoih'
    my_ip = '127.0.0.1'
    test_ip_ban = IpBan(ban_count=4, ban_seconds=20, persist=True, record_dir='.flask-ip-ban-test-app',
                        # ip_header='X_IP_HEADER',
                        ipc=True,
                        abuse_IPDB_config=dict(
                            key=os.environ.get('ABUSE_IPDB_KEY'),
                            report=True, load=False, debug=True))
    app = Flask(__name__)


    @app.after_request
    def hook_after_request(response):
        response.headers['X_IP_HEADER'] = '123.45.12.112'
        return response


    @app.route('/ban')
    def route_block():
        test_ip_ban.block([my_ip])
        return '<h1>You are now blocked</h1>'


    @app.route('/remove')
    def route_remove():
        test_ip_ban.remove(my_ip)
        return '<h1>You are now free</h1>'


    @app.route('/ban_perm')
    def route_block_perm():
        test_ip_ban.block([my_ip], permanent=True)
        return '<h1>You are now blocked</h1>'


    @app.route('/display')
    def route_display():
        return test_ip_ban.display()


    @app.route('/clean')
    def route_clean():
        return str(test_ip_ban.ip_record.clean())


    @app.route('/favicon.ico')
    def route_favicon():
        return ''


    @app.route('/unblock')
    def route_unblock():
        removed = test_ip_ban.remove(my_ip)
        return '<h1>Un blocked {}={}</h1><a href="/">Home</a>'.format(my_ip, removed)


    @app.route('/')
    def route_hello():
        js = """var interval = null;
    function startExercise(){
        interval = setInterval(()=>{
        const urls = ['/ban','/ban_perm','/remove','/doesnotexist','/unblock','/sftp-config.json'];
        const r = Math.floor(Math.random()*urls.length);
        fetch(urls[r]).then(response=>document.getElementById('message').innerText=urls[r] + '-' + response.status);
        fetch('/display').then(response=>response.text()).then(text=>document.getElementById('display').innerHTML=text);
    },1500)
    }
    function stopExercise(){
        clearInterval(interval);
    }
    function stopExerciseClear(){
        clearInterval(interval);
        fetch('/clean').then(response=>response.text()).then(text=>document.getElementById('message').innerText=text);
    }
    """

        return '''<h1>ip ban app - timeout: 20 seconds - ban count: 4</h1>
    <p id='message'></p>
    <a href='/ban'>Block {ip}</a>
    <a href='/ban_perm'>Block perm {ip}</a>
    <a href='/remove'>remove {ip}</a>
    <a href='/doesnotexist'>404</a>
    <a href='/unblock'>unblock</a>
    <a href='/sftp-config.json'>nuisance url</a>
    <script>{js}</script>
    <br>
    <button onclick="startExercise()">Start exercise</button>
    <button onclick="stopExercise()">Cancel exercise</button>
    <button onclick="stopExerciseClear()">Cancel exercise and clear perm</button>
    <div id='display'></div>
    '''.format(js=js, ip=my_ip)


    app.secret_key = secret_key
    test_ip_ban.init_app(app)
    test_ip_ban.url_pattern_add('/unblock', match_type='string')
    test_ip_ban.url_pattern_add('/clean', match_type='string')
    test_ip_ban.url_pattern_add('/display', match_type='string')
    test_ip_ban.ip_whitelist_remove('127.0.0.1')
    test_ip_ban.load_nuisances()
    app.logger.setLevel(logging.INFO)

    port = 8887
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    app.run(host='localhost', port=port, debug=True)
