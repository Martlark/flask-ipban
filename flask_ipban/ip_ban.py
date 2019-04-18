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


import operator
import os
import random
import re
import tempfile
from datetime import datetime
from itsdangerous import Signer

import yaml
from flask import request, abort


class IpRecord:
    """
    class to read and write ipc messages so that ip_ban can be shared across instances and applications
    """

    def __init__(self, ip_ban, record_dir, persist, ipc, secret_key):
        self.ip_ban = ip_ban
        self._ip_record_timer_seconds = min(5.0, self.ip_ban.ban_seconds / 4)  # type: float
        self._ip_record_dir = record_dir or os.path.join(tempfile.gettempdir(), 'flask-ip-ban')  # type: str
        self._instance_id = str(random.randint(0, 999999999999))  # type: str
        self._persist = persist
        self._ipc = ipc
        self._secret_key = secret_key
        self._logger = None
        self._signer = None
        self._last_update_time = datetime.now()

    def start(self, app):
        """
        setup the ip record db
        if store cannot be setup then ipc will be disabled.
        :return: True if setup correctly.
        """
        if not self._ipc and not self._persist:
            return False

        self._logger = app.logger

        tmp_secret_key = self._secret_key or app.secret_key or app.config.get('SECRET_KEY') or 'not-very-secret-key'
        if tmp_secret_key == 'not-very-secret-key':
            self._logger.warning('secret_key is default of: {}'.format(tmp_secret_key))

        self._signer = Signer(tmp_secret_key)

        try:
            if not os.path.isdir(self._ip_record_dir):
                os.makedirs(self._ip_record_dir)

            test_file_name = self.write('test', 'test')
            self.safe_unlink(test_file_name)
            if self._persist:
                self.read_updates(force=True)
            else:
                self.clean()
        except Exception as e:
            self._logger.exception(e)
            self._logger.error('ip record store cannot be established.  Disabling IPC.')
            self._ipc = False
            return False

        return True

    @staticmethod
    def safe_unlink(file_name):
        """
        safely remove a file if it exists
        :param file_name:
        :return:
        """
        try:
            if os.path.isfile(file_name):
                # attempt to remove the file
                os.unlink(file_name)
        except Exception as ex:
            pass

    def clean(self):
        """
        clean out all ip record files
        :return: None
        """
        for f in os.listdir(self._ip_record_dir):
            file_name = os.path.join(self._ip_record_dir, f)
            self.safe_unlink(file_name)

    def update_from_other_instances(self):
        """
        Read updates from other instances every now and then
        """
        if not self._ipc:
            return

        elapsed = datetime.now() - self._last_update_time
        if elapsed.seconds > self._ip_record_timer_seconds:
            self.read_updates()

    @classmethod
    def path_clean(cls, dirty):
        clean = ''
        if dirty:
            for c in dirty:
                if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.0123456789_':
                    clean += c
        return clean

    def write(self, ip, record_type='add', count=0):
        """
        write a ip record into the store
        :param ip: the ip to add
        :param record_type: type of record, could be: add (default), permanent, block, remove, test
        :param count: the list count of the add - allows adds to be communicated
        :return:the file_name of the record or None if nothing going or can't write
        """
        if not self._ipc and not self._persist:
            return

        safe_ip = IpRecord.path_clean(ip)
        file_name = os.path.join(self._ip_record_dir,
                                 '{}-{}-{}.{}'.format(self._instance_id, safe_ip, count, record_type))
        try:
            if os.path.exists(file_name):
                # touch it
                os.utime(file_name, None)
            else:
                with open(file_name, 'wb') as f:
                    f.write(self._signer.sign(ip))
        except:
            return
        return file_name

    def remove(self, ip, record_types):
        """
        Remove the given record type extensions for the given ip
        :param ip: ip to remove
        :param record_types: list of file extensions to remove ie: ['.add', '.remove']
        :return:
        """
        if not self._ipc and not self._persist:
            return

        self._logger.debug('Removing {} for records {}'.format(ip, record_types))
        for filename in os.listdir(self._ip_record_dir):
            try:
                full_name = os.path.join(self._ip_record_dir, filename)
                extension = os.path.splitext(filename)[1]
                if '-' + ip + '-' in filename and extension in record_types:
                    self.safe_unlink(full_name)
            except Exception as e:
                self._logger.exception(e)

    def read_updates(self, force=False):
        """
        Read other process and persistence ip records.  Only reads records that are newer than previous run.
        When not persisting older records will be cleaned up when > 2*ban_seconds old
        updates the _last_update_time on exit
        :param force: force update from older records
        :return:
        """
        if not self._ipc and not self._persist:
            return

        # read records and process from oldest to youngest
        try:
            filename_list = [dict(filename=f, full_name=os.path.join(self._ip_record_dir, f),
                                  mtime=datetime.fromtimestamp(os.path.getmtime(os.path.join(self._ip_record_dir, f))))
                             for
                             f in os.listdir(self._ip_record_dir)]
            filename_list = sorted(filename_list, key=operator.itemgetter('mtime'))
        except Exception as ex:
            # silently return if a file has been removed during enumeration
            return

        for filename_entry in filename_list:
            try:
                filename = filename_entry['filename']
                if not filename.startswith(self._instance_id + '-'):
                    if os.path.isfile(filename_entry['full_name']):
                        if filename_entry['mtime'] > self._last_update_time or force:
                            with open(filename_entry['full_name'], 'rb') as f:
                                signed_ip = f.readline()
                                ip = self._signer.unsign(signed_ip).decode('utf-8')
                                self._logger.debug(
                                    'Instance: {}, reading ip {} from record {}@{}'.format(self._instance_id, ip,
                                                                                           filename, str(
                                            filename_entry['mtime']).split('.')[0]))
                                if filename.endswith('.add'):
                                    self.ip_ban.add(ip, url=' ', no_write=True, timestamp=filename_entry['mtime'])
                                elif filename.endswith('.block'):
                                    self.ip_ban.block([ip], no_write=True, timestamp=filename_entry['mtime'])
                                elif filename.endswith('.test'):
                                    pass
                                elif filename.endswith('.permanent'):
                                    self.ip_ban.block([ip], permanent=True, no_write=True)
                                elif filename.endswith('.remove'):
                                    self.ip_ban.remove(ip, no_write=True)
                                    self.remove(ip, record_types=['.block', '.permanent', '.add'])
                                else:
                                    raise Exception(
                                        'Instance: {}, unknown ip record type for file: {}'.format(self._instance_id,
                                                                                                   filename))
                        elif not self._persist:
                            # clean up old entry
                            elapsed = datetime.now() - filename_entry['mtime']
                            if elapsed.seconds > self.ip_ban.ban_seconds * 2:
                                self.safe_unlink(filename_entry['full_name'])
            except FileNotFoundError:
                pass
            except Exception as e:
                self._logger.warning(e)
                # attempt to remove the problematic entry
                self.safe_unlink(filename_entry['full_name'])
        self._last_update_time = datetime.now()


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

    def __init__(self, app=None, ban_count=20, ban_seconds=3600, persist=False, record_dir=None, ipc=True,
                 secret_key=None, ip_header=None):
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
        """
        self.ban_count = int(os.environ.get('IP_BAN_LIST_COUNT', ban_count))  # type: int
        self.ban_seconds = int(os.environ.get('IP_BAN_LIST_SECONDS', ban_seconds))  # type: int

        self._ip_whitelist = {}
        self._ip_ban_list = {}
        self._url_whitelist_patterns = {}
        self._url_blocklist_patterns = {}
        self._logger = None
        self.ip_header = ip_header

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
        app.after_request(self._after_request)
        app.before_request(self._before_request_check)
        self.ip_record.start(app)

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
        :param timestamp; use this timestamp instead of now()
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
            else:
                self._ip_ban_list[ip] = dict(timestamp=timestamp, count=self.ban_count * 2, permanent=permanent)
            self._logger.warning('{ip} added to ban list.'.format(ip=ip))
            self.ip_record.remove(ip, record_types=['.remove'])
            if not no_write:
                self.ip_record.write(ip, record_type='permanent' if permanent else 'block')
        return len(self._ip_ban_list)

    def get_ip(self):
        ip = None
        if self.ip_header:
            ip = request.headers.get(self.ip_header)
        return ip or request.environ.get('REMOTE_ADDR')

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

    def add(self, ip=None, url=None, reason='404', no_write=False, timestamp=None):
        """
        increment ban count ip of the current request in the banned list
        :return:
        :param ip: optional ip to add
        :param url: optional url to display/store
        :param reason: optional reason for ban, default is 404
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
                self.block([ip], no_write=no_write)
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

        self._logger.info(
            '{}. {} {} added/updated ban list. Count: {}'.format(reason, ip, url, entry['count']))
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
    my_ip = '123.45.12.112'
    test_ip_ban = IpBan(ban_count=4, ban_seconds=20, persist=True, record_dir='/tmp/flask-ip-ban-test-app',
                        ip_header='X_IP_HEADER')
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


    @app.route('/unblock')
    def route_unblock():
        test_ip_ban.remove(my_ip)
        return '<h1>You are now un blocked</h1>'


    @app.route('/')
    def route_hello():
        js = """var interval = null;
        function startExercise(){
            interval = setInterval(()=>{
            const urls = ['/ban','/ban_perm','/remove','/doesnotexist','/unblock','/sftp-config.json'];
            const r = Math.floor(Math.random()*urls.length);
            fetch(urls[r]).then(response=>document.getElementById('message').innerText=urls[r] + '-' + response.status);
        },1500)
        }
        function stopExercise(){
            clearInterval(interval);
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
        '''.format(js=js, ip=my_ip)


    app.secret_key = secret_key
    test_ip_ban.init_app(app)
    test_ip_ban.url_pattern_add('/unblock', match_type='string')
    test_ip_ban.load_nuisances()
    app.logger.setLevel(logging.INFO)

    port = 8887
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    app.run(host='0.0.0.0', port=port, debug=True)
