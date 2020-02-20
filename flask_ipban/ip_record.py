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
import tempfile
from datetime import datetime

from itsdangerous import Signer


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
        self.init = True
        self.listdir = None

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
            self.init = False
            return False

        self.init = False
        return True

    @staticmethod
    def safe_unlink(file_name):
        """
        safely remove a file if it exists

        :param file_name:
        :return: True if actually deleted.
        """
        try:
            if os.path.isfile(file_name):
                # attempt to remove the file
                os.unlink(file_name)
                return True
        except Exception as ex:
            return False

    def clean(self):
        """
        clean out all ip record files

        :return: number cleaned
        """
        cleaned = 0
        for f in os.listdir(self._ip_record_dir):
            file_name = os.path.join(self._ip_record_dir, f)
            if self.safe_unlink(file_name):
                cleaned += 1
        return cleaned

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
        """
        make a path without funny characters

        :param dirty:
        :return:
        """
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
        if not self.init:
            self.listdir = None

        if not self.listdir:
            self.listdir = []
            for filename in os.listdir(self._ip_record_dir):
                self.listdir.append(dict(
                    filename=filename,
                    full_name=os.path.join(self._ip_record_dir, filename),
                    extension=os.path.splitext(filename)[1]))

        for entry in self.listdir:
            if '-' + ip + '-' in entry['filename'] and entry['extension'] in record_types:
                self.safe_unlink(entry['full_name'])

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
                                  mtime=datetime.fromtimestamp(
                                      os.path.getmtime(os.path.join(self._ip_record_dir, f))))
                             for
                             f in os.listdir(self._ip_record_dir)]
            filename_list = sorted(filename_list, key=operator.itemgetter('mtime'))
        except Exception as ex:
            # silently return if a file has been removed during enumeration
            return

        now = datetime.now()
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
                                delta = now - filename_entry['mtime']
                                if delta.seconds < self.ip_ban.ban_seconds:
                                    self.ip_ban.add(ip, url=' ', no_write=True, timestamp=filename_entry['mtime'])
                                else:
                                    self.safe_unlink(filename_entry['full_name'])
                            elif filename.endswith('.block'):
                                delta = now - filename_entry['mtime']
                                if delta.seconds < self.ip_ban.ban_seconds:
                                    self.ip_ban.block([ip], no_write=True, timestamp=filename_entry['mtime'])
                                else:
                                    self.safe_unlink(filename_entry['full_name'])
                            elif filename.endswith('.test'):
                                self.safe_unlink(filename_entry['full_name'])
                            elif filename.endswith('.permanent'):
                                self.ip_ban.block([ip], permanent=True, no_write=True)
                            elif filename.endswith('.remove'):
                                self.ip_ban.remove(ip, no_write=True)
                                self.remove(ip, record_types=['.block', '.permanent', '.add'])
                            else:
                                raise Exception(
                                    'Instance: {}, unknown ip record type for file: {}'.format(
                                        self._instance_id,
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

