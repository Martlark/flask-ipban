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


class ExceptionLockInUse(Exception):
    def __init__(self, message):
        # Call the base class constructor with the parameters it needs
        super(Exception, self).__init__(message)


class GetLock:
    """
    get and hold a lock at the given path until the process exits or the
    context is closed
    """
    def blank_lockf(self, file_handle, options):
        pass

    def __init__(self, lock_file_prefix=__name__):

        self.lock_file_path = os.path.join(os.environ.get('TEMP', '/tmp'), lock_file_prefix + '.lock')

        try:
            fcntl = __import__('fcntl')
            self.lockf = fcntl.lockf
            self.LOCK_EX = fcntl.LOCK_EX
            self.LOCK_NB = fcntl.LOCK_NB
        except ImportError:
            self.lockf = self.blank_lockf
            self.LOCK_EX = 0
            self.LOCK_NB = 0

    def __enter__(self):
        if os.path.exists(self.lock_file_path):
            try:
                with open(self.lock_file_path, 'w') as existing_lock_file:
                    self.lockf(existing_lock_file, self.LOCK_EX | self.LOCK_NB)
                os.unlink(self.lock_file_path)
            except:
                raise ExceptionLockInUse('lock file:{} in use'.format(self.lock_file_path))

        self.lock_file = open(self.lock_file_path, 'w')
        self.lockf(self.lock_file, self.LOCK_EX)

        return self

    def __exit__(self, type, value, traceback):
        if hasattr(self, 'lock_file'):
            self.lock_file.close()
        if os.path.exists(self.lock_file_path):
            os.unlink(self.lock_file_path)
