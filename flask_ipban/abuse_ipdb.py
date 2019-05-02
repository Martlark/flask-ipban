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

from datetime import datetime
import json
import requests

from flask_ipban.get_lock import GetLock, ExceptionLockInUse


class AbuseIPDB:
    def __init__(self, logger, ip_ban, key, report=False, load=False, debug=False):
        """
        Report/load to AbuseIPDB.com
        :param logger: flask logger to use
        :param ip_ban: ip_ban instance
        :param key: AbuseIPDB.com api key
        :param report: True/False - report url blocks to AbuseIPDB
        :param load:  True/False - load the AbuseIPDB blacklist
        :param debug: True/False - debug mode - alters ip to 127.0.0.2 for abuse db
        """
        self.key = key
        self.logger = logger
        self.ip_ban = ip_ban
        self.report = report
        self.end_point = 'https://api.abuseipdb.com/api/v2/'
        self.categories = [21]  # Web App Attack
        self.lock_name = 'flask-ip-ban-abuse-ipdb-load'
        self.debug = debug
        self.reported = {}  # url and ip alread reported
        if load:
            self.import_black_list()

    def report_ip(self, ip, reason, categories=None):
        """
            :param ip: the address being reported
            :param reason: reason for report
            :param categories: numbered list of report categories. default 21 is web app attack
            :return success code: ['already','error','ok','']
        """
        if not self.report:
            return ''

        key = ip + '-' + reason

        if self.reported.get(key):
            self.logger.info('Already reported {}'.format(key))
            # already reported ip and reason combination
            return 'already'

        if self.debug:
            # ip = '127.0.0.2' use for testing when api is rate limited
            ip = '127.0.0.1'

        url = self.end_point + 'report'
        data = dict(ip=ip, comment=reason, categories=','.join(map(str, categories or self.categories)))
        headers = dict(Accept='application/json', Key=self.key)
        try:
            # POST the submission.
            # curl https://api.abuseipdb.com/api/v2/report \
            #  --data-urlencode "ip=127.0.0.1" \
            #  -d categories=18,22 \
            #  --data-urlencode "comment=SSH login attempts with user root." \
            #  -H "Key: $YOUR_API_KEY" \
            #  -H "Accept: application/json"
            response = requests.post(url, data=data, headers=headers).content
            json_response = json.loads(response)
            if json_response.get('data'):
                self.reported[key] = datetime.utcnow()
                self.logger.warn('reported ip {} for {}.  ok: {}'.format(ip, reason, json_response.get('data')))
            else:
                self.logger.error('reported ip {} for {}.  Error: {}'.format(ip, reason, response))
                return 'error'

        except Exception as e:
            self.logger.error('Error reporting ip to {}'.format(url))
            self.logger.exception(e)
            return 'error'
        return 'ok'

    def import_black_list(self):
        """
        import the top 10000 blocked ip address from the abuse db
        NOTE: can take a long time.
        :return:
        """
        url = self.end_point + 'blacklist'
        data = json.dumps(dict(countMinimum=15, maxAgeInDays=20, confidenceMinimum=100))
        headers = dict(Accept='application/json', Key=self.key)
        try:
            with GetLock(self.lock_name):
                # The -G option will convert form parameters (-d options) into query parameters.
                # The CHECK endpoint is a GET request.
                # curl - G
                # https: // api.abuseipdb.com / api / v2 / blacklist \
                #           - d
                # countMinimum = 15 \
                #                - d
                # maxAgeInDays = 60 \
                #                - d
                # confidenceMinimum = 90 \
                #                     - H
                # "Key: $YOUR_API_KEY" \
                # - H
                # "Accept: application/json"
                #
                # {
                #     "meta": {
                #         "generatedAt": "2018-12-21T16:00:04+00:00"
                #     },
                #     "data": [
                #         {
                #             "ipAddress": "5.188.10.179",
                #             "totalReports": 560,
                #             "abuseConfidenceScore": 100
                #         },
                #         {
                #             "ipAddress": "185.222.209.14",
                #             "totalReports": 529,
                #             "abuseConfidenceScore": 100
                #         },
                #         {
                #             "ipAddress": "191.96.249.183",
                #             "totalReports": 325,
                #             "abuseConfidenceScore": 100
                #         },
                #         ...
                #     ]
                # }

                response = requests.get(url, params=data, headers=headers).content
                json_response = json.loads(response.decode('utf-8'))
                self.logger.warn('Got ip blacklist.  Importing {} records.'.format(len(json_response['data'])))
                ip_list = [record['ipAddress'] for record in json_response['data']]
                self.ip_ban.block(ip_list=ip_list, no_write=False)
        except ExceptionLockInUse:
            self.logger.warn('Other flask-ip-ban process has import lock:{}'.format(self.lock_name))
            return
        except Exception as e:
            self.logger.error('Error importing ip blacklist from: {}.  Response: {}'.format(url, response))
            self.logger.exception(e)
