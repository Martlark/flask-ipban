# Copyright 2019 Andrew Rowe Inc. All Rights Reserved.
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

from flask import Flask, render_template, abort, request

from flask_ipban.ip_ban import IpBan

app = Flask(__name__)

ban_count = 5
ban_seconds = 5

ip_ban = IpBan(app=app, ban_count=ban_count, ban_seconds=ban_seconds)
ip_ban.load_nuisances()
ip_ban.url_pattern_add('/tmp/\\d*$')
ip_ban.url_pattern_add('/whitelist/\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b$')


@app.route('/hello')
def hello():
    return 'Hello there'


@app.route('/')
def index():
    return render_template('index.html', title='Ip Ban sample app', ban_count=ban_count, ban_seconds=ban_seconds)


@app.route('/block_it/<path:ip>')
def block_it(ip):
    ip_ban.block([ip])
    return 'ok'


@app.route('/tmp/<int:random_int>')
def ignore_it(random_int):
    url = request.environ.get('PATH_INFO')
    app.logger.info('404 will be ignored: url: {}'.format(url))
    abort(404)
    return 'ok'


@app.route('/add_it')
def add_it():
    result = ip_ban.add(reason='spite')
    return 'ok: observation added: {}'.format(result)


@app.route('/whitelist/<string:ip>', methods=['PUT', 'DELETE'])
def whitelist_ip(ip):
    result = 'error: unknown method'
    if request.method == 'PUT':
        result = 'Added.  {} entries in the whitelist'.format(ip_ban.ip_whitelist_add(ip))
    elif request.method == 'DELETE':
        result = '{} removed'.format(ip) if ip_ban.ip_whitelist_remove(ip) else '{} not in whitelist'.format(ip)
    return result


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8888, debug=True)
