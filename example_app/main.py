# Copyright 2015 Google Inc. All Rights Reserved.
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

from flask import Flask, render_template

from flask_ipban.ip_ban import IpBan

app = Flask(__name__)

ban_count = 5

ip_ban = IpBan(app=app, ban_count=ban_count, ban_minutes=5)


@app.route('/')
def index():
    return render_template('index.html', title='Ip Ban sample app', ban_count=ban_count)


@app.route('/block_it/<path:ip>')
def block_it(ip):
    ip_ban.block([ip])
    return 'ok'


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8888, debug=True)
