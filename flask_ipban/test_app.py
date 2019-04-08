from flask import Flask
import sys
import logging
from flask_ipban.ip_ban import IpBan


"""
small flask application for testing of functions.
"""

secret_key = 'abscdefghijklj430urojfdshfdsoih'
test_ip_ban = IpBan(ban_count=4, ban_seconds=20, persist=True, record_dir='/tmp/flask-ip-ban-test-app')
app = Flask(__name__)


@app.route('/ban')
def route_block():
    test_ip_ban.block(['127.0.0.1'])
    return '<h1>You are now blocked</h1>'


@app.route('/remove')
def route_remove():
    test_ip_ban.remove('127.0.0.1')
    return '<h1>You are now free</h1>'


@app.route('/ban_perm')
def route_block_perm():
    test_ip_ban.block(['127.0.0.1'], permanent=True)
    return '<h1>You are now blocked</h1>'


@app.route('/unblock')
def route_unblock():
    test_ip_ban.remove('127.0.0.1')
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
    <a href='/ban'>Block 127.0.0.1</a>
    <a href='/ban_perm'>Block perm 127.0.0.1</a>
    <a href='/remove'>remove 127.0.0.1</a>
    <a href='/doesnotexist'>404</a>
    <a href='/unblock'>unblock</a>
    <a href='/sftp-config.json'>nuisance url</a>
    <script>{js}</script>
    <br>
    <button onclick="startExercise()">Start exercise</button>
    <button onclick="stopExercise()">Cancel exercise</button>
    '''.format(js=js)


def run():
    app.secret_key = secret_key
    test_ip_ban.init_app(app)
    test_ip_ban.url_pattern_add('/unblock', match_type='string')
    test_ip_ban.load_nuisances()
    app.logger.setLevel(logging.INFO)

    port = 8887
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    app.run(host='0.0.0.0', port=port, debug=True)
