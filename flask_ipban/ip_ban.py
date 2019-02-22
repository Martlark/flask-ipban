import os
from datetime import datetime, timedelta

from flask import request, abort


class IpBan:
    """
    implements a simple list of ip addresses that
    seem to be trying credential stuffing.

    Optional config by env variable
    ======
    IP_BAN_LIST_COUNT - number of entries before 403 exception
    IP_BAN_LIST_MINUTES - number of minutes to retain memory of IP

    """

    def __init__(self, app=None, ban_count=50, ban_minutes=60):
        """
        start
        :param app: (optional when using init_app) flask application with logger defined
        :param ban_count: (optional) number of observations before ban
        :param ban_minutes: (optional) number minutes of silence before ban rescinded (0 is never rescind)
        """
        self._ip_ban_list = {}
        self.ban_count = int(os.environ.get('IP_BAN_LIST_COUNT', ban_count))
        self.ban_seconds = int(os.environ.get('IP_BAN_LIST_MINUTES', ban_minutes)) * 60
        self.app = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        initialise using app as parameter
        :param app: flask app with logger defined
        :return:
        """
        self.app = app
        app.after_request(self.after_request)
        app.before_request(self.check)

    def after_request(self, response):
        if response.status_code == 404:
            self.add()
        return response

    def block(self, ip_list, permanent=False):
        """
        add a list of ip address to the block list
        :param ip_list: list of ip addresses to block
        :param permanent: (optional) True=do not allow entries to expire
        """
        for ip in ip_list:
            entry = self._ip_ban_list.get(ip)
            if entry:
                entry['timestamp'] = datetime.utcnow()
                entry['count'] = self.ban_count * 2
            else:
                self._ip_ban_list[ip] = dict(timestamp=datetime.utcnow(), count=self.ban_count * 2)

            if permanent:
                # ban for about 38 years
                entry = self._ip_ban_list[ip]
                entry['timestamp'] = datetime.utcnow() + timedelta(minutes=20000000)
            self.app.logger.warning('{ip} added to ban list.'.format(ip=ip))

    def check(self):
        """
        raise 403 exception if ip in request has made too many 404 or failed login attempts
        """
        ip = request.environ.get('REMOTE_ADDR')
        entry = self._ip_ban_list.get(ip)
        if entry and entry.get('count', 0) > self.ban_count:
            url = request.environ.get('PATH_INFO')
            utc_now = datetime.utcnow()
            delta = utc_now - entry.get('timestamp', utc_now)
            if delta.seconds < self.ban_seconds or self.ban_seconds == 0:
                self.app.logger.exception('IP is in ban list {}.  Url: {}'.format(ip, url))
                abort(403)
            else:
                self.app.logger.exception('IP expired from ban list {}.  Url: {}'.format(ip, url))
                self._ip_ban_list[ip]['count'] = 0

    def add(self, reason='404'):
        """
        increment ban count ip of the current request in the banned list
        :param reason: optional reason for ban, default is 404
        """

        ip = request.environ.get('REMOTE_ADDR')
        url = request.environ.get('PATH_INFO')
        entry = self._ip_ban_list.get(ip)
        if entry:
            entry['timestamp'] = datetime.utcnow()
            entry['count'] += 1
        else:
            self._ip_ban_list[ip] = dict(timestamp=datetime.utcnow(), count=1)
            entry = self._ip_ban_list[ip]

        self.app.logger.warning(
            '{}. url {}.  {} in ban list. count: {}'.format(reason,
                                                            url,
                                                            ip,
                                                            entry['count']))
        return entry['count']
