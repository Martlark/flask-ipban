import os
import re
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

    def __init__(self, app=None, ban_count=50, ban_seconds=3600):
        """
        start
        :param app: (optional when using init_app) flask application with logger defined
        :param ban_count: (optional) number of observations before ban
        :param ban_seconds: (optional) number minutes of silence before ban rescinded (0 is never rescind)
        """
        self._ip_whitelist = {}
        self._ip_ban_list = {}
        self._url_whitelist_patterns = {}
        self.ban_count = int(os.environ.get('IP_BAN_LIST_COUNT', ban_count))
        self.ban_seconds = int(os.environ.get('IP_BAN_LIST_SECONDS', ban_seconds))
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
                entry['permanent'] = True
            self.app.logger.info('{ip} added to ban list.'.format(ip=ip))
        return len(self._ip_ban_list)

    def check(self):
        """
        raise 403 exception if ip in request has made too many 404 or failed login attempts
        checks url and ip lists
        """

        if self._is_excluded():
            return

        ip = request.environ.get('REMOTE_ADDR')
        url = request.environ.get('PATH_INFO')

        entry = self._ip_ban_list.get(ip)
        if entry and entry.get('count', 0) > self.ban_count:
            url = request.environ.get('PATH_INFO')
            utc_now = datetime.utcnow()
            delta = utc_now - entry.get('timestamp', utc_now)

            if entry.get('permanent', False):
                abort(403)

            if delta.seconds < self.ban_seconds or self.ban_seconds == 0:
                self.app.logger.warning('IP is in ban list {}.  Url: {}'.format(ip, url))
                abort(403)
            else:
                self.app.logger.warning('IP expired from ban list {}.  Url: {}'.format(ip, url))
                self._ip_ban_list[ip]['count'] = 0

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
        add the pattern to the list of url patterns to ignore
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
        :param url: optional url to display
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
            self._ip_ban_list[ip] = dict(timestamp=datetime.utcnow(), count=1)
            entry = self._ip_ban_list[ip]

        self.app.logger.info(
            '{}. {} {} added to ban list. Count: {}'.format(reason, ip, url, entry['count']))
        return True
