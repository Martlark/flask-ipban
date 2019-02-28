IpBan: HTTP spam security for Flask
=========================================

|PyPI Version|

IpBan is a Flask extension that can help protect against ip locations spamming url requests
against unknown pages.  Often this is to search for security issues.

The default configuration:

- 50 attempts before ban
- 1 hour blocking period

Once an ip address is banned any attempt to access a web address will result in a 403 forbidden
result.  After the default 1 hour blocking period of no access attempts the ban will be lifted.
Any access attempt during the ban period will extend the ban period.

Ip addresses can be manually entered for banning.  Url patterns can be configured to be excluded
from ban calculations.

Installation & Basic Usage
--------------------------

Install via `pip <https://pypi.python.org/pypi/pip>`_:

::

    pip install flask-ipban

After installing, wrap your Flask app with an ``IpBan``, or call ip_ban.init_app(app):

.. code:: python

    from flask import Flask
    from flask_ipban import IpBan

    app = Flask(__name__)
    IpBan(app)


Enclosed is a small example application

Options
-------

-  ``ban_count``, default ``50``, Number of observations before banning
-  ``ban_seconds``, default ``60``, Number of seconds ip address is banned


Methods
-------

-  ``block(ip_address, permanent=False)`` - block the specific address optionally forever
-  ``add(reason='404')`` - increase the observations for the current request ip
-  ``url_pattern_add('reg-ex-pattern')`` - exclude any url matching the pattern from checking
-  ``url_pattern_remove('reg-ex-pattern')`` - remove pattern from the url whitelist
-  ``url_block_pattern_add('reg-ex-pattern', match_type='regex')`` - add any url matching the pattern to the block list. match_type can be 'string' or 'regex'.  String is direct match.  Regex is a regex pattern.
-  ``url_block_pattern_remove('reg-ex-pattern')`` - remove pattern from the url block list
-  ``ip_whitelist_add('ip-address')`` - exclude the given ip from checking
-  ``ip_whitelist_remove('ip-address')`` - remove the given ip from the ip whitelist
-  ``load_nuisances(file_name=None)`` - add a list of nuisances to url pattern block list from a file.  See below for more information.


Example code

.. code:: python

    from flask import Flask
    from flask_ipban import IpBan

    app = Flask(__name__)
    ip_ban = IpBan(app)

    @app.route('/normal')
    def normal():
        return 'Normal'

Nuisance file
-------------

ip_ban includes a file of common web nuisances that should not be allowed on a flask site.  It includes:

- Blocking any non flask extension such as .jsp, .asp etc.
- Known hacking urls.

Load them by calling ip_ban.load_nuisances()

You can add your own nuisance file by calling with the parameter file_name=.

See the nuisance.txt file in the source for formatting and details.

Licensing
---------

- Apache 2.0

.. |PyPI Version| image:: https://img.shields.io/pypi/v/flask-ipban.svg
   :target: https://pypi.python.org/pypi/flask-ipban

