IpBan: HTTP spam security for Flask
=========================================

|PyPI Version|

IpBan is a Flask extension that can help protect against ip locations spamming url requests
against unknown pages.  Often this is to search for security issues.

The default configuration:

- 20 attempts before ban
- 1 hour blocking period

Once an ip address is banned any attempt to access a web address on your site from that ip will
result in a 403 forbidden status response.  After the default 1 hour blocking period of no access
attempts the ban will be lifted.  Any access attempt during the ban period will extend the ban period.

Ip addresses can be entered for banning by the api.

Url patterns can be entered to be excluded from ban calculations by the api.

Url patterns can be entered for banning by the api.

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
    IpBan(app, ban_seconds=200)


The repository includes a small example application

Options
-------

-  ``ban_count``, default ``20``, Number of observations before banning
-  ``ban_seconds``, default ``60``, Number of seconds ip address is banned
-  ``persist``, default ``False``, Persist, by the use of a file in the tmp folder, the ip ban list.
-  ``persist_file_name``, default ``None``, Override the name of the persistence file.

Config by env variable overrides options
########################################

These environment variables will override options from the initialisation.

-  IP_BAN_LIST_COUNT - number of observations before 403 exception
-  IP_BAN_LIST_SECONDS - number of seconds to retain memory of IP


Methods
-------

-  ``block(ip_address, permanent=False)`` - block the specific address optionally forever
-  ``add(reason='404')`` - increase the observations for the current request ip
-  ``url_pattern_add('reg-ex-pattern', match_type='regex')`` - exclude any url matching the pattern from checking
-  ``url_pattern_remove('reg-ex-pattern')`` - remove pattern from the url whitelist
-  ``url_block_pattern_add('reg-ex-pattern', match_type='regex')`` - add any url matching the pattern to the block list. match_type can be 'string' or 'regex'.  String is direct match.  Regex is a regex pattern.
-  ``url_block_pattern_remove('reg-ex-pattern')`` - remove pattern from the url block list
-  ``ip_whitelist_add('ip-address')`` - exclude the given ip from checking
-  ``ip_whitelist_remove('ip-address')`` - remove the given ip from the ip whitelist
-  ``load_nuisances(file_name=None)`` - add a list of nuisances to url pattern block list from a file.  See below for more information.


Example whitelist code

.. code:: python

    from flask import Flask
    from flask_ipban import IpBan

    app = Flask(__name__)
    ip_ban = IpBan(app)
    ip_ban.url_pattern_add('^/whitelist$')

    @app.route('/normal')
    def normal():
        return 'Normal'

    @app.route('/whitelist')
    def whitelist():
        parameter_value = request.args.get('parameter')
        return 'whitelist ' + parameter_value

Url patterns
------------

Url matching match_type can be 'string' or 'regex'.  String is direct match.  Regex is a regex pattern.

Nuisance file
-------------

ip_ban includes a file of common web nuisances that should not be allowed on a flask site.  It includes:

- Blocking any non flask extension such as .jsp, .asp etc.
- Known hacking urls.

Nuisance urls are only checked as a result of a 404.  If you have legitimate routes
that use nuisance url patterns they won't result in a block.

Load them by calling ip_ban.load_nuisances()

You can add your own nuisance file by calling with the parameter file_name=.

See the nuisance.txt file in the source for formatting and details.

Licensing
---------

- Apache 2.0

.. |PyPI Version| image:: https://img.shields.io/pypi/v/flask-ipban.svg
   :target: https://pypi.python.org/pypi/flask-ipban

