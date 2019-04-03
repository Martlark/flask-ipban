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
    ip_ban = IpBan(ban_seconds=200)
    ip_ban.init_app(app)


The repository includes a small example application.

Options
-------

-  ``app``,  Flask application to monitor.  Use ip_ban.init_app(app) to intialise later on.
-  ``ban_count``, default ``20``, Number of observations before banning.
-  ``ban_seconds``, default ``60``, Number of seconds ip address is banned.
-  ``persist``, default ``False``, Persist ban list between restarts, using records in the report_dir folder.
-  ``report_dir``, default ``None``, Override the location of persistence and report files.
-  ``ipc``, default ``True``, Allow multiple instances of ip_ban to cross communicate using the ``report_dir``.
-  ``secret_key``, default ``flask secret key``, Key to sign reports in the ``report_dir``.

Config by env variable overrides options
########################################

These environment variables will override options from the initialisation.

-  IP_BAN_LIST_COUNT - number of observations before 403 exception
-  IP_BAN_LIST_SECONDS - number of seconds to retain memory of IP


Methods
-------

-  ``init_app(app)`` - Initialise and start ip_ban with the given Flask application.
-  ``block(ip_address, permanent=False)`` - block the specific address optionally forever
-  ``add(ip=None, url=None, reason='404')`` - increase the observations for the current request ip or given ip address

Example for add:

.. code:: python

    from flask import Flask
    from flask_ipban import IpBan

    app = Flask(__name__)
    ip_ban = IpBan(app)

    @route('/login', methods=['GET','POST']
    def login:
        # ....
        # increment block if wrong passwords to prevent password stuffing
        # ....
        if request.method == 'POST':
            if request.arg.get('password') != 'secret':
                ip_ban.add(reason='bad password')

-  ``remove(ip_address)`` - remove the given ip address from the ban list.  Returns true if ban removed.
-  ``url_pattern_add('reg-ex-pattern', match_type='regex')`` - exclude any url matching the pattern from checking


Example of url_pattern_add:

.. code:: python

    from flask import Flask
    from flask_ipban import IpBan

    app = Flask(__name__)
    ip_ban = IpBan(app)
    ip_ban.url_pattern_add('^/whitelist$', match_type='regex')
    ip_ban.url_pattern_add('/flash/dance', match_type='string')


-  ``url_pattern_remove('reg-ex-pattern')`` - remove pattern from the url whitelist
-  ``url_block_pattern_add('reg-ex-pattern', match_type='regex')`` - add any url matching the pattern to the block list. match_type can be 'string' or 'regex'.  String is direct match.  Regex is a regex pattern.
-  ``url_block_pattern_remove('reg-ex-pattern')`` - remove pattern from the url block list
-  ``ip_whitelist_add('ip-address')`` - exclude the given ip from checking
-  ``ip_whitelist_remove('ip-address')`` - remove the given ip from the ip whitelist


Example of ip_whitelist_add

.. code:: python

    from flask import Flask
    from flask_ipban import IpBan

    app = Flask(__name__)
    ip_ban = IpBan(app)
    ip_ban.whitelist_add('127.0.0.1')


-  ``load_nuisances(file_name=None)`` - add a list of nuisances to url pattern block list from a file.  See below for more information.

Example:

.. code:: python

    ip_ban = IpBan()
    app = Flask(__name__)
    ip_ban.init_app(app)
    ip_ban.load_nuisances()


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

You can add your own nuisance yaml file by calling with the parameter file_name=.

See the nuisance.yaml file in the source for formatting and details.

IPC and persistence
-------------------

By default ip_ban writes out each 404/ban event to a file in the ``record_dir`` folder, which has a default in linux of
``/tmp/flask-ip-ban``.  This folder has to be writable by the process running your app.  Obviously if you use multiple
different apps they can share ip_ban reporting.  Each record is signed with the ``secret_key``, so this must be shared
amongst all applications that use the ``record_dir`` folder.  The ``secret_key`` is by default the flask secret key.

Only ip records using the `block`, `add` and `remove` methods or by 404; are persisted or shared.  Any whitelisting or 
pattern bans are not presisted/shared and must be done for each instance of your application.

Licensing
---------

- Apache 2.0

.. |PyPI Version| image:: https://img.shields.io/pypi/v/flask-ipban.svg
   :target: https://pypi.python.org/pypi/flask-ipban

