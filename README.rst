IpBan: HTTP spam security for Flask
=========================================

|PyPI Version|

IpBan is a Flask extension that can help protect against ip sources spamming url requests
against unknown pages or attempts to exploit URLs.  Often this is to search for security issues.

The default configuration:

- 20 attempts before ban
- 1 day blocking period

Once an ip address is banned any attempt to access a web address on your site from that ip will
result in a 403 forbidden status response.  After the default 1 day blocking period of no access
attempts the ban will be lifted.  Any access attempt during the ban period will extend the ban period
by the `ban_seconds` amount.

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
-  ``ban_seconds``, default ``3600*24 (one day)``, Number of seconds ip address is banned.
-  ``persist``, default ``False``, Persist ban list between restarts, using records in the report_dir folder.
-  ``report_dir``, default ``None``, Override the location of persistence and report files.
-  ``ipc``, default ``False``, Allow multiple instances of ip_ban to cross communicate using the ``report_dir``.
-  ``secret_key``, default ``flask secret key``, Key to sign reports in the ``report_dir``.
-  ``ip_header``, default ``None``, Optional name of request header that contains the ip for use behind proxies when in a docker/kube hosted env.
-  ``abuse_IPDB_config``, default ``None``, config {key=, report=False, load=False} to a AbuseIPDB.com account.  Blocked ip addresses via url nuisance matching will be reported.

Config by env variable overrides options
########################################

These environment variables will override options from the initialisation.

-  IP_BAN_LIST_COUNT - number of observations before 403 exception
-  IP_BAN_LIST_SECONDS - number of seconds to retain memory of IP


Methods
-------

-  ``init_app(app)`` - Initialise and start ip_ban with the given Flask application.
-  ``block(ip_address, permanent=False)`` - block the specific address, optionally forever
-  ``add(ip=None, url=None)`` - increase the observations for the current request ip or given ip address

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
                ip_ban.add()

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
    ip_ban.ip_whitelist_add('127.0.0.1')


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

Block networks / cidr
---------------------

Use the `block_cidr(network)` method to block a range of addresses or whole regions.

Example:

.. code:: python

    ip_ban = IpBan()
    app = Flask(__name__)
    ip_ban.init_app(app)
    # block a network in Aruba
    ip_ban.block_cidr('190.220.142.104/29')


Nuisance file
-------------

ip_ban includes a file of common web nuisances that should not be allowed on a flask site.  It includes:

- Blocking any non flask extension such as .jsp, .asp etc.
- Known hacking urls.

Nuisance urls are only checked as a result of a 404.  If you have legitimate routes
that use nuisance url patterns they won't result in a block.

Load them by calling ip_ban.load_nuisances()

You can add your own nuisance yaml file by calling with the parameter `file_name`.

See the nuisance.yaml file in the source for formatting and details.

IPC and persistence
-------------------

When you have multiple applications or processes serving a web application it can be handy to share
any abuse ip between processes.  The ipc option allows this.

Set ipc to True to allow writing out each 404/ban event to a file in the ``record_dir`` folder, which has a default in linux of
``/tmp/flask-ip-ban``.  This folder has to be writable by the process running your app.  Obviously if you use multiple
different apps they can share ip_ban reporting.  Each record is signed with the ``secret_key``, so this must be shared
amongst all applications that use the ``record_dir`` folder.  The ``secret_key`` is by default the flask secret key.

This folder and secret key is also used by the persistence feature.

Only ip records using the `block`, `add` and `remove` methods or by 404; are persisted or shared.  Any whitelisting or
pattern bans are not persisted/shared and must be done for each instance of your application.

The bit that shares ipc records between processes only updates during the `before_request` handler
of the Flask app. It only updates every 5 seconds at the most. If the app does no
request handling between bans then that ban record won't be shared between processes.

IP Header
---------
When running a flask app in a docker hosted environment (or similar) the ip address will be the virtual
adapter ip and won't change for differing requests.  Use your proxy server to set the real IP address in a header
so that ip-ban can find what it really is.  For apache:


    ``RequestHeader set X_TRUE_IP "%{REMOTE_ADDR}s"``

    ``ProxyPass / http://localhost:8080/``

    ``ProxyPassReverse / http://localhost:8080/``

Then when initializing ip_ban set the header name using the parameter ``ip_header``, in this example: ip_header='X_TRUE_IP'.

Abuse IPDB
----------

see: https://docs.abuseipdb.com/#introduction

You can setup flask-ipban so it will auto report url hacking attempts to the Abuse IPDB.  Or you can
load the Abuse IPDB list of blocked ip address on start.  Warning!  Loading takes a while for the default 10000 records.

*Config*

abuse_IPDB_config = {key=, report=False, load=False, debug=False}

* key - your abuse IPDB api v2 key
* report - True/False (default is False) - report hack attempts to the DB.
* load - True/False (default is False) - load and block already blocked ip addresses from the DB on startup
* debug - True/False (default is False) - debug mode, uses ip 127.0.0.1.


Release History
---------------

* 1.0.13 - Remove reason= which did nothing.  Add url to report table.  Add more nuisances.  Add release history.
* 1.1.0 - Add more nuisances.  Add ability to block regions by using `block_cidr()`.  Remove support for obsolete Python releases (2.7,3.4,3.5).
* 1.1.1 - Fix doco typo.
* 1.1.2 - allow ip as list for ip_whitelist_add()/ip_whitelist_remove().

Licensing
---------

- Apache 2.0

.. |PyPI Version| image:: https://img.shields.io/pypi/v/flask-ipban.svg
   :target: https://pypi.python.org/pypi/flask-ipban

