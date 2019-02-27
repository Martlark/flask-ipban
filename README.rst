IpBan: HTTP spam security for Flask
=========================================

|PyPI Version|

IpBan is a Flask extension that can help protect against ip locations spamming url requests
against unknown pages.  Often this is to search for security issues.

The default configuration:

- 50 attempts before ban
- 1 hour blocking period

Installation & Basic Usage
--------------------------

Install via `pip <https://pypi.python.org/pypi/pip>`_:

::

    pip install flask-ipban

After installing, wrap your Flask app with a ``IpBan``:

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
-  ``ip_ban.block(ip_address, permanent=True)`` - block the specific address forever
-  ``ip_ban.add(reason='spite')`` - increase the observation for the current request ip

Per-view options
~~~~~~~~~~~~~~~~

Example code

.. code:: python

    from flask import Flask
    from flask_ipban import IpBan

    app = Flask(__name__)
    ip_ban = IpBan(app)

    @app.route('/normal')
    def normal():
        return 'Normal'
Licensing
---------

- Apache 2.0

.. |PyPI Version| image:: https://img.shields.io/pypi/v/flask-ipban.svg
   :target: https://pypi.python.org/pypi/flask-ipban

