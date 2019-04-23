#!/usr/bin/env bash
# Notes and commands to upload to pypi
#
# https://medium.com/@joel.barmettler/how-to-upload-your-python-package-to-pypi-65edc5fe9c56
# https://pypi.org/project/twine/
#
# https://python-packaging.readthedocs.io/en/latest/non-code-files.html
# edit setup.py
# to update the version

. venv36/bin/activate

# first

pip install setuptools
pip install wheel
pip install twine

# on each release

python3 setup.py sdist bdist_wheel
#
twine check dist/flask_ipban-1.0.5*
# test
# pip install -e .
# twine upload --repository-url https://test.pypi.org/legacy/ dist/* -u martlark
# prod pypi
# add release in git hub to match the version
twine upload dist/flask_ipban-1.0.5* -u martlark
