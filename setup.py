# Copyright 2019 Andrew Rowe.
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

from codecs import open

from setuptools import setup

VERSION = '1.1.2'
LONG_DESCRIPTION = open('README.rst', 'r', encoding='utf-8').read()

setup(
    name='flask-ipban',

    version=VERSION,

    description='URL spam security for Flask.',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/x-rst',

    url='https://github.com/Martlark/flask-ipban',
    download_url='https://github.com/Martlark/flask-ipban/archive/{version}.tar.gz'.format(version=VERSION),

    author='Andrew Rowe',
    author_email='rowe.andrew.d@gmail.com',

    license='Apache Software License',

    classifiers=[
        'Development Status :: 5 - Production/Stable',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',

        'License :: OSI Approved :: Apache Software License',

        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',

        'Operating System :: POSIX',
        'Operating System :: MacOS',
        'Operating System :: Unix',
        'Operating System :: Microsoft :: Windows',

        'Framework :: Flask',
    ],
    keywords='flask security spam url ban',

    packages=['flask_ipban'],
    include_package_data=True,
    install_requires=['flask>=0.11', 'pyyaml', 'itsdangerous', 'requests'],
)
