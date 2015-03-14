#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of hashID.
#
# hashID is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# hashID is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with hashID. If not, see <http://www.gnu.org/licenses/>.

import io
import os
import re
from setuptools import setup, find_packages


def read(*parts):
    here = os.path.abspath(os.path.dirname(__file__))
    with io.open(os.path.join(here, *parts), "r", encoding="utf-8") as f:
        return f.read()


def get_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


setup(
    name='hashID',
    packages=find_packages(exclude=['HASHINFO.xlsx']),
    version=get_version('hashid.py'),
    description='Software to identify the different types of hashes',
    long_description=read('README.rst'),
    author='c0re',
    author_email='c0re@psypanda.org',
    license='GNU GPL',
    url='https://github.com/psypanda/hashID',
    download_url='https://github.com/psypanda/hashID/tarball/v' + get_version('hashid.py'),
    keywords='hashid hash identifier hash-identifier',
    py_modules=['hashid'],
    entry_points={
        'console_scripts': [
            'hashid = hashid:main',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Natural Language :: English',
        'Intended Audience :: Other Audience',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
)
