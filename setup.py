#!/usr/bin/env python
# -*- coding: utf-8 -*-

import io
import os
import re
from setuptools import setup


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
    packages=['hashID'],
    version=get_version('hashid.py'),
    description='Software to identify the different types of hashes',
    long_description=read('README.rst'),
    author='c0re',
    author_email='c0re@psypanda.org',
    license='GNU GPL',
    url='https://github.com/psypanda/hashID',
    download_url=url + '/tarball/v' + get_version('hashid.py'),
    keywords='hashid hash identifier hash-identifier',
    py_modules=['hashid'],
    # packages=find_packages(exclude=['man', 'hashinfo.xlsx'])
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Natural Language :: English',
        'Intended Audience :: Other Audience',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
    ],
)
