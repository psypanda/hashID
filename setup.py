#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

def get_version():
    with open('hashid.py') as f:
        for line in f:
            if line.startswith('__version__'):
                return eval(line.split('=')[-1])

def get_long_description():
    descr = []
    for fname in 'README.rst', 'doc/CHANGELOG':
        with open(fname) as f:
            descr.append(f.read())
    return '\n\n'.join(descr)

setup(
    name = 'hashID',
    packages = ['hashID'],
    version = get_version(),
    description = 'Software to identify the different types of hashes',
    long_description = get_long_description(),
    author = 'c0re',
    author_email = 'c0re@psypanda.org',
    license = 'GNU GPL',
    url = 'https://github.com/psypanda/hashID',
    download_url = 'https://github.com/psypanda/hashID/tarball/v' + get_version(),
    keywords = ['hashid', 'hash', 'identifier', 'hash-identifier'],
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Other Audience',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
    ],
)
