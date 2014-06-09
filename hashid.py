#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2013-2014 by c0re
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__author__  = "c0re"
__version__ = "2.8.1"
__github__  = "https://github.com/psypanda/hashID"
__license__ = "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>"

import re
import os
import io
import sys
import json
import argparse
from collections import namedtuple

Prototype = namedtuple('Prototype', ['regex', 'modes'])
HashMode = namedtuple('HashMode', ['name', 'hashcat', 'extended'])

JSON_PATH = os.path.join(os.path.dirname(__file__), 'prototypes.json')


class HashID(object):

    """HashID with configurable prototypes"""

    def __init__(self, prototypes=None):
        super(HashID, self).__init__()

        if prototypes:
            # Set self.prototypes to a copy of prototypes to allow
            # modification after instantiation
            self.prototypes = list(prototypes)
        else:
            self.prototypes = []
            with open(JSON_PATH) as f:
                for prototype in json.load(f):
                    self.prototypes.append(Prototype(
                        regex=re.compile(prototype['regex'], re.IGNORECASE),
                        modes=[
                            HashMode(
                                name=mode['name'],
                                hashcat=mode['hashcat'],
                                extended=mode['extended']) for mode in prototype['modes']
                        ]))

    def identifyHash(self, phash):
        """return algorithm and hashcat mode"""
        phash = phash.strip()
        for prototype in self.prototypes:
            if prototype.regex.match(phash):
                for mode in prototype.modes:
                    yield mode


def writeResult(candidate, identified_modes, outfile=sys.stdout, hashcatMode=False, extended=False):
    """create human readable output"""
    outfile.write(u"Analyzing '{0}'\n".format(candidate))
    count = 0
    for mode in identified_modes:
        if not mode.extended or extended:
            if hashcatMode and mode.hashcat is not None:
                outfile.write(u"[+] {0} [Hashcat Mode: {1}]\n".format(mode.name, mode.hashcat))
            else:
                outfile.write(u"[+] {0}\n".format(mode.name))
        count += 1
    if count == 0:
        outfile.write(u"[+] Unknown hash\n")
    return (count > 0)


def main():
    usage = "{0} [-a] [-m] [--help] [--version] INPUT".format(__file__)
    banner = "hashID v{0} by {1} ({2})".format(__version__, __author__, __github__)
    description = "Identify the different types of hashes used to encrypt data"

    parser = argparse.ArgumentParser(usage=usage, description=description, epilog=__license__)
    parser.add_argument("strings", metavar="input", type=str, nargs="+", help="string or filename to analyze")
    parser.add_argument("-a", "--all", action="store_true", help="list all possible hash algorithms including salted passwords")
    parser.add_argument("-m", "--mode", action="store_true", help="include corresponding hashcat mode in output")
    parser.add_argument("--version", action="version", version=banner)
    args = parser.parse_args()

    hashID = HashID()

    if not args.strings:
        for line in sys.stdin:
            writeResult(line.strip(), hashID.identifyHash(line.strip()), sys.stdout, args.mode, args.all)
    else:
        for string in args.strings:
            if os.path.isfile(string):
                try:
                    with io.open(string, "r", encoding="utf-8") as infile:
                        print("--File '{0}'--".format(string))
                        for line in infile:
                            if line.strip():
                                writeResult(line.strip(), hashID.identifyHash(line.strip()), sys.stdout, args.mode, args.all)
                    infile.close()
                except IOError:
                    print("--File '{0}' - could not open--".format(string))
                else:
                    print("--End of file '{0}'--".format(string))
            else:
                writeResult(string, hashID.identifyHash(string), sys.stdout, args.mode, args.all)


if __name__ == "__main__":
    main()
