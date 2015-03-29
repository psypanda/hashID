#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# hashid.py - Software to identify the different types of hashes
# Copyright (C) 2013-2015 by c0re <c0re@psypanda.org>
#
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

import io
import os
import re
import sys
import argparse
from collections import namedtuple
import json
import pkgutil

__author__  = "c0re"
__version__ = "3.2.0-dev"
__github__  = "https://github.com/psypanda/hashID"
__license__ = "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>"
__banner__  = "hashID v{0} by {1} ({2})".format(__version__, __author__, __github__)

Prototype = namedtuple('Prototype', ['regex', 'modes'])
HashInfo = namedtuple('HashInfo', ['name', 'hashcat', 'john', 'extended'])

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
            for prototype in json.loads(pkgutil.get_data('hashid', 'prototypes.json')):
                self.prototypes.append(Prototype(
                    regex=re.compile(prototype['regex'], re.IGNORECASE),
                    modes=[
                        HashInfo(
                            name=mode['name'],
                            hashcat=mode['hashcat'],
                            john=mode['john'],
                            extended=mode['extended']) for mode in prototype['modes']
                    ]))

    def identifyHash(self, phash):
        """Returns identified HashInfo"""
        phash = phash.strip()
        for prototype in self.prototypes:
            if prototype.regex.match(phash):
                for mode in prototype.modes:
                    yield mode


def writeResult(identified_modes, outfile, hashcatMode=False, johnFormat=False, extended=False):
    """Write human readable output from identifyHash"""
    count = 0
    hashTypes = ""
    for mode in identified_modes:
        if not mode.extended or extended:
            count += 1
            hashTypes += u"[+] {0} ".format(mode.name)
            if hashcatMode and mode.hashcat is not None:
                hashTypes += "[Hashcat Mode: {0}]".format(mode.hashcat)
            if johnFormat and mode.john is not None:
                hashTypes += "[JtR Format: {0}]".format(mode.john)
            hashTypes += "\n"
    outfile.write(hashTypes)
    if count == 0:
        outfile.write(u"[+] Unknown hash\n")
    return (count > 0)


def main():
    usage = "{0} [-h] [-e] [-m] [-j] [-o FILE] [--version] INPUT".format(os.path.basename(__file__))

    parser = argparse.ArgumentParser(
        description="Identify the different types of hashes used to encrypt data",
        usage=usage,
        epilog=__license__,
        add_help=False,
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=27)
    )
    parser.add_argument("strings",
                        metavar="INPUT", type=str, nargs="*",
                        help="input to analyze (default: STDIN)")
    group = parser.add_argument_group('options')
    group.add_argument("-e", "--extended",
                       action="store_true",
                       help="list all possible hash algorithms including salted passwords")
    group.add_argument("-m", "--mode",
                       action="store_true",
                       help="show corresponding Hashcat mode in output")
    group.add_argument("-j", "--john",
                       action="store_true",
                       help="show corresponding JohnTheRipper format in output")
    group.add_argument("-o", "--outfile",
                       metavar="FILE", type=str,
                       help="write output to file")
    group.add_argument("-h", "--help",
                       action="help",
                       help="show this help message and exit")
    group.add_argument("--version",
                       action="version",
                       version=__banner__)
    args = parser.parse_args()

    hashID = HashID()

    if not args.outfile:
        outfile = sys.stdout
    else:
        try:
            outfile = io.open(args.outfile, "w", encoding="utf-8")
        except EnvironmentError:
            parser.error("Could not open {0}".format(args.output))

    if not args.strings or args.strings[0] == "-":
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            outfile.write(u"Analyzing '{0}'\n".format(line.strip()))
            writeResult(hashID.identifyHash(line), outfile, args.mode, args.john, args.extended)
            sys.stdout.flush()
    else:
        for string in args.strings:
            if os.path.isfile(string):
                try:
                    with io.open(string, "r", encoding="utf-8") as infile:
                        outfile.write("--File '{0}'--\n".format(string))
                        for line in infile:
                            if line.strip():
                                outfile.write(u"Analyzing '{0}'\n".format(line.strip()))
                                writeResult(hashID.identifyHash(line), outfile, args.mode, args.john, args.extended)
                except (EnvironmentError, UnicodeDecodeError):
                    outfile.write("--File '{0}' - could not open--".format(string))
                else:
                    outfile.write("--End of file '{0}'--".format(string))
            else:
                outfile.write(u"Analyzing '{0}'\n".format(string.strip()))
                writeResult(hashID.identifyHash(string), outfile, args.mode, args.john, args.extended)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
