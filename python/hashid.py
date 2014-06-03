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
__version__ = "2.7.0"
__github__  = "https://github.com/psypanda/hashID"
__license__ = "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>"

import re
import os
import sys
import argparse
from collections import namedtuple

Prototype = namedtuple('Prototype', ['regex', 'modes'])
HashMode = namedtuple('HashMode', ['name', 'hashcat'])

prototypes = [
    Prototype(
        regex='^[a-f0-9]{4}$',
        modes=[
            HashMode(name='CRC-16', hashcat=None),
            HashMode(name='CRC-16-CCITT', hashcat=None),
            HashMode(name='FCS-16', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{8}$',
        modes=[
            HashMode(name='Adler-32', hashcat=None),
            HashMode(name='CRC-32', hashcat=None),
            HashMode(name='CRC-32B', hashcat=None),
            HashMode(name='FCS-32', hashcat=None),
            HashMode(name='GHash-32-3', hashcat=None),
            HashMode(name='GHash-32-5', hashcat=None),
            HashMode(name='FNV-132', hashcat=None),
            HashMode(name='Fletcher-32', hashcat=None),
            HashMode(name='Joaat', hashcat=None),
            HashMode(name='ELF-32', hashcat=None),
            HashMode(name='XOR-32', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{6}$',
        modes=[
            HashMode(name='CRC-24', hashcat=None)]),
    Prototype(
        regex='^\\+[a-z0-9\\/\\.]{12}$',
        modes=[
            HashMode(name='Eggdrop IRC Bot', hashcat=None)]),
    Prototype(
        regex='^[a-z0-9\\/\\.]{13}$',
        modes=[
            HashMode(name='DES(Unix)', hashcat=1500),
            HashMode(name='Traditional DES', hashcat=1500),
            HashMode(name='DEScrypt', hashcat=1500)]),
    Prototype(
        regex='^[a-f0-9]{16}$',
        modes=[
            HashMode(name='MySQL323', hashcat=200),
            HashMode(name='DES(Oracle)', hashcat=3100),
            HashMode(name='Half MD5', hashcat=5100),
            HashMode(name='Oracle 7-10g', hashcat=3100),
            HashMode(name='FNV-164', hashcat=None),
            HashMode(name='CRC-64', hashcat=None)]),
    Prototype(
        regex='^[a-z0-9\\/\\.]{16}$',
        modes=[
            HashMode(name='Cisco-PIX(MD5)', hashcat=2400)]),
    Prototype(
        regex='^\\([a-z0-9\\+\\/]{20}\\)$',
        modes=[
            HashMode(name='Lotus Notes/Domino 6', hashcat=8700)]),
    Prototype(
        regex='^_[a-z0-9\\/\\.]{19}$',
        modes=[
            HashMode(name='BSDi Crypt', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{24}$',
        modes=[
            HashMode(name='CRC-96(ZIP)', hashcat=None)]),
    Prototype(
        regex='^[a-z0-9\\/\\.]{24}$',
        modes=[
            HashMode(name='Crypt16', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{32}$',
        modes=[
            HashMode(name='MD5', hashcat=0),
            HashMode(name='MD4', hashcat=900),
            HashMode(name='MD2', hashcat=None),
            HashMode(name='Double MD5', hashcat=2600),
            HashMode(name='LM', hashcat=3000),
            HashMode(name='RAdmin v2.x', hashcat=None),
            HashMode(name='RIPEMD-128', hashcat=None),
            HashMode(name='Haval-128', hashcat=None),
            HashMode(name='Tiger-128', hashcat=None),
            HashMode(name='Snefru-128', hashcat=None),
            HashMode(name='ZipMonster', hashcat=None),
            HashMode(name='Skein-256(128)', hashcat=None),
            HashMode(name='Skein-512(128)', hashcat=None),
            HashMode(name='Lotus Notes/Domino 5', hashcat=8600)]),
    Prototype(
        regex='^(\\$NT\\$)?[a-f0-9]{32}$',
        modes=[
            HashMode(name='NTLM', hashcat=1000)]),
    Prototype(
        regex='^[a-f0-9]{32}(:[^\\\\/\\:\\*\\?"\\<\\>\\|]{1,20})?$',
        modes=[
            HashMode(name='Domain Cached Credentials', hashcat=1100),
            HashMode(name='mscash', hashcat=1100)]),
    Prototype(
        regex='^(\\$DCC2\\$10240#[^\\\\/\\:\\*\\?"\\<\\>\\|]{1,20}#)?[a-f0-9]{32}$',
        modes=[
            HashMode(name='Domain Cached Credentials 2', hashcat=2100),
            HashMode(name='mscash2', hashcat=2100)]),
    Prototype(
        regex='^{SHA}[a-z0-9\\+\\/=]{28}$',
        modes=[
            HashMode(name='SHA-1(Base64)', hashcat=101),
            HashMode(name='Netscape LDAP SHA', hashcat=101),
            HashMode(name='nsldap', hashcat=101)]),
    Prototype(
        regex='^\\$1\\$[a-z0-9\\/\\.]{0,8}\\$[a-z0-9\\/\\.]{22}$',
        modes=[
            HashMode(name='MD5 Crypt', hashcat=500),
            HashMode(name='Cisco-IOS(MD5)', hashcat=500),
            HashMode(name='FreeBSD MD5', hashcat=500)]),
    Prototype(
        regex='^0x[a-f0-9]{32}$',
        modes=[
            HashMode(name='Lineage II C4', hashcat=None)]),
    Prototype(
        regex='^\\$H\\$[a-z0-9\\/\\.]{31}$',
        modes=[
            HashMode(name='phpBB v3.x', hashcat=400),
            HashMode(name='Wordpress v2.6.0/2.6.1', hashcat=400),
            HashMode(name="PHPass' Portable Hash", hashcat=400)]),
    Prototype(
        regex='^\\$P\\$[a-z0-9\\/\\.]{31}$',
        modes=[
            HashMode(name='Wordpress \xe2\x89\xa5 v2.6.2', hashcat=400),
            HashMode(name='Joomla \xe2\x89\xa5 v2.5.18', hashcat=400),
            HashMode(name="PHPass' Portable Hash", hashcat=400)]),
    Prototype(
        regex='^[a-f0-9]{32}:[a-z0-9]{2}$',
        modes=[
            HashMode(name='osCommerce', hashcat=21),
            HashMode(name='xt:Commerce', hashcat=21)]),
    Prototype(
        regex='^\\$apr1\\$[a-z0-9\\/\\.]{0,8}\\$[a-z0-9\\/\\.]{22}$',
        modes=[
            HashMode(name='MD5(APR)', hashcat=1600),
            HashMode(name='Apache MD5', hashcat=1600),
            HashMode(name='md5apr1', hashcat=1600)]),
    Prototype(
        regex='^{smd5}[a-z0-9\\.\\$]{31}$',
        modes=[
            HashMode(name='AIX(smd5)', hashcat=6300)]),
    Prototype(
        regex='^[a-f0-9]{32}:[a-f0-9]{32}$',
        modes=[
            HashMode(name='WebEdition CMS', hashcat=3721)]),
    Prototype(
        regex='^[a-f0-9]{32}:.{5}$',
        modes=[
            HashMode(name='IP.Board v2+', hashcat=2811)]),
    Prototype(
        regex='^[a-f0-9]{32}:.{8}$',
        modes=[
            HashMode(name='MyBB \xe2\x89\xa5 v1.2+', hashcat=2811)]),
    Prototype(
        regex='^[a-z0-9]{34}$',
        modes=[
            HashMode(name='CryptoCurrency(Adress)', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{40}$',
        modes=[
            HashMode(name='SHA-1', hashcat=100),
            HashMode(name='Double SHA-1', hashcat=4500),
            HashMode(name='MaNGOS CMS', hashcat=None),
            HashMode(name='MaNGOS CMS v2', hashcat=None),
            HashMode(name='LinkedIn', hashcat=190),
            HashMode(name='RIPEMD-160', hashcat=6000),
            HashMode(name='Haval-160', hashcat=None),
            HashMode(name='Tiger-160', hashcat=None),
            HashMode(name='HAS-160', hashcat=None),
            HashMode(name='Skein-256(160)', hashcat=None),
            HashMode(name='Skein-512(160)', hashcat=None)]),
    Prototype(
        regex='^\\*[a-f0-9]{40}$',
        modes=[
            HashMode(name='MySQL5.x', hashcat=300),
            HashMode(name='MySQL4.1', hashcat=300)]),
    Prototype(
        regex='^[a-z0-9]{43}$',
        modes=[
            HashMode(name='Cisco-IOS(SHA-256)', hashcat=5700)]),
    Prototype(
        regex='^{SSHA}[a-z0-9\\+\\/=]{40}$',
        modes=[
            HashMode(name='SSHA-1(Base64)', hashcat=111),
            HashMode(name='Netscape LDAP SSHA', hashcat=111),
            HashMode(name='nsldaps', hashcat=111)]),
    Prototype(
        regex='^[a-z0-9]{47}$',
        modes=[
            HashMode(name='Fortigate(FortiOS)', hashcat=7000)]),
    Prototype(
        regex='^[a-f0-9]{48}$',
        modes=[
            HashMode(name='Haval-192', hashcat=None),
            HashMode(name='Tiger-192', hashcat=None),
            HashMode(name='SHA-1(Oracle)', hashcat=None),
            HashMode(name='OSX v10.4', hashcat=122),
            HashMode(name='OSX v10.5', hashcat=122),
            HashMode(name='OSX v10.6', hashcat=122)]),
    Prototype(
        regex='^[a-f0-9]{51}$',
        modes=[
            HashMode(name='Palshop CMS', hashcat=None)]),
    Prototype(
        regex='^[a-z0-9]{51}$',
        modes=[
            HashMode(name='CryptoCurrency(PrivateKey)', hashcat=None)]),
    Prototype(
        regex='^{ssha1}[a-z0-9\\.\\$]{47}$',
        modes=[
            HashMode(name='AIX(ssha1)', hashcat=6700)]),
    Prototype(
        regex='^0x0100[a-f0-9]{48}$',
        modes=[
            HashMode(name='MSSQL(2005)', hashcat=132),
            HashMode(name='MSSQL(2008)', hashcat=132)]),
    Prototype(
        regex='^(\\$md5,rounds=[0-9]+\\$|\\$md5\\$rounds=[0-9]+\\$|\\$md5\\$)[a-z0-9\\/\\.]{0,16}(\\$|\\$\\$)[a-z0-9\\/\\.]{22}$',
        modes=[
            HashMode(name='Sun MD5 Crypt', hashcat=3300)]),
    Prototype(
        regex='^[a-f0-9]{56}$',
        modes=[
            HashMode(name='SHA-224', hashcat=None),
            HashMode(name='Haval-224', hashcat=None),
            HashMode(name='SHA3-224', hashcat=None),
            HashMode(name='Skein-256(224)', hashcat=None),
            HashMode(name='Skein-512(224)', hashcat=None)]),
    Prototype(
        regex='^(\\$2[axy]|\\$2)\\$[0-9]{0,2}?\\$[a-z0-9\\/\\.]{53}$',
        modes=[
            HashMode(name='Blowfish(OpenBSD)', hashcat=3200),
            HashMode(name='Woltlab Burning Board 4.x', hashcat=None),
            HashMode(name='bcrypt', hashcat=3200)]),
    Prototype(
        regex='^[a-f0-9]{40}:[a-f0-9]{16}$',
        modes=[
            HashMode(name='Samsung Android Password/PIN', hashcat=5800)]),
    Prototype(
        regex='^S:[a-f0-9]{60}$',
        modes=[
            HashMode(name='Oracle 11g', hashcat=112)]),
    Prototype(
        regex='^\\$bcrypt-sha256\\$(2[axy]|2)\\,[0-9]+\\$[a-z0-9\\/\\.]{22}\\$[a-z0-9\\/\\.]{31}$',
        modes=[
            HashMode(name='BCrypt(SHA-256)', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{32}:.{3}$',
        modes=[
            HashMode(name='vBulletin < v3.8.5', hashcat=2611)]),
    Prototype(
        regex='^[a-f0-9]{32}:.{30}$',
        modes=[
            HashMode(name='vBulletin \xe2\x89\xa5 v3.8.5', hashcat=2711)]),
    Prototype(
        regex='^[a-f0-9]{64}$',
        modes=[
            HashMode(name='SHA-256', hashcat=1400),
            HashMode(name='RIPEMD-256', hashcat=None),
            HashMode(name='Haval-256', hashcat=None),
            HashMode(name='Snefru-256', hashcat=None),
            HashMode(name='GOST R 34.11-94', hashcat=6900),
            HashMode(name='SHA3-256', hashcat=5000),
            HashMode(name='Skein-256', hashcat=None),
            HashMode(name='Skein-512(256)', hashcat=None),
            HashMode(name='Ventrilo', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{32}:[a-z0-9]{32}$',
        modes=[
            HashMode(name='Joomla < v2.5.18', hashcat=11)]),
    Prototype(
        regex='^[a-f-0-9]{32}:[a-f-0-9]{32}$',
        modes=[
            HashMode(name='SAM(LM_Hash:NT_Hash)', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{32}:[0-9]{32}:[0-9]{2}$',
        modes=[
            HashMode(name='MD5(Chap)', hashcat=4800),
            HashMode(name='iSCSI CHAP Authentication', hashcat=4800)]),
    Prototype(
        regex='^\\$episerver\\$\\*0\\*[a-z0-9=\\*\\+]{52}$',
        modes=[
            HashMode(name='EPiServer 6.x < v4', hashcat=141)]),
    Prototype(
        regex='^{ssha256}[a-z0-9\\.\\$]{63}$',
        modes=[
            HashMode(name='AIX(ssha256)', hashcat=6400)]),
    Prototype(
        regex='^[a-f0-9]{80}$',
        modes=[
            HashMode(name='RIPEMD-320', hashcat=None)]),
    Prototype(
        regex='^\\$episerver\\$\\*1\\*[a-z0-9=\\*\\+]{68}$',
        modes=[
            HashMode(name='EPiServer 6.x \xe2\x89\xa5 v4', hashcat=1441)]),
    Prototype(
        regex='^0x0100[a-f0-9]{88}$',
        modes=[
            HashMode(name='MSSQL(2000)', hashcat=131)]),
    Prototype(
        regex='^[a-f0-9]{96}$',
        modes=[
            HashMode(name='SHA-384', hashcat=None),
            HashMode(name='SHA3-384', hashcat=None),
            HashMode(name='Skein-512(384)', hashcat=None),
            HashMode(name='Skein-1024(384)', hashcat=None)]),
    Prototype(
        regex='^{SSHA512}[a-z0-9\\+\\/]{96}={0,2}$',
        modes=[
            HashMode(name='SSHA-512(Base64)', hashcat=1711),
            HashMode(name='LDAP(SSHA-512)', hashcat=1711)]),
    Prototype(
        regex='^{ssha512}[0-9]{2}\\$[a-z0-9\\.\\/]{16,48}\\$[a-z0-9\\.\\/]{86}$',
        modes=[
            HashMode(name='AIX(ssha512)', hashcat=6500)]),
    Prototype(
        regex='^[a-f0-9]{128}$',
        modes=[
            HashMode(name='SHA-512', hashcat=1700),
            HashMode(name='Whirlpool', hashcat=6100),
            HashMode(name='Salsa10', hashcat=None),
            HashMode(name='Salsa20', hashcat=None),
            HashMode(name='SHA3-512', hashcat=None),
            HashMode(name='Skein-512', hashcat=None),
            HashMode(name='Skein-1024(512)', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{136}$',
        modes=[
            HashMode(name='OSX v10.7', hashcat=1722)]),
    Prototype(
        regex='^0x0200[a-f0-9]{136}$',
        modes=[
            HashMode(name='MSSQL(2012)', hashcat=1731),
            HashMode(name='MSSQL(2014)', hashcat=1731)]),
    Prototype(
        regex='^\\$ml\\$[0-9]+\\$[a-f0-9]{64}\\$[a-f0-9]{128}$',
        modes=[
            HashMode(name='OSX v10.8', hashcat=7100),
            HashMode(name='OSX v10.9', hashcat=7100)]),
    Prototype(
        regex='^[a-f0-9]{256}$',
        modes=[
            HashMode(name='Skein-1024', hashcat=None)]),
    Prototype(
        regex='^grub\\.pbkdf2\\.sha512\\.[0-9]+\\.[a-f0-9]+\\.[a-f0-9]+$',
        modes=[
            HashMode(name='GRUB 2', hashcat=7200)]),
    Prototype(
        regex='^sha1\\$[a-z0-9\\/\\.]{1,12}\\$[a-f0-9]{40}$',
        modes=[
            HashMode(name='Django CMS(SHA-1)', hashcat=800)]),
    Prototype(
        regex='^[a-f0-9]{49}$',
        modes=[
            HashMode(name='Citrix Netscaler', hashcat=8100)]),
    Prototype(
        regex='^\\$S\\$[a-z0-9\\/\\.]{52}$',
        modes=[
            HashMode(name='Drupal \xe2\x89\xa5 v7.x', hashcat=7900)]),
    Prototype(
        regex='^\\$5\\$(rounds=[0-9]+\\$)?[a-z0-9\\/\\.]{0,16}\\$[a-z0-9\\/\\.]{43}$',
        modes=[
            HashMode(name='SHA-256 Crypt', hashcat=7400)]),
    Prototype(
        regex='^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$',
        modes=[
            HashMode(name='Sybase ASE', hashcat=8000)]),
    Prototype(
        regex='^\\$6\\$(rounds=[0-9]+\\$)?[a-z0-9\\/\\.]{0,16}\\$[a-z0-9\\/\\.]{86}$',
        modes=[
            HashMode(name='SHA-512 Crypt', hashcat=1800)]),
    Prototype(
        regex='^\\$sha\\$[a-z0-9]{1,16}\\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$',
        modes=[
            HashMode(name='Minecraft(AuthMe Reloaded)', hashcat=None)]),
    Prototype(
        regex='^sha256\\$[a-z0-9\\/\\.]{1,12}\\$[a-f0-9]{64}$',
        modes=[
            HashMode(name='Django CMS(SHA-256)', hashcat=None)]),
    Prototype(
        regex='^sha384\\$[a-z0-9\\/\\.]{1,12}\\$[a-f0-9]{96}$',
        modes=[
            HashMode(name='Django CMS(SHA-384)', hashcat=None)]),
    Prototype(
        regex='^crypt1:[a-z0-9\\+\\=]{12}:[a-z0-9\\+\\=]{12}$',
        modes=[
            HashMode(name='Clavister Secure Gateway', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{112}$',
        modes=[
            HashMode(name='Cisco VPN Client(PCF-File)', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{1329}$',
        modes=[
            HashMode(name='Microsoft MSTSC(RDP-File)', hashcat=None)]),
    Prototype(
        regex='^[^\\\\/:\\*\\?"\\<\\>\\|]{1,20}::[^\\\\/:\\*\\?"\\<\\>\\|]{1,20}:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$',
        modes=[
            HashMode(name='NetNTLMv1-VANILLA / NetNTLMv1+ESS', hashcat=5500)]),
    Prototype(
        regex='^[^\\\\/:\\*\\?"\\<\\>\\|]{1,20}::[^\\\\/:\\*\\?"\\<\\>\\|]{1,20}:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$',
        modes=[
            HashMode(name='NetNTLMv2', hashcat=5600)]),
    Prototype(
        regex='^\\$krb5pa\\$23\\$user\\$realm\\$salt\\$[a-f0-9]{104}$',
        modes=[
            HashMode(name='Kerberos 5 AS-REQ Pre-Auth', hashcat=7500)]),
    Prototype(
        regex='^\\$scram\\$[0-9]+\\$[a-z0-9\\/\\.]{16}\\$sha-1=[a-z0-9\\/\\.]{27},sha-256=[a-z0-9\\/\\.]{43},sha-512=[a-z0-9\\/\\.]{86}$',
        modes=[
            HashMode(name='SCRAM Hash', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{40}:[a-f0-9]{0,32}$',
        modes=[
            HashMode(name='Redmine Project Management Web App', hashcat=7600)]),
    Prototype(
        regex='^([0-9]{12})?\\$[a-f0-9]{16}$',
        modes=[
            HashMode(name='SAP CODVN B (BCODE)', hashcat=7700)]),
    Prototype(
        regex='^([0-9]{12})?\\$[a-f0-9]{40}$',
        modes=[
            HashMode(name='SAP CODVN F/G (PASSCODE)', hashcat=7800)]),
    Prototype(
        regex='^(.+\\$)?[a-z0-9\\/\\.]{30}(:.+)?$',
        modes=[
            HashMode(name='Juniper Netscreen/SSG(ScreenOS)', hashcat=22)]),
    Prototype(
        regex='^0x[a-f0-9]{60}\\s0x[a-f0-9]{40}$',
        modes=[
            HashMode(name='EPi', hashcat=123)]),
    Prototype(
        regex='^[a-f0-9]{40}:[^*]{1,25}$',
        modes=[
            HashMode(name='SMF \xe2\x89\xa5 v1.1', hashcat=121)]),
    Prototype(
        regex='^[a-f0-9]{40}(:[a-f0-9]{40})?$',
        modes=[
            HashMode(name='Woltlab Burning Board 3.x', hashcat=8400)]),
    Prototype(
        regex='^[a-f0-9]{130}(:[a-f0-9]{40})?$',
        modes=[
            HashMode(name='IPMI2 RAKP HMAC-SHA1', hashcat=7300)]),
    Prototype(
        regex='^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\\.[a-z0-9-.]+$',
        modes=[
            HashMode(name='Lastpass', hashcat=6800)]),
    Prototype(
        regex='^[a-z0-9\\/\\.]{16}(:.{1,})?$',
        modes=[
            HashMode(name='Cisco-ASA(MD5)', hashcat=2410)]),
    Prototype(
        regex='^\\$vnc\\$\\*[a-f0-9]{32}\\*[a-f0-9]{32}$',
        modes=[
            HashMode(name='VNC', hashcat=None)]),
    Prototype(
        regex='^[a-z0-9]{32}(:([a-z0-9-]+\\.)?[a-z0-9-.]+\\.[a-z]{2,7}:.+:[0-9]+)?$',
        modes=[
            HashMode(name='DNSSEC(NSEC3)', hashcat=8300)]),
    Prototype(
        regex='^(user-.+:)?\\$racf\\$\\*.+\\*[a-f0-9]{16}$',
        modes=[
            HashMode(name='RACF', hashcat=8500)]),
    Prototype(
        regex='^\\$3\\$\\$[a-f0-9]{32}$',
        modes=[
            HashMode(name='NTHash(FreeBSD Variant)', hashcat=None)]),
    Prototype(
        regex='^\\$sha1\\$[0-9]+\\$[a-z0-9\\/\\.]{0,64}\\$[a-z0-9\\/\\.]{28}$',
        modes=[
            HashMode(name='SHA-1 Crypt', hashcat=None)]),
    Prototype(
        regex='^[a-f0-9]{70}$',
        modes=[
            HashMode(name='hMailServer', hashcat=1421)]),
    Prototype(
        regex='^[:\\$][AB][:\\$]([a-f0-9]{1,8}[:\\$])?[a-f0-9]{32}$',
        modes=[
            HashMode(name='MediaWiki', hashcat=3711)]),
    Prototype(
        regex='^[a-f0-9]{140}$',
        modes=[
            HashMode(name='Minecraft(xAuth)', hashcat=None)]),
    Prototype(
        regex='^\\$pbkdf2-sha(1|256|512)\\$[0-9]+\\$[a-z0-9\\/\\.]{22}\\$([a-z0-9\\/\\.]{27}|[a-z0-9\\/\\.]{43}|[a-z0-9\\/\\.]{86})$',
        modes=[
            HashMode(name='PBKDF2(Generic)', hashcat=None)]),
    Prototype(
        regex='^\\$p5k2\\$[0-9]+\\$[a-z0-9\\/+=-]+\\$[a-z0-9\\/\\+=-]{28}$',
        modes=[
            HashMode(name='PBKDF2(Cryptacular)', hashcat=None)]),
    Prototype(
        regex='^\\$p5k2\\$[0-9]+\\$[a-z0-9\\/\\.]+\\$[a-z0-9\\/\\.]{32}$',
        modes=[
            HashMode(name='PBKDF2(Dwayne Litzenberger)', hashcat=None)]),
    Prototype(
        regex='^{FSHP[0123]\\|[0-9]+\\|[0-9]+}[a-z0-9\\/\\+=]+$',
        modes=[
            HashMode(name='Fairly Secure Hashed Password', hashcat=None)]),
    Prototype(
        regex='^\\$PHPS\\$.+\\$[a-f0-9]{32}$',
        modes=[
            HashMode(name='PHPS', hashcat=2612)]),
    Prototype(
        regex='^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$',
        modes=[
            HashMode(name='1Password(Agile Keychain)', hashcat=6600)]),
    Prototype(
        regex='^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$',
        modes=[
            HashMode(name='1Password(Cloud Keychain)', hashcat=8200)]),
    Prototype(
        regex='^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$',
        modes=[
            HashMode(name='IKE-PSK MD5', hashcat=5300)]),
    Prototype(
        regex='^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$',
        modes=[
            HashMode(name='IKE-PSK SHA1', hashcat=5400)])
]


def identifyHash(phash):
    """return algorithm and hashcat mode"""
    phash = phash.strip()
    for prototype in prototypes:
        if (re.match(prototype.regex, phash, re.IGNORECASE)):
            for mode in prototype.modes:
                yield mode


def writeResult(candidate, identified_modes, outfile=sys.stdout, hashcatMode=False):
    """create human readable output"""
    outfile.write("Analyzing '{}'\n".format(candidate))
    count = 0
    for mode in identified_modes:
        if hashcatMode and mode.hashcat is not None:
            outfile.write("[+] {} [Hashcat Mode: {}]\n".format(mode.name, mode.hashcat))
        else:
            outfile.write("[+] {}\n".format(mode.name))
        count += 1
    if count == 0:
        outfile.write("[+] Unknown hash\n")
    return (count > 0)


def main():
    usage = "{0} INPUT [-m] [--help] [--version]".format(__file__)
    banner = "hashID v{0} by {1} ({2})".format(__version__, __author__, __github__)
    description = "Identify the different types of hashes used to encrypt data"

    parser = argparse.ArgumentParser(usage=usage, description=description, epilog=__license__)
    parser.add_argument("strings", metavar="input", type=str, nargs="+", help="string or filename to analyze")
    parser.add_argument("-m", "--mode", action="store_true", help="include corresponding hashcat mode in output")
    parser.add_argument("--version", action="version", version=banner)
    args = parser.parse_args()

    if not args.strings:
        for line in sys.stdin:
            writeResult(line.strip(), identifyHash(line.strip()), sys.stdout, args.mode)
    else:
        for string in args.strings:
            if os.path.isfile(string):
                try:
                    with open(string, "r", encoding="utf-8") as infile:
                        print("--File '{0}'--".format(string))
                        for line in infile:
                            if line.strip():
                                writeResult(line.strip(), identifyHash(line.strip()), sys.stdout, args.mode)
                    infile.close()
                except:
                    print("--File '{0}' - could not open--".format(string))
                else:
                    print("--End of file '{0}'--".format(string))
            else:
                writeResult(string, identifyHash(string), sys.stdout, args.mode)


if __name__ == "__main__":
    main()
