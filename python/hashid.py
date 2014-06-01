#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
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

import re, os, sys, argparse, mimetypes

#set regular expressions tuple
prototypes = (
    ("^[a-f0-9]{4}$", ("CRC-16","CRC-16-CCITT","FCS-16")),
    ("^[a-f0-9]{8}$", ("Adler-32","CRC-32","CRC-32B","FCS-32","GHash-32-3","GHash-32-5","FNV-132","Fletcher-32","Joaat","ELF-32","XOR-32")),
    ("^[a-f0-9]{6}$", ("CRC-24",)),
    ("^\+[a-z0-9\/\.]{12}$", ("Eggdrop IRC Bot",)),
    ("^[a-z0-9\/\.]{13}$", ("DES(Unix)","Traditional DES","DEScrypt")),
    ("^[a-f0-9]{16}$", ("MySQL323","DES(Oracle)","Half MD5","Oracle 7-10g","FNV-164","CRC-64")),
    ("^[a-z0-9\/\.]{16}$", ("Cisco-PIX(MD5)",)),
    ("^\([a-z0-9\+\/]{20}\)$", ("Lotus Notes/Domino 6",)),
    ("^_[a-z0-9\/\.]{19}$", ("BSDi Crypt",)),
    ("^[a-f0-9]{24}$", ("CRC-96(ZIP)",)),
    ("^[a-z0-9\/\.]{24}$", ("Crypt16",)),
    ("^[a-f0-9]{32}$", ("MD5","MD4","MD2","Double MD5","LM","RAdmin v2.x","RIPEMD-128","Haval-128","Tiger-128","Snefru-128","ZipMonster","Skein-256(128)","Skein-512(128)","Lotus Notes/Domino 5")),
    ("^(\$NT\$)?[a-f0-9]{32}$", ("NTLM",)),
    ("^[a-f0-9]{32}(:[^\\\/\:\*\?\"\<\>\|]{1,20})?$", ("Domain Cached Credentials","mscash")),
    ("^(\$DCC2\$10240#[^\\\/\:\*\?\"\<\>\|]{1,20}#)?[a-f0-9]{32}$", ("Domain Cached Credentials 2","mscash2")),
    ("^{SHA}[a-z0-9\+\/=]{28}$", ("SHA-1(Base64)","Netscape LDAP SHA","nsldap")),
    ("^\$1\$[a-z0-9\/\.]{0,8}\$[a-z0-9\/\.]{22}$", ("MD5 Crypt","Cisco-IOS(MD5)","FreeBSD MD5")),
    ("^0x[a-f0-9]{32}$", ("Lineage II C4",)),
    ("^\$H\$[a-z0-9\/\.]{31}$", ("phpBB v3.x","Wordpress v2.6.0/2.6.1","PHPass' Portable Hash")),
    ("^\$P\$[a-z0-9\/\.]{31}$", ("Wordpress ≥ v2.6.2","Joomla ≥ v2.5.18","PHPass' Portable Hash")),
    ("^[a-f0-9]{32}:[a-z0-9]{2}$", ("osCommerce","xt:Commerce")),
    ("^\$apr1\$[a-z0-9\/\.]{0,8}\$[a-z0-9\/\.]{22}$", ("MD5(APR)","Apache MD5","md5apr1")),
    ("^{smd5}[a-z0-9\.\$]{31}$", ("AIX(smd5)",)),
    ("^[a-f0-9]{32}:[a-f0-9]{32}$", ("WebEdition CMS",)),
    ("^[a-f0-9]{32}:.{5}$", ("IP.Board v2+",)),
    ("^[a-f0-9]{32}:.{8}$", ("MyBB ≥ v1.2+",)),
    ("^[a-z0-9]{34}$", ("CryptoCurrency(Adress)",)),
    ("^[a-f0-9]{40}$", ("SHA-1","Double SHA-1","MaNGOS CMS","MaNGOS CMS v2","LinkedIn","RIPEMD-160","Haval-160","Tiger-160","HAS-160","Skein-256(160)","Skein-512(160)")),
    ("^\*[a-f0-9]{40}$", ("MySQL5.x","MySQL4.1")),
    ("^[a-z0-9]{43}$", ("Cisco-IOS(SHA-256)",)),
    ("^{SSHA}[a-z0-9\+\/=]{40}$", ("SSHA-1(Base64)","Netscape LDAP SSHA","nsldaps")),
    ("^[a-z0-9]{47}$", ("Fortigate(FortiOS)",)),
    ("^[a-f0-9]{48}$", ("Haval-192","Tiger-192","SHA-1(Oracle)","OSX v10.4","OSX v10.5","OSX v10.6")),
    ("^[a-f0-9]{51}$", ("Palshop CMS",)),
    ("^[a-z0-9]{51}$", ("CryptoCurrency(PrivateKey)",)),
    ("^{ssha1}[a-z0-9\.\$]{47}$", ("AIX(ssha1)",)),
    ("^0x0100[a-f0-9]{48}$", ("MSSQL(2005)","MSSQL(2008)")),
    ("^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/\.]{0,16}(\$|\$\$)[a-z0-9\/\.]{22}$", ("Sun MD5 Crypt",)),
    ("^[a-f0-9]{56}$", ("SHA-224","Haval-224","SHA3-224","Skein-256(224)","Skein-512(224)")),
    ("^(\$2[axy]|\$2)\$[0-9]{0,2}?\$[a-z0-9\/\.]{53}$", ("Blowfish(OpenBSD)","Woltlab Burning Board 4.x","bcrypt")),
    ("^[a-f0-9]{40}:[a-f0-9]{16}$", ("Samsung Android Password/PIN",)),
    ("^S:[a-f0-9]{60}$", ("Oracle 11g",)),
    ("^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/\.]{22}\$[a-z0-9\/\.]{31}$", ("BCrypt(SHA-256)",)),
    ("^[a-f0-9]{32}:.{3}$", ("vBulletin < v3.8.5",)),
    ("^[a-f0-9]{32}:.{30}$", ("vBulletin ≥ v3.8.5",)),
    ("^[a-f0-9]{64}$", ("SHA-256","RIPEMD-256","Haval-256","Snefru-256","GOST R 34.11-94","SHA3-256","Skein-256","Skein-512(256)","Ventrilo")),
    ("^[a-f0-9]{32}:[a-z0-9]{32}$", ("Joomla < v2.5.18",)),
    ("^[a-f-0-9]{32}:[a-f-0-9]{32}$", ("SAM(LM_Hash:NT_Hash)",)),
    ("^[a-f0-9]{32}:[0-9]{32}:[0-9]{2}$", ("MD5(Chap)","iSCSI CHAP Authentication")),
    ("^\$episerver\$\*0\*[a-z0-9=\*\+]{52}$", ("EPiServer 6.x < v4",)),
    ("^{ssha256}[a-z0-9\.\$]{63}$", ("AIX(ssha256)",)),
    ("^[a-f0-9]{80}$", ("RIPEMD-320",)),
    ("^\$episerver\$\*1\*[a-z0-9=\*\+]{68}$", ("EPiServer 6.x ≥ v4",)),
    ("^0x0100[a-f0-9]{88}$", ("MSSQL(2000)",)),
    ("^[a-f0-9]{96}$", ("SHA-384","SHA3-384","Skein-512(384)","Skein-1024(384)")),
    ("^{SSHA512}[a-z0-9\+\/]{96}={0,2}$", ("SSHA-512(Base64)","LDAP(SSHA-512)")),
    ("^{ssha512}[0-9]{2}\$[a-z0-9\.\/]{16,48}\$[a-z0-9\.\/]{86}$", ("AIX(ssha512)",)),
    ("^[a-f0-9]{128}$", ("SHA-512","Whirlpool","Salsa10","Salsa20","SHA3-512","Skein-512","Skein-1024(512)")),
    ("^[a-f0-9]{136}$", ("OSX v10.7",)),
    ("^0x0200[a-f0-9]{136}$", ("MSSQL(2012)","MSSQL(2014)")),
    ("^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$", ("OSX v10.8","OSX v10.9")),
    ("^[a-f0-9]{256}$", ("Skein-1024",)),
    ("^grub\.pbkdf2\.sha512\.[0-9]+\.[a-f0-9]+\.[a-f0-9]+$", ("GRUB 2",)),
    ("^sha1\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{40}$", ("Django CMS(SHA-1)",)),
    ("^[a-f0-9]{49}$", ("Citrix Netscaler",)),
    ("^\$S\$[a-z0-9\/\.]{52}$", ("Drupal ≥ v7.x",)),
    ("^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/\.]{0,16}\$[a-z0-9\/\.]{43}$", ("SHA-256 Crypt",)),
    ("^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$", ("Sybase ASE",)),
    ("^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/\.]{0,16}\$[a-z0-9\/\.]{86}$", ("SHA-512 Crypt",)),
    ("^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$", ("Minecraft(AuthMe Reloaded)",)),
    ("^sha256\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{64}$", ("Django CMS(SHA-256)",)),
    ("^sha384\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{96}$", ("Django CMS(SHA-384)",)),
    ("^crypt1:[a-z0-9\+\=]{12}:[a-z0-9\+\=]{12}$", ("Clavister Secure Gateway",)),
    ("^[a-f0-9]{112}$", ("Cisco VPN Client(PCF-File)",)),
    ("^[a-f0-9]{1329}$", ("Microsoft MSTSC(RDP-File)",)),
    ("^[^\\\/:\*\?\"\<\>\|]{1,20}::[^\\\/:\*\?\"\<\>\|]{1,20}:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$", ("NetNTLMv1-VANILLA / NetNTLMv1+ESS",)),
    ("^[^\\\/:\*\?\"\<\>\|]{1,20}::[^\\\/:\*\?\"\<\>\|]{1,20}:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$", ("NetNTLMv2",)),
    ("^\$krb5pa\$23\$user\$realm\$salt\$[a-f0-9]{104}$", ("Kerberos 5 AS-REQ Pre-Auth",)),
    ("^\$scram\$[0-9]+\$[a-z0-9\/\.]{16}\$sha-1=[a-z0-9\/\.]{27},sha-256=[a-z0-9\/\.]{43},sha-512=[a-z0-9\/\.]{86}$", ("SCRAM Hash",)),
    ("^[a-f0-9]{40}:[a-f0-9]{0,32}$", ("Redmine Project Management Web App",)),
    ("^([0-9]{12})?\$[a-f0-9]{16}$", ("SAP CODVN B (BCODE)",)),
    ("^([0-9]{12})?\$[a-f0-9]{40}$", ("SAP CODVN F/G (PASSCODE)",)),
    ("^(.+\$)?[a-z0-9\/\.]{30}(:.+)?$", ("Juniper Netscreen/SSG(ScreenOS)",)),
    ("^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$", ("EPi",)),
    ("^[a-f0-9]{40}:[^*]{1,25}$", ("SMF ≥ v1.1",)),
    ("^[a-f0-9]{40}(:[a-f0-9]{40})?$", ("Woltlab Burning Board 3.x",)),
    ("^[a-f0-9]{130}(:[a-f0-9]{40})?$", ("IPMI2 RAKP HMAC-SHA1",)),
    ("^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$", ("Lastpass",)),
    ("^[a-z0-9\/\.]{16}(:.{1,})?$", ("Cisco-ASA(MD5)",)),
    ("^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$", ("VNC",)),
    ("^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$", ("DNSSEC(NSEC3)",)),
    ("^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$", ("RACF",)),
    ("^\$3\$\$[a-f0-9]{32}$", ("NTHash(FreeBSD Variant)",)),
    ("^\$sha1\$[0-9]+\$[a-z0-9\/\.]{0,64}\$[a-z0-9\/\.]{28}$", ("SHA-1 Crypt",)),
    ("^[a-f0-9]{70}$", ("hMailServer",)),
    ("^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$", ("MediaWiki",)),
    ("^[a-f0-9]{140}$", ("xAuth",)),
    ("^\$pbkdf2-sha(1|256|512)\$[0-9]+\$[a-z0-9\/\.]{22}\$([a-z0-9\/\.]{27}|[a-z0-9\/\.]{43}|[a-z0-9\/\.]{86})$", ("PBKDF2(Generic)",)),
    ("^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/\+=-]{28}$", ("PBKDF2(Cryptacular)",)),
    ("^\$p5k2\$[0-9]+\$[a-z0-9\/\.]+\$[a-z0-9\/\.]{32}$", ("PBKDF2(Dwayne Litzenberger)",)),
    ("^{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/\+=]+$", ("Fairly Secure Hashed Password",)),
    ("^\$PHPS\$.+\$[a-f0-9]{32}$", ("PHPS",)),
    ("^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$", ("1Password(Agile Keychain)",)),
    ("^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$", ("1Password(Cloud Keychain)",)),
    ("^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$", ("IKE-PSK MD5",)),
    ("^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$", ("IKE-PSK SHA1",))
)

#set hashcat mode dictionary
hashcatModes = {
    "MD5":"0", "Joomla < v2.5.18":"11", "osCommerce":"21", "xt:Commerce":"21", "Juniper Netscreen/SSG(ScreenOS)":"22", "SHA-1":"100", "SHA-1(Base64)":"101",
    "Netscape LDAP SHA":"101", "nsldap":"101", "SSHA-1(Base64)":"111", "Netscape LDAP SSHA":"111", "nsldaps":"111", "Oracle 11g":"112", "SMF ≥ v1.1":"121",
    "OSX v10.4":"122", "OSX v10.5":"122", "OSX v10.6":"122", "EPi":"123", "MSSQL(2000)":"131", "MSSQL(2005)":"132", "MSSQL(2008)":"132", "EPiServer 6.x < v4":"141",
    "LinkedIn":"190", "MySQL323":"200", "MySQL5.x":"300", "MySQL4.1":"300", "phpBB v3.x":"400", "Wordpress v2.6.0/2.6.1":"400", "PHPass' Portable Hash":"400",
    "Wordpress ≥ v2.6.2":"400", "Joomla ≥ v2.5.18":"400", "MD5 Crypt":"500", "Cisco-IOS(MD5)":"500", "FreeBSD MD5":"500", "Django CMS(SHA-1)":"800", "MD4":"900",
    "NTLM":"1000", "Domain Cached Credentials":"1100", "mscash":"1100", "SHA-256":"1400", "hMailServer":"1421", "EPiServer 6.x ≥ v4":"1441", "DES(Unix)":"1500",
    "Traditional DES":"1500", "DEScrypt":"1500", "MD5(APR)":"1600", "Apache MD5":"1600", "md5apr1":"1600", "SHA-512":"1700", "SSHA-512(Base64)":"1711",
    "LDAP(SSHA-512)":"1711", "OSX v10.7":"1722", "MSSQL(2012)":"1731", "MSSQL(2014)":"1731", "SHA-512 Crypt":"1800", "Domain Cached Credentials 2":"2100",
    "mscash2":"2100", "Cisco-PIX(MD5)":"2400", "Cisco-ASA(MD5)":"2410", "Double MD5":"2600", "vBulletin < v3.8.5":"2611", "PHPS":"2612", "vBulletin ≥ v3.8.5":"2711",
    "IP.Board v2+":"2811", "MyBB ≥ v1.2+":"2811", "LM":"3000", "DES(Oracle)":"3100", "Oracle 7-10g":"3100", "Blowfish(OpenBSD)":"3200", "bcrypt":"3200",
    "Sun MD5 Crypt":"3300", "MediaWiki":"3711", "WebEdition CMS":"3721", "Double SHA-1":"4500", "MD5(Chap)":"4800", "iSCSI CHAP Authentication":"4800", "SHA3-256":"5000",
    "Half MD5":"5100", "IKE-PSK MD5":"5300", "IKE-PSK SHA1":"5400", "NetNTLMv1-VANILLA / NetNTLMv1+ESS":"5500", "NetNTLMv2":"5600", "Cisco-IOS(SHA-256)":"5700",
    "Samsung Android Password/PIN":"5800", "RIPEMD-160":"6000", "Whirlpool":"6100", "AIX(smd5)":"6300", "AIX(ssha256)":"6400", "AIX(ssha512)":"6500",
    "1Password(Agile Keychain)":"6600", "AIX(ssha1)":"6700", "Lastpass":"6800", "GOST R 34.11-94":"6900", "Fortigate(FortiOS)":"7000", "OSX v10.8":"7100", "OSX v10.9":"7100",
    "GRUB 2":"7200", "IPMI2 RAKP HMAC-SHA1":"7300", "SHA-256 Crypt":"7400", "Kerberos 5 AS-REQ Pre-Auth":"7500", "Redmine Project Management Web App":"7600",
    "SAP CODVN B (BCODE)":"7700", "SAP CODVN F/G (PASSCODE)":"7800", "Drupal ≥ v7.x":"7900", "Sybase ASE":"8000", "Citrix Netscaler":"8100", "1Password(Cloud Keychain)":"8200",
    "DNSSEC(NSEC3)":"8300", "Woltlab Burning Board 3.x":"8400", "RACF":"8500", "Lotus Notes/Domino 5":"8600", "Lotus Notes/Domino 6":"8700"
}


def identifyHash(phash):
    """return algorithm and hashcat mode"""
    phash = phash.strip()
    for hashtype in prototypes:
        if (re.match(hashtype[0], phash, re.IGNORECASE)):
            for match in hashtype[1]:
                if match in hashcatModes:
                    yield (match, hashcatModes[match])
                else:
                    yield (match, False)


def writeResult(candidate, identify, outfile=sys.stdout, hashcatMode=False):
    """create human readable output"""
    outfile.write("Analyzing '" + candidate + "'\n")
    count = 0
    for result in identify:
        if hashcatMode and result[1]:
            outfile.write("[+] " + result[0] + " [Hashcat Mode: " + result[1] + "]\n")
        else:
            outfile.write("[+] " + result[0] + "\n")
        count += 1
    if count == 0:
        outfile.write("[+] Unknown hash\n")
    return (count > 0)


def main():
    usage = "%(prog)s INPUT [-m] [--help] [--version]"
    banner = "hashID v%s (%s)" % (__version__, __github__)
    description = "Identify the different types of hashes used to encrypt data"

    parser = argparse.ArgumentParser(usage=usage, description=description, epilog=__license__)
    parser.add_argument("strings", metavar="input", type=str, nargs="+", help="string or filename to be analyzed")
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
                        print ("--File '%s'--" % string)
                        for line in infile:
                            writeResult(line.strip(), identifyHash(line.strip()), sys.stdout, args.mode)
                    infile.close()
                except:
                    print ("--File '%s' - could not open--" % string)
                else:
                    print ("--End of file '%s'--" % string)
            else:
                writeResult(string, identifyHash(string), sys.stdout, args.mode)


if __name__ == "__main__":
    main()