#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name: hashID.py
# @author: c0re <https://psypanda.org/>                           
# @date: 2014/03/12
# @copyright: <https://www.gnu.org/licenses/gpl-3.0.html>

import re, os, sys, argparse

#set essential variables
version = "v2.3.6"
banner = "%(prog)s " + version + " by c0re <https://github.com/psypanda/hashID>"
usage = "%(prog)s (-i HASH | -f FILE) [-o OUTFILE] [-n] [--help] [--version]"
description = "Identify the different types of hashes"
epilog = "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>"

#configure argparse
parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=36), usage=usage, description=description, epilog=epilog)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-i", "--hash", type=str, help="identify a single hash")
group.add_argument("-f", "--file", type=argparse.FileType("r"), help="analyze a given file")
parser.add_argument("-o", "--output", type=str, default="hashid_output.txt", help="set output filename (default: %(default)s)")
#parser.add_argument("-n", "--notfound", action="store_true", default=False, help="set separate file containing all unknown hashes (default: hashid_notfound.txt)")
#parser.add_argument("-hc", "--hashcat", action="store_true", default=False, help="include hashcat mode in output")
parser.add_argument("--version", action="version", version=banner)
args = parser.parse_args()

#identify the input hash
def identifyHash(phash):
	#trim possible whitespace
	phash = phash.strip()
	#set regex and algorithms
	prototypes = \
	(
		("^[a-f0-9]{4}$", ("CRC-16","CRC-16-CCITT","FCS-16")),
		("^[a-f0-9]{8}$", ("Adler-32","CRC-32","CRC-32B","FCS-32","GHash-32-3","GHash-32-5","FNV-132","Fletcher-32","Joaat","ELF-32","XOR-32")),
		("^\+[a-z0-9\/\.]{12}$", ("Blowfish(Eggdrop)",)),
		("^[a-z0-9\/\.]{13}$", ("DES(Unix)","Traditional DES","DEScrypt")),
		("^[a-f0-9]{16}$", ("MySQL323","DES(Oracle)","Half MD5","Oracle 7-10g","FNV-164","CRC-64")),
		("^[a-z0-9\/\.]{16}$", ("Cisco-PIX(MD5)",)),
		("^\([a-z0-9\+\/]{20}\)$", ("Lotus Domino",)),
		("^_[a-z0-9\/\.]{19}$", ("BSDi Crypt",)),
		("^[a-f0-9]{24}$", ("CRC-96(ZIP)",)),
		("^[a-z0-9\/\.]{24}$", ("Crypt16",)),
		("^[a-f0-9]{32}$", ("MD5","MD4","MD2","NTLM","LM","RAdmin v2.x","RIPEMD-128","Haval-128","Tiger-128","Snefru-128","ZipMonster","DCC","DCC v2","Skein-256(128)","Skein-512(128)")),
		("^{SHA}[a-z0-9\/\+]{27}=$", ("SHA-1(Base64)","Netscape LDAP SHA","nsldap")),
		("^\$1\$[a-z0-9\/\.]{0,8}\$[a-z0-9\/\.]{22}$", ("MD5(Unix)","Cisco-IOS(MD5)","FreeBSD MD5","md5crypt")),
		("^0x[a-f0-9]{32}$", ("Lineage II C4",)), 
		("^\$H\$[a-z0-9\/\.]{31}$", ("phpBB v3.x","Wordpress v2.6.0/2.6.1","PHPass' Portable Hash")),
		("^\$P\$[a-z0-9\/\.]{31}$", ("Wordpress ≥ 2.6.2","PHPass' Portable Hash")),
		("^[a-f0-9]{32}:[a-z0-9]{2}$", ("osCommerce","xt:Commerce")),
		("^\$apr1\$[a-z0-9\/\.]{0,8}\$[a-z0-9\/\.]{22}$", ("MD5(APR)","Apache MD5")),
		("^{smd5}[a-z0-9\.\$]{31}$", ("AIX(smd5)",)),
		("^[a-f0-9]{32}:[a-f0-9]{32}$", ("WebEdition CMS",)),
		("^[a-f0-9]{32}:.{5}$", ("IP.Board v2+",)),
		("^[a-f0-9]{32}:.{8}$", ("MyBB ≥ v1.2+",)),
		("^[a-z0-9]{34}$", ("CryptoCurrency(Adress)",)),
		("^[a-f0-9]{40}$", ("SHA-1","MaNGOS CMS","MaNGOS CMS v2","LinkedIn","RIPEMD-160","Haval-160","Tiger-160","HAS-160","Skein-256(160)","Skein-512(160)")),
		("^\*[a-f0-9]{40}$", ("MySQL5.x","MySQL4.1")),
		("^[a-z0-9]{43}$", ("Cisco-IOS(SHA256)",)),
		("^{SSHA}([a-z0-9\+\/]{40}|[a-z0-9\+\/]{38}==)$", ("SSHA-1(Base64)","Netscape LDAP SSHA","nsldaps")),
		("^[a-z0-9]{47}$", ("Fortigate(FortiOS)",)),
		("^[a-f0-9]{48}$", ("Haval-192","Tiger-192","SHA-1(Oracle)","OSX v10.4","OSX v10.5","OSX v10.6")),
		("^[a-f0-9]{51}$", ("Palshop CMS",)),
		("^[a-z0-9]{51}$", ("CryptoCurrency(PrivateKey)",)),
		("^{ssha1}[a-z0-9\.\$]{47}$", ("AIX(ssha1)",)),
		("^0x0100[a-f0-9]{48}$", ("MSSQL(2005)","MSSQL(2008)")),
		("^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/\.]{0,16}(\$|\$\$)[a-z0-9\/\.]{22}$", ("MD5(Sun)",)),
		("^[a-f0-9]{56}$", ("SHA-224","Haval-224","SHA3-224","Skein-256(224)","Skein-512(224)")),
		("^(\$2a|\$2y|\$2)\$[0-9]{0,2}?\$[a-z0-9\/\.]{53}$", ("Blowfish(OpenBSD)",)),
		("^[a-f0-9]{40}:[a-f0-9]{16}$", ("Samsung Android Password/PIN",)),
		("^S:[a-f0-9]{60}$", ("Oracle 11g",)),
		("^\$bcrypt-sha256\$.{5}\$[a-z0-9\/\.]{22}\$[a-z0-9\/\.]{31}$", ("BCrypt(SHA256)",)),
		("^[a-f0-9]{32}:[0-9]{3}$", ("vBulletin < v3.8.5",)),
		("^[a-f0-9]{32}:[a-z0-9]{30}$", ("vBulletin ≥ v3.8.5",)),
		("^[a-f0-9]{64}$", ("SHA-256","RIPEMD-256","Haval-256","Snefru-256","GOST R 34.11-94","SHA3-256","Skein-256","Skein-512(256)","Ventrilo")),
		("^[a-f0-9]{32}:[a-z0-9]{32}$", ("Joomla",)),
		("^[a-f-0-9]{32}:[a-f-0-9]{32}$", ("SAM(LM_Hash:NT_Hash)",)),
		("^[a-f0-9]{32}:[0-9]{32}:[0-9]{2}$", ("MD5(Chap)","iSCSI CHAP Authentication")),
		("^\$episerver\$\*0\*[a-z0-9=\*+]{52}$", ("EPiServer 6.x < v4",)),
		("^{ssha256}[a-z0-9\.\$]{63}$", ("AIX(ssha256)",)),
		("^[a-f0-9]{80}$", ("RIPEMD-320",)),
		("^\$episerver\$\*1\*[a-z0-9=\*+]{68}$", ("EPiServer 6.x ≥ v4",)),
		("^0x0100[a-f0-9]{88}$", ("MSSQL(2000)",)),
		("^[a-f0-9]{96}$", ("SHA-384","SHA3-384","Skein-512(384)","Skein-1024(384)")),
		("^{SSHA512}[a-z0-9\+\/]{96}={0,2}$", ("SSHA-512(Base64)","LDAP(SSHA512)")),
		("^{ssha512}[0-9]{2}\$[a-z0-9\.\/]{16,48}\$[a-z0-9\.\/]{86}$", ("AIX(ssha512)",)),
		("^[a-f0-9]{128}$", ("SHA-512","Whirlpool","Salsa10","Salsa20","SHA3-512","Skein-512","Skein-1024(512)")),
		("^[a-f0-9]{136}$", ("OSX v10.7",)),
		("^0x0200[a-f0-9]{136}$", ("MSSQL(2012)",)),
		("^\$ml\$.+$", ("OSX v10.8","OSX v10.9")),
		("^[a-f0-9]{256}$", ("Skein-1024",)),
		("^grub\.pbkdf2\.sha512\..+$", ("GRUB 2",)),
		("^sha1\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{40}$", ("Django CMS(SHA-1)",)),
		("^[a-f0-9]{49}$", ("Citrix Netscaler",)),
		("^\$S\$[a-z0-9\/\.]{52}$", ("Drupal7",)),
		("^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/\.]{0,16}\$[a-z0-9\/\.]{43}$", ("SHA-256(Unix)","sha256crypt")),
		("^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$", ("Sybase ASE",)),
		("^\$6\$.{0,22}\$[a-z0-9\/\.]{86}$", ("SHA-512(Unix)",)),
		("^\$sha\$[a-z0-9]{1,16}\$[a-f0-9]{64}$", ("Minecraft(AuthMe Reloaded)",)),
		("^sha256\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{64}$", ("Django CMS(SHA-256)",)),
		("^sha384\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{96}$", ("Django CMS(SHA-384)",)),
		("^crypt1:[a-z0-9\+\=]{12}:[a-z0-9\+\=]{12}$", ("Clavister Secure Gateway",)),
		("^[a-f0-9]{112}$", ("Cisco VPN Client(PCF-File)",)),
		("^[a-f0-9]{1329}$", ("Microsoft MSTSC(RDP-File)",)),
		("^[^\\\/:*?\"\<\>\|]{1,15}::[^\\\/:*?\"\<\>\|]{1,15}:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$", ("NetNTLMv1-VANILLA / NetNTLMv1+ESS",)),
		("^[^\\\/:*?\"\<\>\|]{1,15}::[^\\\/:*?\"\<\>\|]{1,15}:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$", ("NetNTLMv2",)),
		("^\$krb5pa\$.+$", ("Kerberos 5 AS-REQ Pre-Auth",)),
		("^\$scram\$[0-9]+\$[a-z0-9\/\.]{16}\$sha-1=[a-z0-9\/\.]{27},sha-256=[a-z0-9\/\.]{43},sha-512=[a-z0-9\/\.]{86}$", ("SCRAM Hash",)),
		("^[a-f0-9]{40}:[a-f0-9]{0,32}$", ("Redmine Project Management Web App",)),
		("^[0-9]{12}\$[a-f0-9]{40}$", ("SAP CODVN F/G (PASSCODE)",)),
		("^[0-9]{12}\$[a-f0-9]{16}$", ("SAP CODVN B (BCODE)",)),
		("^[a-z0-9\/\.]{30}(:.+)?$", ("Juniper Netscreen/SSG(ScreenOS)",)),
		("^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$", ("EPi",)),
		("^[a-f0-9]{40}:[^*]{1,25}$", ("SMF ≥ v1.1",)),
		("^[a-f0-9]{40}(:[a-f0-9]{40})?$", ("Burning Board 3.x",)),
		("^[a-f0-9]{130}(:[a-f0-9]{40})?$", ("IPMI2 RAKP HMAC-SHA1",)),
		("^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$", ("Lastpass",)),
		("^[a-z0-9\/\.]{16}(:[0-9]{2})?$", ("Cisco-ASA(MD5)",)),
		("^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$", ("VNC",)),
		("^[a-z0-9]{32}$", ("DNSSEC(NSEC3)",))
	)
	for hashtype in prototypes:
		#try to find matches
		if (re.match(hashtype[0], phash, re.IGNORECASE)):
			for h in hashtype[1]:
				yield h


#analyze a given file
def analyzeFile(infile, outfile):
	#define the counters
	hashesAnalyzed = 0
	hashesFound = 0
	#show input file path
	print ("Analyzing '" + os.path.abspath(infile.name) + "'")
	for line in infile:
		#skip empty lines
		if line.strip():
			#increment hash count
			hashesAnalyzed += 1
			#trim possible whitespace
			line = line.strip()
			#try to identify the hash
			identify = identifyHash(line)
			outfile.write("Analyzing '" + line + "'\n")
			hashesFound += writeResult(identify, outfile)
			#add a newline
			outfile.write("\n")
	#show number of hashes analyzed
	print ("Hashes analyzed: " + str(hashesAnalyzed))
	#show number of hashes found
	print ("Hashes found: " + str(hashesFound))
	#show output file path
	print ("Output written: '" + os.path.abspath(outfile.name) + "'")


#create human readable output
def writeResult(identify, outfile):
	#define the counter
	count = 0
	#iterate over matches
	for result in identify:
		#write the result
		outfile.write("[+] " + result + "\n")
		#increment counter
		count += 1
	#check for unknown hash
	if count == 0:
		outfile.write("[+] Unknown hash\n")
	return (count > 0)


#analyze a single hash
if args.hash:
	print ("Analyzing '" + args.hash + "'")
	writeResult(identifyHash(args.hash), sys.stdout)
#analyze a file
elif args.file:
	with open(args.output, "w", encoding="utf-8") as outfile:
		analyzeFile(args.file, outfile)
	outfile.close()