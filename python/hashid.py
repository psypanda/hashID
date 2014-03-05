#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @name: hashID.py
# @author: c0re <https://psypanda.org/>                           
# @date: 2014/03/05
# @copyright: <https://www.gnu.org/licenses/gpl-3.0.html>


import re, os, argparse

#set the version
version = "v2.2.2"
#set the banner
banner = "%(prog)s " + version + " by c0re <https://github.com/psypanda/hashID>\nLicense GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>"
#set the usage
usage = "%(prog)s (-i HASH | -f FILE) [-o OUTFILE] [--help] [--version]"
#set the description
description = "identify the different types of hashes"

#configure argparse
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, usage=usage, description=description)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-i", "--identify", type=str, help="identify a single hash")
group.add_argument("-f", "--file", type=argparse.FileType("r"), help="analyse a given file")
parser.add_argument("-o", "--output", type=argparse.FileType("w"), default="hashid_output.txt", help="sets a different output filename (default: %(default)s)")
parser.add_argument("--version", action="version", version=banner)
args = parser.parse_args()

#define found hash counter
foundHashes = 0

#identify the input hash
def identifyHash(hash):
  global foundHashes
  #define the list
  hashes=[]
  #trim possible whitespace
  hash = hash.strip()
  #set regex and algorithms
  prototypes = \
  (
    ("^[a-f0-9]{4}$", ("CRC-16","CRC-16-CCITT","FCS-16")),
    ("^[a-f0-9]{8}$", ("Adler-32","CRC-32","CRC-32B","FCS-32","GHash-32-3","GHash-32-5","FNV-132","Fletcher-32","Joaat","ELF-32","XOR-32")),
    ("^\+[a-z0-9\/\.]{12}$", ("Blowfish(Eggdrop)",)),
    ("^[a-z0-9\/\.]{13}$", ("DES(Unix)","Traditional DES","DEScrypt")),
    ("^[a-f0-9]{16}$", ("MySQL3.x","DES(Oracle)","VNC","Half MD5","FNV-164","CRC-64")),
    ("^[a-z0-9\/\.]{16}$", ("Cisco-PIX MD5",)),
    ("^\([a-z0-9\+\/]{20}\)$", ("Lotus Domino",)),
    ("^[a-f0-9]{24}$", ("CRC-96(ZIP)",)),
    ("^[0-9a-f]{32}$", ("MD5","NTLM","LM","MD4","MD2","RAdmin v2.x","RIPEMD-128","Haval-128","Tiger-128","Snefru-128","MD5(ZipMonster)","Skein-256(128)","Skein-512(128)")),
    ("^{SHA}[a-z0-9\/\+]{27}=$", ("SHA-1(Base64)","Netscape LDAP SHA")),
    ("^\$1\$.{0,8}\$[a-z0-9\/\.]{22}$", ("MD5(Unix)","Cisco-IOS MD5","FreeBSD MD5")),
    ("^0x[a-f0-9]{32}$", ("Lineage II C4",)), 
    ("^\$H\$[a-z0-9\/\.]{31}$", ("MD5(phpBB3)",)),
    ("^\$P\$[a-z0-9\/\.]{31}$", ("MD5(Wordpress)",)),
    ("^[a-f0-9]{32}:[a-z0-9]{2}$", ("osCommerce","xt:Commerce")),
    ("^\$apr1\$.{0,8}\$[a-z0-9\/\.]{22}$", ("MD5(APR)","Apache MD5")),
    ("^{smd5}.{31}$", ("AIX(smd5)",)),
    ("^[a-f0-9]{32}:[0-9]{4}$", ("WebEdition CMS",)),
    ("^[a-f0-9]{32}:.{5}$", ("IP.Board v2+","MyBB v1.2+")),
    ("^[a-z0-9]{34}$", ("CryptoCurrency(Adress)",)),
    ("^[a-f0-9]{40}$", ("SHA-1","MySQL4.x","RIPEMD-160","Haval-160","SHA-1(MaNGOS)","SHA-1(MaNGOS2)","Tiger-160","Skein-256(160)","Skein-512(160)")),
    ("^\*[a-f0-9]{40}$", ("MySQL5.x",)),
    ("^[a-z0-9]{43}$", ("Cisco-IOS(SHA256)",)),
    ("^[a-f-0-9]{32}:.+$", ("Domain Cached Credentials 2",)),
    ("^{SSHA}[a-z0-9\+\/]{38}={0,2}$", ("SSHA-1(Base64)","Netscape LDAP SSHA")),
    ("^[a-z0-9]{47}$", ("FortiOS",)),
    ("^[a-f0-9]{48}$", ("Haval-192","Tiger-192","OSX v10.4","OSX v10.5","OSX v10.6")),
    ("^[a-f0-9]{51}$", ("Palshop CMS",)),
    ("^[a-z0-9]{51}$", ("CryptoCurrency(PrivateKey)",)),
    ("^{ssha1}[a-z0-9\.\$]{47}$", ("AIX(ssha1)",)),
    ("^0x0100[a-f0-9]{48}$", ("MSSQL(2005)","MSSQL(2008)")),
    ("^\$md5,rounds=[0-9]+\$[a-z0-9\.\/]{0,8}(\$|\$\$)[a-z0-9\.\/]{22}$", ("MD5(Sun)",)),
    ("^[a-f0-9]{56}$", ("SHA-224","Haval-224","Keccak-224","Skein-256(224)","Skein-512(224)")),
    ("^(\$2a|\$2y|\$2)\$[0-9]{0,2}?\$[a-z0-9\/\.]{53}$", ("Blowfish(OpenBSD)",)),
    ("^S:[a-f0-9]{60}$", ("Oracle 11g",)),
    ("^[a-f0-9]{32}:[a-z0-9]{30}$", ("vBulletin >v3.8.5",)),
    ("^[a-f0-9]{64}$", ("SHA-256","RIPEMD-256","Haval-256","Snefru-256","GOST R 34.11-94","Keccak-256","Skein-256","Skein-512(256)")),
    ("^[a-f0-9]{32}:[a-z0-9]{32}$", ("Joomla",)),
    ("^[a-f-0-9]{32}:[a-f-0-9]{32}$", ("SAM(LM_Hash:NT_Hash)",)),
    ("^\$episerver\$\*0\*[a-z0-9=\*+]{52}$", ("EPiServer 6.x <v4",)),
    ("^{ssha256}[a-z0-9\.\$]{63}$", ("AIX(ssha256)",)),
    ("^[a-f0-9]{80}$", ("RIPEMD-320",)),
    ("^\$episerver\$\*1\*[a-z0-9=\*+]{68}$", ("EPiServer 6.x >v4",)),
    ("^0x0100[a-f0-9]{88}$", ("MSSQL(2000)",)),
    ("^[a-f0-9]{96}$", ("SHA-384","Keccak-384","Skein-512(384)","Skein-1024(384)")),
    ("^{SSHA512}[a-z0-9\+\/]{96}={0,2}$", ("SSHA-512(Base64)","LDAP(SSHA512)")),
    ("^{ssha512}[a-z0-9\.\$]{107}$", ("AIX(ssha512)",)),
    ("^[a-f0-9]{128}$", ("SHA-512","Whirlpool","Salsa10","Salsa20","Keccak-512","Skein-512","Skein-1024(512)")),
    ("^[a-f0-9]{136}$", ("OSX v10.7",)),
    ("^0x0200[a-f0-9]{136}$", ("MSSQL(2012)",)),
    ("^\$ml\$.+$", ("OSX v10.8",)),
    ("^[a-f0-9]{256}$", ("Skein-1024",)),
    ("^grub\.pbkdf2.+$", ("GRUB 2",)),
    ("^sha1\$.{0,32}\$[a-f0-9]{40}$", ("SHA-1(Django)",)),
    ("^\$S\$[a-z0-9\/\.]{52}$", ("SHA-512(Drupal)",)),
    ("^\$5\$.{0,22}\$[a-z0-9\/\.]{43,69}$", ("SHA-256(Unix)",)),
    ("^\$6\$.{0,22}\$[a-z0-9\/\.]{86}$", ("SHA-512(Unix)",)),
    ("^\$sha\$[a-z0-9]{0,16}\$[a-f0-9]{64}$", ("Minecraft(AuthMe Reloaded)",)),
    ("^sha256\$.{0,32}\$[a-f0-9]{64}$", ("SHA-256(Django)",)),
    ("^sha384\$.{0,32}\$[a-f0-9]{96}$", ("SHA-384(Django)",)),
    ("^[^\\\/:*?\"\<\>\|]{1,15}:[^\\\/:*?\"\<\>\|]{1,15}:[a-f0-9]{32}:[a-f0-9]{32}:{0,3}$", ("Domain Cached Credentials",))
  )
  for hashtype in prototypes:
    #try to find matches
    if (re.match(hashtype[0], hash, re.IGNORECASE)):
      hashes += hashtype[1]
	  #increment found counter
      foundHashes += 1
  #return the list
  return hashes


#create human readable output
def showResult(list):
  #define the list
  result = []
  #no result found
  if (len(list) == 0):
    return " [+] Unknown Hash\n"
  #show multiple results
  elif (len(list) > 2):
    result = " Most Possible:\n"
    result += " [+] " + list[0] + "\n"
    result += " [+] " + list[1] + "\n"
    result += " Less possible:\n"
    for i in range(int(len(list))-2):
      result += " [+] " + list[i+2] + "\n"
    #return the formatted text
    return result
  #show absolute result
  else:
    result = "Most Possible:\n"
    for i in range(len(list)):
      result += " [+] " + list[i] + "\n"
    #return the formatted text
    return result

#analyse and write file
def analyseFile(infile,outfile):
  hashesAnalysed = 0
  for line in infile:
    #increment hash count
    hashesAnalysed += 1
    #trim possible whitespace
    line = line.strip()
    #write result
    outfile.write("Analysing '" + line + "'\n" + showResult(identifyHash(line)) + "\n")
  #show	number of hashes analysed
  print ("Hashes analysed: " + str(hashesAnalysed))
  #show number of hashes found
  print ("Hashes found: " + str(foundHashes))
  #show output file path
  print ("Output written: " + os.path.abspath(outfile.name))


#analyse a single hash
if args.identify:
  print ("Analysing '" + args.identify + "'\n" + showResult(identifyHash(args.identify)))
#analyse a file
elif args.file:
  #custom output file set
  if args.output:
    analyseFile(args.file,args.output)
  #default output file
  else:
    analyseFile(args.file,args.output)