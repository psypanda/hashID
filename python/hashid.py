#!/usr/bin/env python
#
# @name: hashID.py
# @author: c0re <https://psypanda.org/>                            
# @date: 2013/01/29
# @copyright: <http://creativecommons.org/licenses/by-nc-sa/3.0/>
# @readme: <http://wiki.insidepro.com/index.php/Algorithms>

import re

#set the logo
banner = '''
  #########################################################################
  #     __  __                     __           ______    _____           #
  #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
  #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
  #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
  #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
  #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
  #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/       #
  #                                                                  v1.0 #
  #                                                               by c0re #
  #                                    https://github.com/psypanda/hashID #
  #########################################################################
'''

#function to identify the input hash
def IdentifyHash(hash):
    
    #define the list
    hashes=[]
    
    if (re.match("^[a-f0-9]{4}$", hash, re.IGNORECASE)):
        hashes += ["CRC-16","CRC-16-CCITT","FCS-16"]
    if (re.match("^[a-f0-9]{8}$", hash, re.IGNORECASE)):
        hashes += ["Adler32","CRC-32","CRC-32B","FCS-32","GHash-32-3","GHash-32-5"]
    if (re.match("^\+[a-z0-9\/\.]{12}$", hash, re.IGNORECASE)):
        hashes += ["Blowfish(Eggdrop)"] 
    if (re.match("^.{0,2}[a-z0-9\/\.]{11}$", hash, re.IGNORECASE)):
        hashes += ["DES(Unix)"]    
    if (re.match("^[a-f0-9]{16}$", hash, re.IGNORECASE)):
        hashes += ["MySQL3.x","LM","DES(Oracle)","VNC"]        
    if (re.match("^[a-z0-9\/\.]{16}$", hash, re.IGNORECASE)):
        hashes += ["MD5(Cisco PIX)"]
    if (re.match("^\$1\$.{0,8}\$[a-z0-9\/\.]{22}$", hash, re.IGNORECASE)):
        hashes += ["MD5(Unix)"]
    if (re.match("^\$apr1\$.{0,8}\$[a-z0-9\/\.]{22}$", hash, re.IGNORECASE)):
        hashes += ["MD5(APR)"]
    if (re.match("^[a-f0-9]{24}$", hash, re.IGNORECASE)):
        hashes += ["CRC-96(ZIP)"]
    if (re.match("^\$H\$9[a-z0-9\/\.]{30}$", hash, re.IGNORECASE)):
        hashes += ["MD5(phpBB3)"]
    if (re.match("^\$P\$[a-z0-9\/\.]{31}$", hash, re.IGNORECASE)):
        hashes += ["MD5(Wordpress)"]
    if (re.match("^[0-9a-f]{32}$", hash, re.IGNORECASE)):
        hashes += ["MD5","NTLM","Domain Cached Credentials","Domain Cached Credentials 2","MD4","MD2","RIPEMD-128","Haval-128","Tiger-128","Snefru-128","Skein-256(128)","Skein-512(128)"]
    if (re.match("^0x[a-f0-9]{32}$", hash, re.IGNORECASE)):
        hashes += ["Lineage II C4"]
    if (re.match("^[a-f0-9]{32}:[a-z0-9]{32}$", hash, re.IGNORECASE)):
        hashes += ["MD5(Joomla)"]
    if (re.match("^[a-f0-9]{32}:.{5}$", hash, re.IGNORECASE)):
        hashes += ["MD5(IP.Board)"]
    if (re.match("^[a-f-0-9]{32}:[a-z0-9]{8}$", hash, re.IGNORECASE)):
        hashes += ["MD5(MyBB)"]
    if (re.match("^[a-f0-9]{40}$", hash, re.IGNORECASE)):
        hashes += ["SHA-1","MySQL4.x","RIPEMD-160","Haval-160","SHA-1(MaNGOS)","SHA-1(MaNGOS2)","Tiger-160","Skein-256(160)","Skein-512(160)"]
    if (re.match("^\*[a-f0-9]{40}$", hash, re.IGNORECASE)):
        hashes += ["MySQL5.x"]
    if (re.match("^sha1\$.{0,32}\$[a-f0-9]{40}$", hash, re.IGNORECASE)):
        hashes += ["SHA-1(Django)"]
    if (re.match("^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$", hash, re.IGNORECASE)):
        hashes += ["MSSQL(2005)","MSSQL(2008)"]
    if (re.match("^[a-f0-9]{48}$", hash, re.IGNORECASE)):
        hashes += ["Haval-192","Tiger-192"]
    if (re.match("^[a-f0-9]{51}$", hash, re.IGNORECASE)):
        hashes += ["MD5(Palshop)"]
    if (re.match("^\$S\$[a-z0-9\/\.]{52}$", hash, re.IGNORECASE)):
        hashes += ["SHA-512(Drupal)"]
    if (re.match("^\$2a\$[0-9]{0,2}?\$[a-z0-9\/\.]{53}$", hash, re.IGNORECASE)):
        hashes += ["Blowfish(OpenBSD)"]
    if (re.match("^[a-f0-9]{56}$", hash, re.IGNORECASE)):
        hashes += ["SHA-224","Haval-224","Keccak-224","Skein-256(224)","Skein-512(224)"]
    if (re.match("^[a-f0-9]{64}$", hash, re.IGNORECASE)):
        hashes += ["SHA-256","RIPEMD-256","Haval-256","Snefru-256","GOST R 34.11-94","Keccak-256","Skein-256","Skein-512(256)"]
    if (re.match("^sha256\$.{0,32}\$[a-f0-9]{64}$", hash, re.IGNORECASE)):
        hashes += ["SHA-256(Django)"]
    if (re.match("^\$5\$.{0,22}\$[a-z0-9\/\.]{43,69}$", hash, re.IGNORECASE)):
        hashes += ["SHA-256(Unix)"]
    if (re.match("^[a-f0-9]{80}$", hash, re.IGNORECASE)):
        hashes += ["RIPEMD-320"]
    if (re.match("^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$", hash, re.IGNORECASE)):
        hashes += ["MSSQL(2000)"]
    if (re.match("^\$6\$.{0,22}\$[a-z0-9\/\.]{86}$", hash, re.IGNORECASE)):
        hashes += ["SHA-512(Unix)"]
    if (re.match("^[a-f0-9]{96}$", hash, re.IGNORECASE)):
        hashes += ["SHA-384","Keccak-384","Skein-512(384)","Skein-1024(384)"]
    if (re.match("^sha384\$.{0,32}\$[a-f0-9]{96}$", hash, re.IGNORECASE)):
        hashes += ["SHA-384(Django)"]
    if (re.match("^[a-f0-9]{128}$", hash, re.IGNORECASE)):
        hashes += ["SHA-512","Whirlpool","Keccak-512","Skein-512","Skein-1024(512)"]
    if (re.match("^[a-f0-9]{256}$", hash, re.IGNORECASE)):
        hashes += ["Skein-1024"]
    
    #return the list
    return hashes
        
#display the banner
print (banner)
#loop until CRTL+C
while (1):
   
    print ("----------------------------------------------------------------------------")
    #wait for useriput
    hash = input("HASH: ")
    
    #check for empty input
    if len(hash) < 1:
        print ("\nNo Input detected")
    else:
        #trim possible whitespace
        hash = hash.strip()
        #analyze the hash
        hashes = IdentifyHash(hash)
        
        #no result found
        if len(hashes) == 0:
            print ("\nUnknown Hash")
        #show most and less possible result
        elif len(hashes)>2:
            print ("\nMost Possible:")
            print (" [+] ", hashes[0])
            print (" [+] ", hashes[1])
            print ("\nLess Possible:")
            for i in range(int(len(hashes))-2):
                print (" [+] ", hashes[i+2])
        #show absolut result
        else:
            print ("\nMost Possible:")
            for i in range(len(hashes)):
                print (" [+] ", hashes[i])
