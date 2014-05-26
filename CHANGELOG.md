### hashID Changelog
**Version 2.6.4**
* added hashes:
	* PHPS
* new hashcat mode:
	* PHPS

**Version 2.6.3**
* added hashes:
	* Lotus Notes/Domino 5
* changed regex:
	* DNSSEC(NSEC3)
* renamed:
	* Lotus Domino to Lotus Notes/Domino 6
* new hashcat mode:
	* Lotus Notes/Domino 5
	* Lotus Notes/Domino 6

**Version 2.6.2**
* added JTR formats to hashinfo.xlsx
* changed regex:
	* Juniper Netscreen/SSG(ScreenOS)
	* NTLM

**Version 2.6.1**
* additional mimetype check on file input
* added hashes:
	* MSSQL(2014)
* renamed:
	* Blowfish(Eggdrop) to Eggdrop IRC Bot

**Version 2.6.0**
* added directory analyze (parameter: "-d/--dir")
* more error checking on userinput
* changed regex:
	* vBulletin < v3.8.5

**Version 2.5.0**
* new syntax - see readme
* added hashes:
	* CRC-24
	* Joomla ≥ 2.5.18
	* Woltlab Burning Board 4.x
* changed regex:
	* GRUB 2
	* BCrypt(SHA-256)
	* OSX v10.8
	* OSX v10.9
	* DNSSEC(NSEC3)
	* Minecraft(AuthMe Reloaded)
* renamed:
	* Wordpress 2.6.2 to Wordpress v2.6.2
	* Joomla to Joomla < 2.5.18
	* Drupal7 to Drupal ≥ v7.x
	* Burning Board 3.x to Woltlab Burning Board 3.x
* new hashcat mode:
	* hMailServer

**Version 2.4.5**
* added hashes:
	* Fairly Secure Hashed Password
* changed regex:
	* SAP CODVN B (BCODE)
	* SAP CODVN F/G (PASSCODE)
* renamed:
	* Cisco-IOS(SHA256) to Cisco-IOS(SHA-256)
	
**Version 2.4.4**
* added hashes:
	* xAuth
	* PBKDF2(Generic)
	* PBKDF2(Cryptacular)
	* PBKDF2(Dwayne Litzenberger)

**Version 2.4.3**
* added hashes:
	* hMailServer
	* MediaWiki
* changed regex:
	* vBulletin ≥ v3.8.5
	* Cisco-ASA(MD5)
* renamed:
	* BCrypt(SHA256) to BCrypt(SHA-256)
	
**Version 2.4.2**
* added hashes:
	* SHA-1 Crypt
* renamed:
	* MD5(Sun) to Sun MD5 Crypt
	* SHA-256(Unix) to SHA-256 Crypt
	* SHA-512(Unix) to SHA-512 Crypt
	* MD5(Unix) to MD5 Crypt

**Version 2.4.1**
* added hashes:
	* NTHash(FreeBSD Variant)
* changed regex:
	* Domain Cached Credentials
	* Domain Cached Credentials 2
	* NetNTLMv1-VANILLA / NetNTLMv1+ESS
	* NetNTLMv2

**Version 2.4.0**
* added Hashcat Mode output (-hc, --hashcat)
* added hashes:
	* RACF
	* Double MD5
	* Double SHA-1
	* md5apr1
	* bcrypt
* changed regex:
	* NetNTLMv1-VANILLA / NetNTLMv1+ESS
	* NetNTLMv2
	
**Version 2.3.6**
* added hashes:
	* Burning Board 3.x
	* IPMI2 RAKP HMAC-SHA1
	* Lastpass
	* Cisco-ASA(MD5)
	* DNSSEC(NSEC3)
* changed regex:
	* VNC
* renamed:
	* Keccak to SHA3

**Version 2.3.5**	
* added hashes:
	* Wordpress v2.6.0/2.6.1
* changed regex:
	* MyBB ≥ v1.2+
* renamed:
	* MD5(phpBB) to phpBB 3.x
	* MD5(Wordpress) to Wordpress ≥ v2.6.2
	* MD5(ZipMonster) to ZipMonster
	* MD5(MaNGOS) to MaNGOS CMS
	* MD5(MaNGOS2) to MaNGOS CMS v2
	* SHA1(LinkedIn)to LinkedIn
	* SHA-1(Django) to Django CMS(SHA-1)
	* SHA-256(Django) to Django CMS(SHA-256)
	* SHA-384(Django) to Django CMS(SHA-384)