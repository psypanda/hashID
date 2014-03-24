### hashID Changelog

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
* changed regex for:
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
* changed regex for:
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
* changed regex for:
	* NetNTLMv1-VANILLA / NetNTLMv1+ESS
	* NetNTLMv2
	
**Version 2.3.6**
* added hashes:
	* Burning Board 3.x
	* IPMI2 RAKP HMAC-SHA1
	* Lastpass
	* Cisco-ASA(MD5)
	* DNSSEC(NSEC3)
* changed regex for:
	* VNC
* renamed:
	* Keccak to SHA3

**Version 2.3.5**	
* added hashes:
	* Wordpress v2.6.0/2.6.1
* changed regex for:
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