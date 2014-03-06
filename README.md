hash-identifier
======

identify the different types of hashes used to encrypt data and especially passwords.

this tool replaces [hash-identifier](http://code.google.com/p/hash-identifier/), which is outdated!


### usage:

	$ python hashid.py (-i HASH | -f FILE) [-o OUTFILE] [--help] [--version]

### screenshot:

	$ python hashid.py -i 827ccb0eea8a706c4c34a16891f84e7b
	Analysing '827ccb0eea8a706c4c34a16891f84e7b'
	Most Possible:
	[+] MD5
	[+] NTLM
	Less possible:
	[+] LM
	[+] MD4
	[+] MD2
	[+] RAdmin v2.x
	[+] RIPEMD-128
	[+] Haval-128
	[+] Tiger-128
	[+] Snefru-128
	[+] MD5(ZipMonster)
	[+] Skein-256(128)
	[+] Skein-512(128)

### supported hashes:
	Adler-32, Apache MD5, AIX(smd5), AIX(ssha1), AIX(ssha256), AIX(ssha512)
	Blowfish(Eggdrop), Blowfish(OpenBSD), BSDi Crypt, BCrypt(SHA256)
	CRC-16, CRC-16-CCITT, CRC-32, CRC-32B, CRC-64, CRC-96(ZIP), Cisco-IOS(MD5), Cisco-IOS(SHA256), Cisco-PIX(MD5)
	CryptoCurrency(Adress), CryptoCurrency(PrivateKey), Crypt16
	Domain Cached Credentials, Domain Cached Credentials 2, DES(Unix), DES(Oracle)
	EPiServer 6.x <v4, EPiServer 6.x >v4, ELF-32
	FCS-16, FCS-32, Fletcher-32, FNV-132, FNV-164, FortiOS, FreeBSD MD5
	GOST R 34.11-94, GHash-32-3, GHash-32-5, GRUB 2
	Haval-128, Haval-160, Haval-192, Haval-224, Haval-256, Half MD5, HAS-160
	IPBoard v2+
	Joaat, Joomla
	Keccak-224, Keccak-256, Keccak-384, Keccak-512
	Lineage II C4, LDAP(SSHA512), LM, Lotus Domino
	MD2, MD4, MD5, MD5(APR), MD5(Unix), MD5(phpBB3), MD5(WordPress), MD5(Zipmonster), MD5(Sun), Minecraft(AuthMe Reloaded)
	MyBB1.2+, MySQL3.x, MySQL4.x, MySQL5.x, MSSQL(2000), MSSQL(2005), MSSQL(2008), MSSQL(2012)
	NTLM, Netscape LDAP SHA
	Oracle 7-10g, Oracle 11g, osCommerce, OSX v10.4, OSX v10.5, OSX v10.6, OSX v10.7, OSX v10.8
	Palshop CMS, PHPass' Portable Hash
	RAdmin v2.x, RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320
	SAM(LM_Hash:NT_Hash), SHA-1, SHA-1(Base64), SHA-1(Django), SHA-1(MaNGOS), SHA-1(MaNGOS2), SHA-224, SHA-256
	SHA-256(Django), SHA-256(Unix), SHA-384, SHA-384(Django), SHA-512, SHA-512(Drupal), SHA-512(Unix)
	SSHA-1(Base64), SSHA-512(Base64), Salsa10, Salsa20, Skein-256, Skein-256(128), Skein-256(160), Skein-256(224)
	Skein-512, Skein-512(128), Skein-512(160), Skein-512(224), Skein-512(256), Skein-512(384), Skein-1024, Skein-1024(384)
	Skein-1024(512), Snefru-128, Snefru-256, SCRAM Hash
	Tiger-128, Tiger-160, Tiger-192
	VNC
	vBulletin >v3.8.5
	Whirlpool
	WebEdition CMS
	XOR-32
	xt:Commerce


**Total:** 136 hash algorithms