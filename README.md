hash-identifier
======

identify the different types of hashes used to encrypt data and especially passwords.

this tool replaces [hash-identifier](http://code.google.com/p/hash-identifier/), which is outdated!


### usage:

	$ python hashid.py <hash | file>

### screenshot:

	$ python hashid.py 827ccb0eea8a706c4c34a16891f84e7b
	Analysing '827ccb0eea8a706c4c34a16891f84e7b'
	 Most possible:
	 [+] MD5
	 [+] NTLM
	 Less possible:
	 [+] Domain Cached Credentials
	 [+] Domain Cached Credentials 2
	 [+] RAdmin v2.x
	 [+] MD4
	 [+] MD2
	 [+] RIPEMD-128
	 [+] Haval-128
	 [+] Tiger-128
	 [+] Snefru-128
	 [+] Skein256-(128)
	 [+] Skein512-(128)

### currently supports:

* Adler32
* AIX(IBM)
* Blowfish(Eggdrop), Blowfish(OpenBSD)
* CRC-16, CRC-16-CCITT
* CRC-32, CRC-32B
* CRC-64
* CRC-96(ZIP)
* CiscoIOS(SHA256)
* CryptoCurrency(Adress), CryptoCurrency(PrivateKey)
* Domain Cached Credentials, Domain Cached Credentials 2
* DES(Unix), DES(Oracle)
* EPiServer 6.x <v4, EPiServer 6.x >v4
* FCS-16, FCS-32
* FNV-132, FNV-164
* FortiOS
* GOST R 34.11-94
* GHash-32-3, GHash-32-5
* GRUB 2
* Haval-128, Haval-160, Haval-192, Haval-224, Haval-256
* Joaat
* Keccak-224, Keccak-256, Keccak-384, Keccak-512
* Lineage II C4
* LM
* Lotus Domino
* MD2, MD4, MD5
* MD5(Joomla), MD5(osCommerce), MD5(PalshopCMS)
* MD5(APR), MD5(Cisco PIX), MD5(Unix)
* MD5(IP.Board), MD5(MyBB), MD5(phpBB3), MD5(WordPress)
* Minecraft(AuthMe Reloaded)
* MySQL3.x, MySQL4.x, MySQL5.x
* MSSQL(2000), MSSQL(2005), MSSQL(2008), MSSQL(2012)
* NTLM
* Oracle 11g
* OSX v10.7, OSX v10.8
* RAdmin v2.x
* RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320
* SAM(LM_Hash:NT_Hash)
* SHA-1, SHA-1(Django), SHA-1(MaNGOS), SHA-1(MaNGOS2)
* SHA-224
* SHA-256, SHA-256(Django), SHA-256(Unix)
* SHA-384, SHA-384(Django)
* SHA-512, SHA-512(Drupal), SHA-512(Unix)
* SSHA-1, SSHA-512
* Salsa10, Salsa20
* Skein-256, Skein-256(128), Skein-256(160), Skein-256(224)
* Skein-512, Skein-512(128), Skein-512(160), Skein-512(224), Skein-512(256), Skein-512(384)
* Skein-1024, Skein-1024(384), Skein-1024(512)
* Snefru-128, Snefru-256
* Tiger-128, Tiger-160, Tiger-192
* VNC
* vBulletin >v3.8.5
* Whirlpool
* XOR-32

**Total:** 110 hash algorithms