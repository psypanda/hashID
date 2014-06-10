(function(exports){
	'use strict';
	
	// INPUT: a single line hash
	// OUTPUT: an array of matches
	// ERROR: an error is thrown if there are no matches
	exports.identifyHash = function(phash){
		//trim possible whitespace
		phash = phash.trim();
		//set regex and algorithms
		var hash_arr = [
			{regex: /^[a-f0-9]{4}$/i, hashes: ["CRC-16","CRC-16-CCITT","FCS-16"]},
			{regex: /^[a-f0-9]{6}$/i, hashes: ["CRC-24"]},
			{regex: /^[a-f0-9]{8}$/i, hashes: ["Adler-32","CRC-32","CRC-32B","FCS-32","GHash-32-3","GHash-32-5","FNV-132","Fletcher-32","Joaat","ELF-32","XOR-32"]},
			{regex: /^\+[a-z0-9\/\.]{12}$/i, hashes: ["Blowfish(Eggdrop)"]},
			{regex: /^[a-z0-9\/\.]{13}$/i, hashes: ["DES(Unix)","Traditional DES","DEScrypt"]},
			{regex: /^[a-f0-9]{16}$/i, hashes: ["MySQL323","DES(Oracle)","Half MD5","Oracle 7-10g","FNV-164","CRC-64"]},
			{regex: /^[a-z0-9\/\.]{16}$/i, hashes: ["Cisco-PIX(MD5)"]},
			{regex: /^\([a-z0-9\+\/]{20}\)$/i, hashes: ["Lotus Notes/Domino 6"]},
			{regex: /^_[a-z0-9\/\.]{19}$/i, hashes: ["BSDi Crypt"]},
			{regex: /^[a-f0-9]{24}$/i, hashes: ["CRC-96(ZIP)"]},
			{regex: /^[a-z0-9\/\.]{24}$/i, hashes: ["Crypt16"]},
			{regex: /^[a-f0-9]{32}$/i, hashes: ["MD5","MD4","MD2","Double MD5","NTLM","LM","RAdmin v2.x","RIPEMD-128","Haval-128","Tiger-128","Snefru-128","ZipMonster","Skein-256(128)","Skein-512(128)","Lotus Notes/Domino 5"]},
			{regex: /^[a-f0-9]{32}(:[^\\\/\:\*\?\"<\>\|]{1,20})?$/i, hashes: ["Domain Cached Credentials", "mscash"]},
			{regex: /^(\$DCC2\$10240#[^\\\/\:\*\?\"<\>\|]{1,20}#)?[a-f0-9]{32}$/i, hashes: ["Domain Cached Credentials 2","mscash2"]},
			{regex: /^{SHA}[a-z0-9\/\+]{27}=$/i, hashes: ["SHA-1(Base64)","Netscape LDAP SHA","nsldap"]},
			{regex: /^\$1\$[a-z0-9\/\.]{0,8}\$[a-z0-9\/\.]{22}$/i, hashes: ["MD5 Crypt","Cisco-IOS(MD5)","FreeBSD MD5"]},
			{regex: /^0x[a-f0-9]{32}$/i, hashes: ["Lineage II C4"]},
			{regex: /^\$H\$[a-z0-9\/\.]{31}$/i, hashes: ["phpBB v3.x","Wordpress v2.6.0/2.6.1","PHPass' Portable Hash"]},
			{regex: /^\$P\$[a-z0-9\/\.]{31}$/i, hashes: ["Wordpress ≥ 2.6.2","Joomla ≥ v2.5.18","PHPass' Portable Hash"]},
			{regex: /^[a-f0-9]{32}:[a-z0-9]{2}$/i, hashes: ["osCommerce","xt:Commerce"]},
			{regex: /^\$apr1\$[a-z0-9\/\.]{0,8}\$[a-z0-9\/\.]{22}$/i, hashes: ["MD5(APR)","Apache MD5","md5apr1"]},
			{regex: /^{smd5}[a-z0-9\.\$]{31}$/i, hashes: ["AIX(smd5)"]},
			{regex: /^[a-f0-9]{32}:[a-f0-9]{32}$/i, hashes: ["WebEdition CMS"]},
			{regex: /^[a-f0-9]{32}:.{5}$/i, hashes: ["IP.Board v2+"]},
			{regex: /^[a-f0-9]{32}:.{8}$/i, hashes: ["MyBB ≥ v1.2+"]},
			{regex: /^[a-z0-9]{34}$/i, hashes: ["CryptoCurrency(Adress)"]},
			{regex: /^[a-f0-9]{40}$/i, hashes: ["SHA-1","Double SHA-1","MangosWeb Enhanced CMS","LinkedIn","RIPEMD-160","Haval-160","Tiger-160","HAS-160","Skein-256(160)","Skein-512(160)"]},
			{regex: /^\*[a-f0-9]{40}$/i, hashes: ["MySQL5.x","MySQL4.1"]},
			{regex: /^[a-z0-9]{43}$/i, hashes: ["Cisco-IOS(SHA-256)"]},
			{regex: /^{SSHA}([a-z0-9\+\/]{40}|[a-z0-9\+\/]{38}==)$/i, hashes: ["SSHA-1(Base64)","Netscape LDAP SSHA","nsldaps"]},
			{regex: /^[a-z0-9]{47}$/i, hashes: ["Fortigate(FortiOS)"]},
			{regex: /^[a-f0-9]{48}$/i, hashes: ["Haval-192","Tiger-192","SHA-1(Oracle)","OSX v10.4","OSX v10.5","OSX v10.6"]},
			{regex: /^[a-f0-9]{51}$/i, hashes: ["Palshop CMS"]},
			{regex: /^[a-z0-9]{51}$/i, hashes: ["CryptoCurrency(PrivateKey)"]},
			{regex: /^{ssha1}[a-z0-9\.\$]{47}$/i, hashes: ["AIX(ssha1)"]},
			{regex: /^0x0100[a-f0-9]{48}$/i, hashes: ["MSSQL(2005)","MSSQL(2008)"]},
			{regex: /^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/\.]{0,16}(\$|\$\$)[a-z0-9\/\.]{22}$/i, hashes: ["Sun MD5 Crypt"]},
			{regex: /^[a-f0-9]{56}$/i, hashes: ["SHA-224","Haval-224","SHA3-224","Skein-256(224)","Skein-512(224)"]},
			{regex: /^(\$2[axy]|\$2)\$[0-9]{0,2}?\$[a-z0-9\/\.]{53}$/i, hashes: ["Blowfish(OpenBSD)","Woltlab Burning Board 4.x","BCrypt"]},
			{regex: /^[a-f0-9]{40}:[a-f0-9]{16}$/i, hashes: ["Samsung Android Password/PIN"]},
			{regex: /^S:[a-f0-9]{60}$/i, hashes: ["Oracle 11g"]},
			{regex: /^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/\.]{22}\$[a-z0-9\/\.]{31}$/i, hashes: ["BCrypt(SHA-256)"]},
			{regex: /^[a-f0-9]{32}:.{3}$/i, hashes: ["vBulletin < v3.8.5"]},
			{regex: /^[a-f0-9]{32}:.{30}$/i, hashes: ["vBulletin ≥ v3.8.5"]},
			{regex: /^[a-f0-9]{64}$/i, hashes: ["SHA-256","RIPEMD-256","Haval-256","Snefru-256","GOST R 34.11-94","SHA3-256","Skein-256","Skein-512(256)","Ventrilo"]},
			{regex: /^[a-f0-9]{32}:[a-z0-9]{32}$/i, hashes: ["Joomla < v2.5.18"]},
			{regex: /^[a-f-0-9]{32}:[a-f-0-9]{32}$/i, hashes: ["SAM(LM_Hash:NT_Hash)"]},
			{regex: /^[a-f0-9]{32}:[0-9]{32}:[0-9]{2}$/i, hashes: ["MD5(Chap)","iSCSI CHAP Authentication"]},
			{regex: /^\$episerver\$\*0\*[a-z0-9=\*\+]{52}$/i, hashes: ["EPiServer 6.x < v4"]},
			{regex: /^{ssha256}[a-z0-9\.\$]{63}$/i, hashes: ["AIX(ssha256)"]},
			{regex: /^[a-f0-9]{80}$/i, hashes: ["RIPEMD-320"]},
			{regex: /^\$episerver\$\*1\*[a-z0-9=\*\+]{68}$/i, hashes: ["EPiServer 6.x ≥ v4"]},
			{regex: /^0x0100[a-f0-9]{88}$/i, hashes: ["MSSQL(2000)"]},
			{regex: /^[a-f0-9]{96}$/i, hashes: ["SHA-384","SHA3-384","Skein-512(384)","Skein-1024(384)"]},
			{regex: /^{SSHA512}[a-z0-9\+\/]{96}={0,2}$/i, hashes: ["SSHA-512(Base64)","LDAP(SSHA-512)"]},
			{regex: /^{ssha512}[0-9]{2}\$[a-z0-9\.\/]{16,48}\$[a-z0-9\.\/]{86}$/i, hashes: ["AIX(ssha512)"]},
			{regex: /^[a-f0-9]{128}$/i, hashes: ["SHA-512","Whirlpool","Salsa10","Salsa20","SHA3-512","Skein-512","Skein-1024(512)"]},
			{regex: /^[a-f0-9]{136}$/i, hashes: ["OSX v10.7"]},
			{regex: /^0x0200[a-f0-9]{136}$/i, hashes: ["MSSQL(2012)"]},
			{regex: /^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$/i, hashes: ["OSX v10.8","OSX v10.9"]},
			{regex: /^[a-f0-9]{256}$/i, hashes: ["Skein-1024"]},
			{regex: /^grub\.pbkdf2\.sha512\.[0-9]+\.[a-f0-9]+\.[a-f0-9]+$/i, hashes: ["GRUB 2"]},
			{regex: /^sha1\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{40}$/i, hashes: ["Django(SHA-1)"]},
			{regex: /^[a-f0-9]{49}$/i, hashes: ["Citrix Netscaler"]},
			{regex: /^\$S\$[a-z0-9\/\.]{52}$/i, hashes: ["Drupal ≥ v7.x"]},
			{regex: /^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/\.]{0,16}\$[a-z0-9\/\.]{43}$/i, hashes: ["SHA-256 Crypt"]},
			{regex: /^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$/i, hashes: ["Sybase ASE"]},
			{regex: /^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/\.]{0,16}\$[a-z0-9\/\.]{86}$/i, hashes: ["SHA-512 Crypt"]},
			{regex: /^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$/i, hashes: ["Minecraft(AuthMe Reloaded)"]},
			{regex: /^sha256\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{64}$/i, hashes: ["Django(SHA-256)"]},
			{regex: /^sha384\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{96}$/i, hashes: ["Django(SHA-384)"]},
			{regex: /^crypt1:[a-z0-9\+\=]{12}:[a-z0-9\+\=]{12}$/i, hashes: ["Clavister Secure Gateway"]},
			{regex: /^[a-f0-9]{112}$/i, hashes: ["Cisco VPN Client(PCF-File)"]},
			{regex: /^[a-f0-9]{1329}$/i, hashes: ["Microsoft MSTSC(RDP-File)"]},
			{regex: /^[^\\\/\:\*\?\"<\>\|]{1,20}::[^\\\/\:\*\?\"<\>\|]{1,20}:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$/i, hashes: ["NetNTLMv1-VANILLA / NetNTLMv1+ESS"]},
			{regex: /^[^\\\/\:\*\?\"<\>\|]{1,20}::[^\\\/\:\*\?\"<\>\|]{1,20}:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$/i, hashes: ["NetNTLMv2"]},
			{regex: /^\$krb5pa\$23\$user\$realm\$salt\$[a-f0-9]{104}$/i, hashes: ["Kerberos 5 AS-REQ Pre-Auth"]},
			{regex: /^\$scram\$[0-9]+\$[a-z0-9\/\.]{16}\$sha-1=[a-z0-9\/\.]{27},sha-256=[a-z0-9\/\.]{43},sha-512=[a-z0-9\/\.]{86}$/i, hashes: ["SCRAM Hash"]},
			{regex: /^[a-f0-9]{40}:[a-f0-9]{0,32}$/i, hashes: ["Redmine Project Management Web App"]},
			{regex: /^([0-9]{12})?\$[a-f0-9]{16}$/i, hashes: ["SAP CODVN B (BCODE)"]},
			{regex: /^([0-9]{12})?\$[a-f0-9]{40}$/i, hashes: ["SAP CODVN F/G (PASSCODE)"]},
			{regex: /^[a-z0-9\/\.]{30}(:.+)?$/i, hashes: ["Juniper Netscreen/SSG(ScreenOS)"]},
			{regex: /^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$/i, hashes: ["EPi"]},
			{regex: /^[a-f0-9]{40}:[^*]{1,25}$/i, hashes: ["SMF ≥ v1.1"]},
			{regex: /^[a-f0-9]{40}:[a-f0-9]{40}$/i, hashes: ["Woltlab Burning Board 3.x"]},
			{regex: /^[a-f0-9]{130}(:[a-f0-9]{40})?$/i, hashes: ["IPMI2 RAKP HMAC-SHA1"]},
			{regex: /^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$/i, hashes: ["Lastpass"]},
			{regex: /^[a-z0-9\/\.]{16}(:.{1,})?$/i, hashes: ["Cisco-ASA(MD5)"]},
			{regex: /^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$/i, hashes: ["VNC"]},
			{regex: /^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$/i, hashes: ["DNSSEC(NSEC3)"]},
			{regex: /^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$/i, hashes: ["RACF"]},
			{regex: /^\$3\$\$[a-f0-9]{32}$/i, hashes: ["NTHash(FreeBSD Variant)"]},
			{regex: /^\$sha1\$[0-9]+\$[a-z0-9\/\.]{0,64}\$[a-z0-9\/\.]{28}$/i, hashes: ["SHA-1 Crypt"]},
			{regex: /^[a-f0-9]{70}$/i, hashes: ["hMailServer"]},
			{regex: /^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$/i, hashes: ["MediaWiki"]},
			{regex: /^[a-f0-9]{140}$/i, hashes: ["Minecraft(xAuth)"]},
			{regex: /^\$pbkdf2-sha(1|256|512)\$[0-9]+\$[a-z0-9\/\.]{22}\$([a-z0-9\/\.]{27}|[a-z0-9\/\.]{43}|[a-z0-9\/\.]{86})$/i, hashes: ["PBKDF2(Generic)"]},
			{regex: /^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/\+=-]{28}$/i, hashes: ["PBKDF2(Cryptacular)"]},
			{regex: /^\$p5k2\$[0-9]+\$[a-z0-9\/\.]+\$[a-z0-9\/\.]{32}$/i, hashes: ["PBKDF2(Dwayne Litzenberger)"]},
			{regex: /^{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+$/i, hashes: ["Fairly Secure Hashed Password"]},
			{regex: /^\$PHPS\$.+\$[a-f0-9]{32}$/i, hashes: ["PHPS"]},
			{regex: /^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$/i, hashes: ["1Password(Agile Keychain)"]},
			{regex: /^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$/i, hashes: ["1Password(Cloud Keychain)"]},
			{regex: /^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$/i, hashes: ["IKE-PSK MD5"]},
			{regex: /^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$/i, hashes: ["IKE-PSK SHA1"]},
            {regex: /^[a-z0-9+\/]{27}=$/i, hashes: ["PeopleSoft"]},
            {regex: /^crypt\$[a-f0-9]{5}\$[a-z0-9.\/]{13}$/i, hashes: ["Django(DES Crypt Wrapper)"]},
            {regex: /^pbkdf2_sha256\$[0-9]+\$[a-z0-9]{1,}\$[a-z0-9+\/]{43}=$/i, hashes: ["Django(PBKDF2-HMAC-SHA256)"]},
            {regex: /^pbkdf2_sha1\$[0-9]+\$[a-z0-9]{1,}\$[a-z0-9+\/]{27}=$/i, hashes: ["Django(PBKDF2-HMAC-SHA1)"]},
            {regex: /^bcrypt(\$2[axy]|\$2)\$[0-9]{0,2}?\$[a-z0-9\/\.]{53}$/i, hashes: ["Django(BCrypt)"]},
            {regex: /^md5\$[a-f0-9]{1,}\$[a-f0-9]{32}$/i, hashes: ["Django(MD5)"]},
            {regex: /^\{PKCS5S2\}[a-z0-9+\/]{64}$/i, hashes: ["PBKDF2(Atlassian)"]},
            {regex: /^md5[a-f0-9]{32}$/i, hashes: ["PostgreSQL MD5"]}
		];
		var result = [];
		for(var hash_id=0; hash_id < hash_arr.length; hash_id++){
			var curr_hash = hash_arr[hash_id];
			
			//try to find matches
			if (phash.match(curr_hash.regex)){
				result = result.concat(curr_hash.hashes);
			}
		}
		if(result.length > 0){
			return result;
		}
		// else
		return new Error("Did not find any matches.");
	};
})(typeof exports === 'undefined'? this['hashID']={}: exports);
