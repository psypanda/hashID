(function(exports){
	// INPUT: a single line hash
	// OUTPUT: an array of matches
	// ERROR: an error is thrown if there are no matches
	exports.identifyHash = function(phash){
		//trim possible whitespace
		phash = phash.trim();
		//set regex and algorithms
		var hash_arr = [
			{regex: /^[a-f0-9]{4}$/, hashes: ["CRC-16","CRC-16-CCITT","FCS-16"]},
			{regex: /^[a-f0-9]{8}$/, hashes: ["Adler-32","CRC-32","CRC-32B","FCS-32","GHash-32-3","GHash-32-5","FNV-132","Fletcher-32","Joaat","ELF-32","XOR-32"]},
			{regex: /^\+[a-z0-9\/\.]{12}$/, hashes: ["Blowfish(Eggdrop)",]},
			{regex: /^[a-z0-9\/\.]{13}$/, hashes: ["DES(Unix)","Traditional DES","DEScrypt"]},
			{regex: /^[a-f0-9]{16}$/, hashes: ["MySQL323","DES(Oracle)","VNC","Half MD5","Oracle 7-10g","FNV-164","CRC-64"]},
			{regex: /^[a-z0-9\/\.]{16}$/, hashes: ["Cisco-PIX(MD5)",]},
			{regex: /^\([a-z0-9\+\/]{20}\)$/, hashes: ["Lotus Domino",]},
			{regex: /^_[a-z0-9\/\.]{19}$/, hashes: ["BSDi Crypt",]},
			{regex: /^[a-f0-9]{24}$/, hashes: ["CRC-96(ZIP)",]},
			{regex: /^[a-z0-9\/\.]{24}$/, hashes: ["Crypt16",]},
			{regex: /^[0-9a-f]{32}$/, hashes: ["MD5","MD4","MD2","NTLM","LM","RAdmin v2.x","RIPEMD-128","Haval-128","Tiger-128","Snefru-128","MD5(ZipMonster)","Skein-256(128)","Skein-512(128)"]},
			{regex: /^{SHA}[a-z0-9\/\+]{27}=$/, hashes: ["SHA-1(Base64)","Netscape LDAP SHA"]},
			{regex: /^\$1\$[a-z0-9\/\.]{0,8}\$[a-z0-9\/\.]{22}$/, hashes: ["MD5(Unix)","Cisco-IOS(MD5)","FreeBSD MD5"]},
			{regex: /^0x[a-f0-9]{32}$/, hashes: ["Lineage II C4",]}, 
			{regex: /^\$H\$[a-z0-9\/\.]{31}$/, hashes: ["MD5(phpBB3)",]},
			{regex: /^\$P\$[a-z0-9\/\.]{31}$/, hashes: ["MD5(Wordpress)","PHPass' Portable Hash"]},
			{regex: /^[a-f0-9]{32}:[a-z0-9]{2}$/, hashes: ["osCommerce","xt:Commerce"]},
			{regex: /^\$apr1\$.{0,8}\$[a-z0-9\/\.]{22}$/, hashes: ["MD5(APR)","Apache MD5"]},
			{regex: /^{smd5}.{31}$/, hashes: ["AIX(smd5)",]},
			{regex: /^[a-f0-9]{32}:[0-9]{4}$/, hashes: ["WebEdition CMS",]},
			{regex: /^[a-f0-9]{32}:.{5}$/, hashes: ["IP.Board v2+","MyBB v1.2+"]},
			{regex: /^[a-z0-9]{34}$/, hashes: ["CryptoCurrency(Adress)",]},
			{regex: /^[a-f0-9]{40}$/, hashes: ["SHA-1","RIPEMD-160","Haval-160","SHA-1(MaNGOS)","SHA-1(MaNGOS2)","Tiger-160","HAS-160","Skein-256(160)","Skein-512(160)"]},
			{regex: /^\*[a-f0-9]{40}$/, hashes: ["MySQL5.x","MySQL4.1"]},
			{regex: /^[a-z0-9]{43}$/, hashes: ["Cisco-IOS(SHA256)",]},
			{regex: /^[a-f-0-9]{32}:[^\\\/:*?\"\<\>\|]{1,15}$/, hashes: ["Domain Cached Credentials 2",]},
			{regex: /^{SSHA}[a-z0-9\+\/]{38}={0,2}$/, hashes: ["SSHA-1(Base64)","Netscape LDAP SSHA"]},
			{regex: /^[a-z0-9]{47}$/, hashes: ["FortiOS",]},
			{regex: /^[a-f0-9]{48}$/, hashes: ["Haval-192","Tiger-192","OSX v10.4","OSX v10.5","OSX v10.6"]},
			{regex: /^[a-f0-9]{51}$/, hashes: ["Palshop CMS",]},
			{regex: /^[a-z0-9]{51}$/, hashes: ["CryptoCurrency(PrivateKey)",]},
			{regex: /^{ssha1}[a-z0-9\.\$]{47}$/, hashes: ["AIX(ssha1)",]},
			{regex: /^0x0100[a-f0-9]{48}$/, hashes: ["MSSQL(2005)","MSSQL(2008)"]},
			{regex: /^\$md5,rounds=[0-9]+\$[a-z0-9\.\/]{0,8}(\$|\$\$)[a-z0-9\.\/]{22}$/, hashes: ["MD5(Sun)",]},
			{regex: /^[a-f0-9]{56}$/, hashes: ["SHA-224","Haval-224","Keccak-224","Skein-256(224)","Skein-512(224)"]},
			{regex: /^(\$2a|\$2y|\$2)\$[0-9]{0,2}?\$[a-z0-9\/\.]{53}$/, hashes: ["Blowfish(OpenBSD)",]},
			{regex: /^S:[a-f0-9]{60}$/, hashes: ["Oracle 11g",]},
			{regex: /^\$bcrypt-sha256\$.{5}\$[a-z0-9\/\.]{22}\$[a-z0-9\/\.]{31}$/, hashes: ["BCrypt(SHA256)",]},
			{regex: /^[a-f0-9]{32}:[a-z0-9]{30}$/, hashes: ["vBulletin >v3.8.5",]},
			{regex: /^[a-f0-9]{64}$/, hashes: ["SHA-256","RIPEMD-256","Haval-256","Snefru-256","GOST R 34.11-94","Keccak-256","Skein-256","Skein-512(256)"]},
			{regex: /^[a-f0-9]{32}:[a-z0-9]{32}$/, hashes: ["Joomla",]},
			{regex: /^[a-f-0-9]{32}:[a-f-0-9]{32}$/, hashes: ["SAM(LM_Hash:NT_Hash)",]},
			{regex: /^\$episerver\$\*0\*[a-z0-9=\*+]{52}$/, hashes: ["EPiServer 6.x <v4",]},
			{regex: /^{ssha256}[a-z0-9\.\$]{63}$/, hashes: ["AIX(ssha256)",]},
			{regex: /^[a-f0-9]{80}$/, hashes: ["RIPEMD-320",]},
			{regex: /^\$episerver\$\*1\*[a-z0-9=\*+]{68}$/, hashes: ["EPiServer 6.x >v4",]},
			{regex: /^0x0100[a-f0-9]{88}$/, hashes: ["MSSQL(2000)",]},
			{regex: /^[a-f0-9]{96}$/, hashes: ["SHA-384","Keccak-384","Skein-512(384)","Skein-1024(384)"]},
			{regex: /^{SSHA512}[a-z0-9\+\/]{96}={0,2}$/, hashes: ["SSHA-512(Base64)","LDAP(SSHA512)"]},
			{regex: /^{ssha512}[a-z0-9\.\$]{107}$/, hashes: ["AIX(ssha512)",]},
			{regex: /^[a-f0-9]{128}$/, hashes: ["SHA-512","Whirlpool","Salsa10","Salsa20","Keccak-512","Skein-512","Skein-1024(512)"]},
			{regex: /^[a-f0-9]{136}$/, hashes: ["OSX v10.7",]},
			{regex: /^0x0200[a-f0-9]{136}$/, hashes: ["MSSQL(2012)",]},
			{regex: /^\$ml\$.+$/, hashes: ["OSX v10.8",]},
			{regex: /^[a-f0-9]{256}$/, hashes: ["Skein-1024",]},
			{regex: /^grub\.pbkdf2\.sha512\..+$/, hashes: ["GRUB 2",]},
			{regex: /^sha1\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{40}$/, hashes: ["SHA-1(Django)",]},
			{regex: /^\$S\$[a-z0-9\/\.]{52}$/, hashes: ["SHA-512(Drupal)",]},
			{regex: /^\$5\$.{0,22}\$[a-z0-9\/\.]{43,69}$/, hashes: ["SHA-256(Unix)",]},
			{regex: /^\$6\$.{0,22}\$[a-z0-9\/\.]{86}$/, hashes: ["SHA-512(Unix)",]},
			{regex: /^\$sha\$[a-z0-9]{1,16}\$[a-f0-9]{64}$/, hashes: ["Minecraft(AuthMe Reloaded)",]},
			{regex: /^sha256\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{64}$/, hashes: ["SHA-256(Django)",]},
			{regex: /^sha384\$[a-z0-9\/\.]{1,12}\$[a-f0-9]{96}$/, hashes: ["SHA-384(Django)",]},
			{regex: /^[^\\\/:*?\"\<\>\|]{1,15}:[^\\\/:*?\"\<\>\|]{1,15}:[a-f0-9]{32}:[a-f0-9]{32}:{0,3}$/, hashes: ["Domain Cached Credentials",]},
			{regex: /^\$scram\$.+$/, hashes: ["SCRAM Hash",]}
		];
		for(var hash_id=0; hash_id < hash_arr.length; hash_id++){
			var curr_hash = hash_arr[hash_id];
			
			//try to find matches
			if (phash.match(curr_hash.regex)){
				return curr_hash.hashes;
			}
		}
		return new Error("Did not find any matches.");
	};
})(typeof exports === 'undefined'? this['hashID']={}: exports);
