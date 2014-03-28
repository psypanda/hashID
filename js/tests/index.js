var hashID = require('../hashid');

exports.BCryptSHA256 = function(test){
	test.expect(1);
	var result = hashID.identifyHash("$bcrypt-sha256$2a,12$LrmaIX5x4TRtAwEfwJZa1.$2ehnw6LvuIUTM0iz4iz9hTxv21B6KFO");
	test.deepEqual(result, [ 'BCrypt(SHA-256)' ]);
	test.done();
};

exports.CiscoASAMD5 = function(test){
	test.expect(1);
	var result = hashID.identifyHash("02dMBMYkTdC5Ziyp:36");
	test.deepEqual(result, [ 'Cisco-ASA(MD5)' ]);
	test.done();
};

exports.Crypt16 = function(test){
	test.expect(1);
	var result = hashID.identifyHash("aaX/UmCcBrceQ0kQGGWKTbuE");
	test.deepEqual(result, [ 'Crypt16' ]);
	test.done();
};

exports.MD5Test = function(test){
	test.expect(1);
	var result = hashID.identifyHash("93199cd62bae9138b685b5e1deadd644");
	test.deepEqual(result,[ 'MD5','MD4','MD2','Double MD5','NTLM','LM','RAdmin v2.x','RIPEMD-128','Haval-128','Tiger-128','Snefru-128','ZipMonster','Skein-256(128)','Skein-512(128)','Domain Cached Credentials','mscash','Domain Cached Credentials 2','mscash2','DNSSEC(NSEC3)' ]);
	test.done();
};

exports.SHA256Test = function(test){
	test.expect(1);
	var result = hashID.identifyHash("814769e3e24d441703fb45742970bebd1f02dd09bee26589c4f07f7c0d116f06");
	test.deepEqual(result, ['SHA-256','RIPEMD-256','Haval-256','Snefru-256','GOST R 34.11-94','SHA3-256','Skein-256','Skein-512(256)','Ventrilo' ]);
	test.done();
};

exports.SHA512Test = function(test){
	test.expect(1);
	var result = hashID.identifyHash("7485d0d50c74a5d979c0ec093e77524360b1e1eb0423f9fea1e2ffdf6acc2702d1f4c82d0eec70153ff7aa8573f1ea5d51cde7e6468264ee1c785e0485be7908");
	test.deepEqual(result, ['SHA-512','Whirlpool','Salsa10','Salsa20','SHA3-512','Skein-512','Skein-1024(512)']);
	test.done();
};
