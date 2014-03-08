var hashID = require('../hashid');
exports.MD5Test = function(test){
	test.expect(1);
	var result = hashID.identifyHash("93199cd62bae9138b685b5e1deadd644");
	test.deepEqual(result, ['MD5','MD4','MD2','NTLM','LM','RAdmin v2.x','RIPEMD-128','Haval-128','Tiger-128','Snefru-128','MD5(ZipMonster)','Skein-256(128)','Skein-512(128)']);
	test.done();
};
exports.SHA256Test = function(test){
	test.expect(1);
	var result = hashID.identifyHash("814769e3e24d441703fb45742970bebd1f02dd09bee26589c4f07f7c0d116f06");
	test.deepEqual(result, ['SHA-256','RIPEMD-256','Haval-256','Snefru-256','GOST R 34.11-94','Keccak-256','Skein-256','Skein-512(256)' ]);
	test.done();
};
exports.SHA512Test = function(test){
	test.expect(1);
	var result = hashID.identifyHash("7485d0d50c74a5d979c0ec093e77524360b1e1eb0423f9fea1e2ffdf6acc2702d1f4c82d0eec70153ff7aa8573f1ea5d51cde7e6468264ee1c785e0485be7908");
	test.deepEqual(result, ['SHA-512','Whirlpool','Salsa10','Salsa20','Keccak-512','Skein-512','Skein-1024(512)']);
	test.done();
};
