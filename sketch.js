var fs = require('fs');
var bignum = require('bignum');
var assert = require('assert');
//http://lapo.it/asn1js is awesome


var offset;
var size;

var public_buffer = new Buffer(fs.readFileSync('./id_rsa.pub', 'ascii').split(' ')[1], 'base64');
var public_key = {};
offset = 0;
size = public_buffer.readInt32BE(offset);
offset += 4;
public_key.algorithm = public_buffer.toString('ascii', offset, offset += size);
size = public_buffer.readInt32BE(offset);
offset += 4;
public_key.exponent = bignum.fromBuffer(public_buffer.slice(offset, offset += size));
size = public_buffer.readInt32BE(offset);
offset += 4;
public_key.modulus = bignum.fromBuffer(public_buffer.slice(offset, offset += size));

console.log("\n\npublic_key\n===========");
console.log("\n\npublic_key.algorithm:\n===========\n" + public_key.algorithm);
console.log("\n\npublic_key.exponeent:\n===========\n" + public_key.exponent);
console.log("\n\npublic_key.modulus:\n===========\n" + public_key.modulus);
console.log("\n\n");






function read_ber_size() {
    var size = private_buffer.readInt8(offset++);
    if (size & 0x80) {
        return bignum.fromBuffer(private_buffer.slice(offset, offset += size & 0x7f)).toNumber();
    } else {
        return size;
    }
}
var private_buffer = new Buffer(fs.readFileSync('./id_rsa', 'ascii').split('\n').slice(1, -2).join(''), 'base64');
var private_key = {};
offset = 0;
assert.ok(private_buffer.readInt8(offset++) === 0x30, "should start with a sequence");
read_ber_size(); //we don't care, let's just advance offset
var values = [];
while (offset < private_buffer.length) {
    assert.ok(private_buffer.readInt8(offset++) === 2, "should contain only integers");
    size = read_ber_size();
    values.push(bignum.fromBuffer(private_buffer.slice(offset, offset += size)));
}
var sequence = ["zero", "modulus", "publicExponent", "privateExponent", "prime1", "prime2", "exponent1", "exponent2", "coefficient"];
console.log("\n\nprivate_key\n-----------");
for (var i = 1; i < values.length; i++) {
    console.log("\n\nprivate_key." + sequence[i] + "\n------------\n" +  values[i]);
    private_key[sequence[i]] = values[i];
}
console.log("\n\n");

