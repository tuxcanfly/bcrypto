const rsa = require('../lib/rsa');
const encoding = require('../lib/encoding');
const SHA256 = require('../lib/sha256');

function verify(msg, pk, sig) {
  msg = SHA256.digest(Buffer.from(msg))
  sig = Buffer.from(sig, 'hex');
  pub = encoding.pkcs1.RSAPublicKey.fromPEM(pk)
  key = rsa.publicKeyExport(pub.toRaw());
  pk = rsa.publicKeyImport(key)
  return rsa.verify('SHA256', msg, sig, pk);
}

module.exports = verify;
