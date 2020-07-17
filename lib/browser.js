const rsa = require('../lib/rsa');
const encoding = require('../lib/encoding');
const SHA256 = require('../lib/sha256');

function sign(msg, pk) {
  msg = SHA256.digest(Buffer.from(msg))
  priv = encoding.pkcs1.RSAPrivateKey.fromPEM(pk);
  key = rsa.privateKeyExport(priv.toRaw());
  pk = rsa.privateKeyImport(key);
  return rsa.sign('SHA256', msg, pk);
}

function verify(msg, pk, sig) {
  msg = SHA256.digest(Buffer.from(msg))
  sig = Buffer.from(sig, 'hex');
  pub = encoding.pkcs1.RSAPublicKey.fromPEM(pk)
  key = rsa.publicKeyExport(pub.toRaw());
  pk = rsa.publicKeyImport(key)
  return rsa.verify('SHA256', msg, sig, pk);
}

module.exports = verify;
module.exports = sign;
