const rsa = require('../lib/rsa');
const encoding = require('../lib/encoding');
const SHA256 = require('../lib/sha256');

function sign(msg, pk) {
  msg = SHA256.digest(Buffer.from(msg))
  priv = encoding.pkcs1.RSAPrivateKey.fromPEM(pk);
  key = rsa.privateKeyExport(priv.toRaw());
  pk = rsa.privateKeyImport(key);
  return rsa.sign('SHA256', msg, pk).toString('hex');
}

function verify(msg, pk, sig) {
  msg = bcrypto.SHA256.digest(Buffer.from(msg))
  sig = Buffer.from(sig, 'hex');
  pub = bcrypto.ssh.SSHPublicKey.fromString(pk)
  pk = bcrypto.rsa.publicKeyImport({'n': pub.n, 'e': pub.e})
  return bcrypto.rsa.verify('SHA256', msg, sig, pk);
}

exports.verify = verify;
exports.sign = sign;
