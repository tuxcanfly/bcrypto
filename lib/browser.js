const rsa = require('../lib/rsa');
const SHA256 = require('../lib/sha256');

function sign(msg, pk) {
  const msg = SHA256.digest(Buffer.from(msg))
  const priv = bcrypto.ssh.SSHPrivateKey.fromString(pk);
  const pk = rsa.privateKeyImport(priv);
  return rsa.sign('SHA256', msg, pk).toString('hex');
}

function verify(msg, pk, sig) {
  const msg = bcrypto.SHA256.digest(Buffer.from(msg))
  const sig = Buffer.from(sig, 'hex');
  const pub = bcrypto.ssh.SSHPublicKey.fromString(pk)
  const pk = bcrypto.rsa.publicKeyImport(pub)
  return bcrypto.rsa.verify('SHA256', msg, sig, pk);
}

exports.verify = verify;
exports.sign = sign;
