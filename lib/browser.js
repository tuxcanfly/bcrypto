const rsa = require('../lib/rsa');
const SHA256 = require('../lib/sha256');

function sign(msg, privkey) {
  const hash = SHA256.digest(Buffer.from(msg))
  const ssh = bcrypto.ssh.SSHPrivateKey.fromString(privkey);
  const pk = rsa.privateKeyImport(ssh);
  return rsa.sign('SHA256', hash, pk).toString('hex');
}

function verify(msg, pubkey, signature) {
  const hash = bcrypto.SHA256.digest(Buffer.from(msg))
  const sig = Buffer.from(signature, 'hex');
  const ssh = bcrypto.ssh.SSHPublicKey.fromString(pubkey)
  const pk = bcrypto.rsa.publicKeyImport(ssh)
  return bcrypto.rsa.verify('SHA256', hash, sig, pk);
}

exports.verify = verify;
exports.sign = sign;
