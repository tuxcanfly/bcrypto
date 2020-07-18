const rsa = require('../lib/rsa');
const ssh = require('../lib/ssh');
const SHA256 = require('../lib/sha256');

function sign(msg, privkey) {
  const hash = SHA256.digest(Buffer.from(msg))
  const key = ssh.SSHPrivateKey.fromString(privkey);
  const pk = rsa.privateKeyImport(key);
  return rsa.sign('SHA256', hash, pk).toString('hex');
}

function verify(msg, pubkey, signature) {
  const hash = SHA256.digest(Buffer.from(msg))
  const sig = Buffer.from(signature, 'hex');
  const key = ssh.SSHPublicKey.fromString(pubkey)
  const pk = rsa.publicKeyImport(key)
  return rsa.verify('SHA256', hash, sig, pk);
}

function valid(privkey) {
  var ok = false;
  const key = ssh.SSHPrivateKey.fromString(privkey);
  try {
    rsa.privateKeyBits(key);
    ok = true;
  } catch (e) {
  }
  return ok;
}

exports.verify = verify;
exports.sign = sign;
exports.valid = valid;
