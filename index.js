const { exportCertificate } = require('bindings')('win_export_cert');
const { randomBytes } = require('crypto');
const util = require('util');

module.exports = function exportCertificateAndPrivateKey({
  subject,
  thumbprint,
  store,
  requirePrivKey
} = {}) {
  if (!subject && !thumbprint) {
    throw new Error('Need to specify either `subject` or `thumbprint`');
  }
  if (subject && thumbprint) {
    throw new Error('Cannot specify both `subject` and `thumbprint`');
  }
  if (subject && typeof subject !== 'string') {
    throw new Error('`subject` needs to be a string');
  }
  if (thumbprint && !util.types.isUint8Array(thumbprint)) {
    throw new Error('`thumbprint` needs to be a Uint8Array');
  }
  requirePrivKey = requirePrivKey !== false;
  const passphrase = randomBytes(12).toString('hex');
  const pfx = exportCertificate(
    passphrase,
    store || 'MY', 
    subject ? { subject } : { thumbprint },
    requirePrivKey);
  return { passphrase, pfx };
}