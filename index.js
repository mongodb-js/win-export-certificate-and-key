const { exportCertificate, storeTypes } = require('bindings')('win_export_cert');
const { randomBytes } = require('crypto');
const util = require('util');

function exportCertificateAndPrivateKey(opts = {}) {
  let {
    subject,
    thumbprint,
    store,
    storeTypeList,
    requirePrivKey
  } = opts;
  storeTypeList = storeTypeList || ['CERT_SYSTEM_STORE_LOCAL_MACHINE', 'CERT_SYSTEM_STORE_CURRENT_USER'];
  if (!Array.isArray(storeTypeList) ||
      storeTypeList.length < 1 ||
      !storeTypeList.every(st => typeof st === 'number' || Object.keys(storeTypes).includes(st))) {
    throw new Error(`storeTypeList needs to be an array of valid store types`);
  }
  if (storeTypeList.length !== 1) {
    let err;
    for (const storeType of storeTypeList) {
      try {
        return exportCertificateAndPrivateKey({ ...opts, storeTypeList: [storeType] });
      } catch(err_) {
        err = err_;
      }
    }
    throw err;
  }

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
    typeof storeTypeList[0] === 'number' ? storeTypeList[0] : storeTypes[storeTypeList[0]],
    subject ? { subject } : { thumbprint },
    requirePrivKey);
  return { passphrase, pfx };
}

module.exports = exportCertificateAndPrivateKey;