'use strict';
const {
  exportCertificateAndKey,
  exportAllCertificates,
  storeTypes
} = require('bindings')('win_export_cert');
const { randomBytes } = require('crypto');
const util = require('util');

const DEFAULT_STORE_TYPE_LIST = ['CERT_SYSTEM_STORE_LOCAL_MACHINE', 'CERT_SYSTEM_STORE_CURRENT_USER'];

function validateStoreTypeList(storeTypeList) {
  storeTypeList = storeTypeList || DEFAULT_STORE_TYPE_LIST;
  if (!Array.isArray(storeTypeList) ||
      storeTypeList.length < 1 ||
      !storeTypeList.every(st => typeof st === 'number' || Object.keys(storeTypes).includes(st))) {
    throw new Error(`storeTypeList needs to be an array of valid store types`);
  }
  return storeTypeList.map(st => typeof st === 'number' ? st : storeTypes[st]);
}

function exportSystemCertificates(opts = {}) {
  let {
    store,
    storeTypeList
  } = opts;
  storeTypeList = validateStoreTypeList(storeTypeList);

  const result = new Set();
  for (const storeType of storeTypeList) {
    for (const cert of exportAllCertificates(store || 'ROOT', storeType)) {
      result.add(cert);
    }
  }

  return [...result];
}

function exportCertificateAndPrivateKey(opts = {}) {
  let {
    subject,
    thumbprint,
    store,
    storeTypeList,
    requirePrivKey
  } = opts;
  storeTypeList = validateStoreTypeList(storeTypeList);

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
  const pfx = exportCertificateAndKey(
    passphrase,
    store || 'MY',
    storeTypeList[0],
    subject ? { subject } : { thumbprint },
    requirePrivKey);
  return { passphrase, pfx };
}

module.exports = exportCertificateAndPrivateKey;
module.exports.exportCertificateAndPrivateKey = exportCertificateAndPrivateKey;
module.exports.exportSystemCertificates = exportSystemCertificates;