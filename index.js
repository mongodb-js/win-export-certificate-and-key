'use strict';
const {
  exportCertificateAndKey,
  exportCertificateAndKeyAsync,
  exportAllCertificates,
  exportAllCertificatesAsync,
  storeTypes
} = require('bindings')('win_export_cert');
const { randomBytes, X509Certificate } = require('crypto');
const util = require('util');
const { promisify } = util;

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

function addExportedCertificatesToSet(set, list) {
  for (const cert of list) {
    // X509Certificate was added in Node.js 15 and accepts DER as input, but .toString() returns PEM
    set.add(new X509Certificate(cert).toString());
  }
}

function exportSystemCertificates({
  store,
  storeTypeList
} = {}) {
  storeTypeList = validateStoreTypeList(storeTypeList);

  const result = new Set();
  for (const storeType of storeTypeList) {
    addExportedCertificatesToSet(result, exportAllCertificates(store || 'ROOT', storeType));
  }

  return [...result];
}

async function exportSystemCertificatesAsync({
  store,
  storeTypeList
} = {}) {
  storeTypeList = validateStoreTypeList(storeTypeList);

  const result = new Set();
  for (const storeType of storeTypeList) {
    addExportedCertificatesToSet(result, await promisify(exportAllCertificatesAsync)(store || 'ROOT', storeType));
  }

  return [...result];
}

function validateSubjectAndThumbprint(subject, thumbprint) {
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

  validateSubjectAndThumbprint(subject, thumbprint);
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

async function exportCertificateAndPrivateKeyAsync(opts = {}) {
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
        return await exportCertificateAndPrivateKeyAsync({ ...opts, storeTypeList: [storeType] });
      } catch(err_) {
        err = err_;
      }
    }
    throw err;
  }

  validateSubjectAndThumbprint(subject, thumbprint);
  requirePrivKey = requirePrivKey !== false;
  const passphrase = (await promisify(randomBytes)(12)).toString('hex');
  const pfx = await promisify(exportCertificateAndKeyAsync)(
    passphrase,
    store || 'MY',
    storeTypeList[0],
    subject ? { subject } : { thumbprint },
    requirePrivKey);
  return { passphrase, pfx };
}

module.exports = exportCertificateAndPrivateKey;
module.exports.exportCertificateAndPrivateKey = exportCertificateAndPrivateKey;
module.exports.exportCertificateAndPrivateKeyAsync = exportCertificateAndPrivateKeyAsync;
module.exports.exportSystemCertificates = exportSystemCertificates;
module.exports.exportSystemCertificatesAsync = exportSystemCertificatesAsync;