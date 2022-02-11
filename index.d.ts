declare type StoreType =
  'CERT_SYSTEM_STORE_CURRENT_SERVICE' |
  'CERT_SYSTEM_STORE_CURRENT_USER' |
  'CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY' |
  'CERT_SYSTEM_STORE_LOCAL_MACHINE' |
  'CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE' |
  'CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY' |
  'CERT_SYSTEM_STORE_SERVICES' |
  'CERT_SYSTEM_STORE_USERS';

declare function exportCertificateAndPrivateKey(input: {
  subject: string;
  store?: string;
  storeTypeList?: Array<StoreType | number>;
  requirePrivKey?: boolean;
} | {
  thumbprint: Uint8Array;
  store?: string;
  requirePrivKey?: boolean;
}): { passphrase: string; pfx: Uint8Array; };
export = exportCertificateAndPrivateKey;