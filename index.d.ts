declare function exportCertificateAndPrivateKey(input: {
  subject: string;
  store?: string;
  requirePrivKey?: boolean;
} | {
  thumbprint: Uint8Array;
  store?: string;
  requirePrivKey?: boolean;
}): { passphrase: string; pfx: Uint8Array; };
export = exportCertificateAndPrivateKey;