'use strict';
const tls = require('tls');
const fs = require('fs');
const assert = require('assert');
const {
  exportCertificateAndPrivateKey,
  exportCertificateAndPrivateKeyAsync,
  exportSystemCertificates,
  exportSystemCertificatesAsync,
 } = require('./');

describe('exportCertificateAndPrivateKey', () => {
  let tlsServer;
  let authorized;
  let resolveAuthorized;
  let tlsServerConnectOptions;
  before((done) => {
    const serverOpts = {
      key: fs.readFileSync(__dirname + '/testkeys/testserver-privkey.pem'),
      cert: fs.readFileSync(__dirname + '/testkeys/testserver-certificate.pem'),
      requestCert: true,
      ca: [fs.readFileSync(__dirname + '/testkeys/certificate.pem')]
    };
    tlsServer = tls.createServer(serverOpts, (socket) => {
      resolveAuthorized(socket.authorized);
      socket.end();
    });
    tlsServer.listen(0, () => {
      tlsServerConnectOptions = {
        host: 'localhost',
        port: tlsServer.address().port,
        rejectUnauthorized: false
      };
      done();
    });
  })
  beforeEach(() => {
    authorized = new Promise(resolve => resolveAuthorized = resolve);
  });
  after(() => {
    tlsServer.close();
  });

  for (const method of ['sync', 'async']) {
    const fn = {
      sync: exportCertificateAndPrivateKey,
      async: exportCertificateAndPrivateKeyAsync
    }[method];
    context(method, () => {
      it('throws when no cert can be found', async() => {
        await assert.rejects(async() => {
          await fn({ subject: 'Banana Corp '});
        }, /CertFindCertificateInStore\(\) failed with: Cannot find object or property. \(0x80092004\)/);
      });

      it('loads a certificate based on its thumbprint', async() => {
        const { passphrase, pfx } = await fn({
          thumbprint: Buffer.from('0b9f37b43c687da49dd51a1f2385652808fd5585', 'hex')
        });
        tls.connect({ ...tlsServerConnectOptions, passphrase, pfx });
        assert.strictEqual(await authorized, true);
      });

      it('loads a certificate based on its subject', async() => {
        const { passphrase, pfx } = await fn({
          subject: 'Internet Widgits Pty Ltd'
        });
        tls.connect({ ...tlsServerConnectOptions, passphrase, pfx });
        assert.strictEqual(await authorized, true);
      });
    });
  }
});

describe('exportSystemCertificates', () => {
  for (const method of ['sync', 'async']) {
    const fn = {
      sync: exportSystemCertificates,
      async: exportSystemCertificatesAsync
    }[method];
    context(method, () => {
      it('exports certificates from the ROOT store as .pem', async() => {
        const certs = await fn({ store: 'ROOT' });
        assert.notStrictEqual(certs.length, 0);
        for (const cert of certs) {
          assert.match(cert.trim(), /^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/);
        }
      });

      it('exports certificates from the CA store as .pem', async() => {
        const certs = await fn({ store: 'CA' });
        assert.notStrictEqual(certs.length, 0);
        for (const cert of certs) {
          assert.match(cert.trim(), /^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/);
        }
      });
    });
  }
});
