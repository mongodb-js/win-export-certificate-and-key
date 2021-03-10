const tls = require('tls');
const fs = require('fs');
const assert = require('assert');
const exportCertificate = require('./');

describe('exportCertificate', () => {
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

  it('throws when no cert can be found', () => {
    assert.throws(() => {
      exportCertificate({ subject: 'Banana Corp '});
    }, /CertFindCertificateInStore\(\) failed with: Cannot find object or property. \(0x80092004\)/);
  });

  it('loads a certificate based on its thumbprint', async() => {
    const { passphrase, pfx } = exportCertificate({
      thumbprint: Buffer.from('d755afda2bbad2509d39eca5968553b9103305af', 'hex')
    });
    tls.connect({ ...tlsServerConnectOptions, passphrase, pfx });
    assert.strictEqual(await authorized, true);
  });

  it('loads a certificate based on its subject', async() => {
    const { passphrase, pfx } = exportCertificate({
      subject: 'Internet Widgits Pty Ltd'
    });
    tls.connect({ ...tlsServerConnectOptions, passphrase, pfx });
    assert.strictEqual(await authorized, true);
  });
});