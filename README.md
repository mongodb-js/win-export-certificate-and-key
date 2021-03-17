# win-export-certificate-and-key

Export a certificate and its corresponding private key from the Windows CA store.
This module is a native addon. It will only successfully work on Windows.
No prebuilt binaries are currently provided.

This module returns a single certificate (and by default its private key)
combination as a .pfx file, along with a random passphrase that has been
used for encrypting the file.
It will throw an exception if no relevant certificate could be found.
The certificate in question can be specified either through its subject line
string or its thumbprint.

## Testing

You need to import `testkeys\certificate.pfx` manually into your local 
CA store in order for the tests to pass. Make sure to import that certificate
with the "exportable private key" option. The password for the file is `pass`.
