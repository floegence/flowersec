# Native v4 leaf-DER pin fixtures

`v4_pin_key.pem` is a public, test-only P-256 private key. The matching certificates
start at Unix time zero for the tests' independent trusted-time source. Their
`pin-only.test` common name differs from the signed `localhost` route, and they
have no Subject Alternative Name. Successful pin tests therefore exercise the
actual leaf-DER SHA-256 policy without PKI or hostname acceptance.

- `v4_pin_cert.pem`: seven-day certificate with digital-signature key usage and
  server-authentication extended key usage.
- `v4_pin_long_cert.pem`: fifteen-day certificate, exceeding the full-certificate
  fourteen-day profile limit despite its shorter signed pin window.
- `v4_pin_client_cert.pem`: client-authentication-only extended key usage.
- `v4_pin_critical_cert.pem`: unsupported critical extension.

The certificates are intentionally expired in wall-clock time. Pin verification
uses the independently configured trusted interval and the certificate's actual
DER validity bounds; these fixtures must never be used outside tests.
