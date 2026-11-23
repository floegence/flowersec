import { createPrivateKey, createPublicKey, X509Certificate } from "node:crypto";

// Static test-only P-256 material keeps browser parity hermetic and is never
// exposed by a production package entrypoint.
const TEST_CERT_DER_B64 =
  "MIIB0DCCAXWgAwIBAgIUN1vflbzlJfrU4ZKED+4S+7sCtiYwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgxNDAyNDM0MloXDTM2MDgxMTAyNDM0MlowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEajwb7qy6VxUFH+WjP/RG8LabjthsjlqZweN2NAkwClGhWdp5XI5HEsP7p5pOpYjjD4kLsvjnBISRRf0CJIW2GKOBpDCBoTAdBgNVHQ4EFgQUe4BGlwqmqkqzEKuW7ACsFr6Dk4YwHwYDVR0jBBgwFoAUe4BGlwqmqkqzEKuW7ACsFr6Dk4YwLAYDVR0RBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoGCCqGSM49BAMCA0kAMEYCIQCYzxx1Zev7TI4aHaXKrj7uV4F8wkJ2kEJtogyGlMJOFwIhAOAEs50N+UKa+0B9JK6xRACX82a6bFBZCY+H9nUKikV9";
const TEST_KEY_DER_B64 =
  "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGw0KRCu5rtYpQtqfTVTSz97sUToj2S3UhuA/cxsDa5KhRANCAARqPBvurLpXFQUf5aM/9EbwtpuO2GyOWpnB43Y0CTAKUaFZ2nlcjkcSw/unmk6liOMPiQuy+OcEhJFF/QIkhbYY";

export type TLSFixture = Readonly<{
  tls: Readonly<{
    certificate_chain_pem: string;
    private_key_pem: string;
    root_certificate_pem: string;
    root_certificate_der_base64: string;
    leaf_certificate_der_base64: string;
  }>;
}>;

export function fixture(): TLSFixture {
  const certificate = pem("CERTIFICATE", TEST_CERT_DER_B64);
  const privateKey = pem("PRIVATE KEY", TEST_KEY_DER_B64);
  validateTestTLSFixture(certificate, privateKey);
  return {
    tls: {
      certificate_chain_pem: certificate,
      private_key_pem: privateKey,
      root_certificate_pem: certificate,
      root_certificate_der_base64: TEST_CERT_DER_B64,
      leaf_certificate_der_base64: TEST_CERT_DER_B64,
    },
  };
}

function validateTestTLSFixture(certificatePEM: string, privateKeyPEM: string): void {
  const certificate = new X509Certificate(certificatePEM);
  const validFrom = Date.parse(certificate.validFrom);
  const validTo = Date.parse(certificate.validTo);
  const maximumValidityMs = 11 * 366 * 24 * 60 * 60 * 1_000;
  const certificatePublicKey = certificate.publicKey.export({ type: "spki", format: "der" });
  const privateKeyPublicKey = createPublicKey(createPrivateKey(privateKeyPEM)).export({ type: "spki", format: "der" });
  if (
    certificate.ca ||
    certificate.publicKey.asymmetricKeyType !== "ec" ||
    certificate.publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1" ||
    certificate.checkHost("localhost") !== "localhost" ||
    certificate.checkIP("127.0.0.1") !== "127.0.0.1" ||
    certificate.checkIP("::1") !== "::1" ||
    !certificate.keyUsage.includes("1.3.6.1.5.5.7.3.1") ||
    !Number.isFinite(validFrom) ||
    !Number.isFinite(validTo) ||
    Date.now() < validFrom ||
    Date.now() >= validTo ||
    validTo - validFrom > maximumValidityMs ||
    !certificatePublicKey.equals(privateKeyPublicKey)
  ) {
    throw new Error("browser parity TLS fixture is invalid");
  }
}

function pem(label: string, encoded: string): string {
  const lines = encoded.match(/.{1,64}/g);
  if (lines === null) throw new Error("invalid embedded TLS fixture");
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

