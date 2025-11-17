"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""
import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def issue_certificate(
    cn: str,
    output_prefix: str,
    ca_cert_path: str = "certs/ca_cert.pem",
    ca_key_path: str = "certs/ca_key.pem"
):
    """Issue a certificate signed by the CA.

    Args:
        cn: Common Name for the certificate (e.g., "server.local", "client.local")
        output_prefix: Prefix for output files (e.g., "certs/server" -> server_cert.pem, server_key.pem)
        ca_cert_path: Path to CA certificate
        ca_key_path: Path to CA private key
    """
    print(f"[*] Issuing certificate for: {cn}")

    # Load CA certificate and private key
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    print("[+] CA certificate and key loaded")

    # Generate private key for this certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    print("[+] Private key generated")

    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    # Certificate valid for 1 year
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_private_key, hashes.SHA256(), backend=default_backend())
    )
    print("[+] Certificate generated and signed by CA")

    # Create output directory if needed
    output_path = Path(output_prefix).parent
    output_path.mkdir(parents=True, exist_ok=True)

    # Save private key
    key_file = f"{output_prefix}_key.pem"
    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print(f"[+] Private key saved to: {key_file}")

    # Save certificate
    cert_file = f"{output_prefix}_cert.pem"
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Certificate saved to: {cert_file}")

    print(f"\n[✓] Certificate for '{cn}' issued successfully!")
    print(f"    Certificate: {cert_file}")
    print(f"    Private Key: {key_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Issue certificate signed by CA")
    parser.add_argument("--cn", required=True,
                        help="Common Name (e.g., server.local, client.local)")
    parser.add_argument("--out", required=True,
                        help="Output prefix (e.g., certs/server)")
    parser.add_argument("--ca-cert", default="certs/ca_cert.pem",
                        help="Path to CA certificate")
    parser.add_argument("--ca-key", default="certs/ca_key.pem",
                        help="Path to CA private key")

    args = parser.parse_args()
    issue_certificate(args.cn, args.out, args.ca_cert, args.ca_key)
