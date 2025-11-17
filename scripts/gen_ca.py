"""Create Root CA (RSA + self-signed X.509) using cryptography."""
import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_ca(name: str, output_dir: str = "certs"):
    """Generate Root CA certificate and private key.

    Args:
        name: Common Name for the CA (e.g., "FAST-NU Root CA")
        output_dir: Directory to save the CA files
    """
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"[*] Generating Root CA: {name}")

    # Generate private key (2048-bit RSA)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    print("[+] Private key generated")

    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    # Certificate valid for 10 years
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), backend=default_backend())
    )
    print("[+] CA certificate generated")

    # Save private key
    private_key_path = output_path / "ca_key.pem"
    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print(f"[+] CA private key saved to: {private_key_path}")

    # Save certificate
    cert_path = output_path / "ca_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] CA certificate saved to: {cert_path}")

    print(f"\n[✓] Root CA '{name}' created successfully!")
    print(f"    Certificate: {cert_path}")
    print(f"    Private Key: {private_key_path}")
    print(f"\n[!] Keep ca_key.pem secret and never commit it to version control!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Root CA certificate")
    parser.add_argument("--name", default="FAST-NU Root CA",
                        help="Common Name for the CA")
    parser.add_argument("--out-dir", default="certs",
                        help="Output directory for CA files")

    args = parser.parse_args()
    generate_ca(args.name, args.out_dir)
