"""X.509 validation: signed-by-CA, validity window, CN/SAN."""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime, timezone
import hashlib

class CertificateValidationError(Exception):
    """Exception raised when certificate validation fails."""
    pass

def load_certificate(cert_pem: str):
    """Load X.509 certificate from PEM string.

    Args:
        cert_pem: Certificate in PEM format

    Returns:
        X.509 certificate object
    """
    return x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

def load_certificate_from_file(filepath: str):
    """Load X.509 certificate from file.

    Args:
        filepath: Path to certificate file

    Returns:
        X.509 certificate object
    """
    with open(filepath, 'r') as f:
        cert_pem = f.read()
    return load_certificate(cert_pem)

def verify_certificate(cert_pem: str, ca_cert_pem: str, expected_cn: str = None) -> bool:
    """Verify X.509 certificate against CA.

    Checks:
    1. Signature chain validity (signed by trusted CA)
    2. Validity period (not expired, not before valid)
    3. Common Name (CN) or SAN match (if expected_cn provided)

    Args:
        cert_pem: Certificate to verify (PEM format)
        ca_cert_pem: CA certificate (PEM format)
        expected_cn: Expected Common Name or DNS name (optional)

    Returns:
        True if certificate is valid

    Raises:
        CertificateValidationError: If validation fails
    """
    try:
        # Load certificates
        cert = load_certificate(cert_pem)
        ca_cert = load_certificate(ca_cert_pem)

        # Check 1: Verify signature chain (cert signed by CA)
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_parameters
            )
        except Exception as e:
            raise CertificateValidationError(f"Certificate signature verification failed: {e}")

        # Check 2: Verify validity period
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc:
            raise CertificateValidationError(
                f"Certificate not yet valid (valid from {cert.not_valid_before_utc})"
            )
        if now > cert.not_valid_after_utc:
            raise CertificateValidationError(
                f"Certificate expired (expired on {cert.not_valid_after_utc})"
            )

        # Check 3: Verify Common Name or SAN (if expected_cn provided)
        if expected_cn:
            # Check CN in subject
            cn_found = False
            try:
                cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attr:
                    cn = cn_attr[0].value
                    if cn == expected_cn:
                        cn_found = True
            except Exception:
                pass

            # Check Subject Alternative Names (SAN)
            san_found = False
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_names = san_ext.value.get_values_for_type(x509.DNSName)
                if expected_cn in san_names:
                    san_found = True
            except Exception:
                pass

            if not (cn_found or san_found):
                raise CertificateValidationError(
                    f"Certificate CN/SAN does not match expected '{expected_cn}'"
                )

        return True

    except CertificateValidationError:
        raise
    except Exception as e:
        raise CertificateValidationError(f"Certificate validation error: {e}")

def get_certificate_fingerprint(cert_pem: str) -> str:
    """Compute SHA-256 fingerprint of certificate.

    Args:
        cert_pem: Certificate in PEM format

    Returns:
        Hex string of SHA-256 fingerprint
    """
    cert = load_certificate(cert_pem)
    fingerprint = hashlib.sha256(cert.public_bytes(
        encoding=serialization.Encoding.DER
    )).hexdigest()
    return fingerprint

def get_certificate_cn(cert_pem: str) -> str:
    """Extract Common Name from certificate.

    Args:
        cert_pem: Certificate in PEM format

    Returns:
        Common Name string
    """
    cert = load_certificate(cert_pem)
    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attr:
        return cn_attr[0].value
    return ""

# Import serialization for fingerprint function
from cryptography.hazmat.primitives import serialization
