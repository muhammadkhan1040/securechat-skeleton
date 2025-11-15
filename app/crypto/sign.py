"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

def sign_data(private_key, data: bytes) -> bytes:
    """Sign data using RSA private key with SHA-256.

    Args:
        private_key: RSA private key object
        data: Data to sign

    Returns:
        RSA signature bytes
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    """Verify RSA signature using public key.

    Args:
        public_key: RSA public key object
        data: Original data that was signed
        signature: Signature to verify

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def load_private_key_from_file(filepath: str):
    """Load RSA private key from PEM file.

    Args:
        filepath: Path to private key file

    Returns:
        RSA private key object
    """
    with open(filepath, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_public_key_from_cert(cert_pem: str):
    """Extract public key from X.509 certificate PEM.

    Args:
        cert_pem: Certificate in PEM format (string)

    Returns:
        RSA public key object
    """
    cert = load_pem_x509_certificate(cert_pem.encode(), default_backend())
    return cert.public_key()

def load_public_key_from_cert_file(filepath: str):
    """Extract public key from X.509 certificate file.

    Args:
        filepath: Path to certificate file

    Returns:
        RSA public key object
    """
    with open(filepath, 'r') as f:
        cert_pem = f.read()
    return load_public_key_from_cert(cert_pem)
