"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""
import hashlib
import secrets

# Safe prime p and generator g for DH (RFC 3526, 2048-bit MODP Group)
DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16
)
DEFAULT_G = 2

def generate_dh_keypair(p: int = DEFAULT_P, g: int = DEFAULT_G):
    """Generate DH private/public keypair.

    Args:
        p: Prime modulus
        g: Generator

    Returns:
        tuple: (private_key, public_key) where public = g^private mod p
    """
    # Generate private key (random in range [2, p-2])
    private_key = secrets.randbelow(p - 3) + 2
    # Compute public key
    public_key = pow(g, private_key, p)
    return private_key, public_key

def compute_shared_secret(other_public: int, my_private: int, p: int = DEFAULT_P) -> int:
    """Compute DH shared secret.

    Args:
        other_public: Other party's public key
        my_private: My private key
        p: Prime modulus

    Returns:
        Shared secret Ks = other_public^my_private mod p
    """
    return pow(other_public, my_private, p)

def derive_aes_key(shared_secret: int) -> bytes:
    """Derive AES-128 key from DH shared secret.

    K = Trunc16(SHA256(big-endian(Ks)))

    Args:
        shared_secret: DH shared secret (integer)

    Returns:
        16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    # Determine byte length needed
    byte_length = (shared_secret.bit_length() + 7) // 8
    if byte_length == 0:
        byte_length = 1
    ks_bytes = shared_secret.to_bytes(byte_length, byteorder='big')

    # Compute SHA-256 hash
    hash_digest = hashlib.sha256(ks_bytes).digest()

    # Truncate to first 16 bytes for AES-128
    aes_key = hash_digest[:16]

    return aes_key
