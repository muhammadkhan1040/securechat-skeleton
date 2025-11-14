"""AES-128(ECB)+PKCS#7 helpers (use library)."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS#7 padding to data."""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding from data."""
    if not data:
        raise ValueError("Cannot unpad empty data")
    padding_length = data[-1]
    if padding_length > len(data) or padding_length == 0:
        raise ValueError("Invalid padding")
    # Verify all padding bytes are correct
    for i in range(padding_length):
        if data[-(i+1)] != padding_length:
            raise ValueError("Invalid padding")
    return data[:-padding_length]

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext using AES-128 ECB with PKCS#7 padding.

    Args:
        key: 16-byte AES key
        plaintext: Data to encrypt

    Returns:
        Ciphertext (padded and encrypted)
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")

    # Pad the plaintext
    padded = pkcs7_pad(plaintext)

    # Create cipher and encrypt
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return ciphertext

def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext using AES-128 ECB and remove PKCS#7 padding.

    Args:
        key: 16-byte AES key
        ciphertext: Data to decrypt

    Returns:
        Plaintext (decrypted and unpadded)
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    plaintext = pkcs7_unpad(padded)

    return plaintext
