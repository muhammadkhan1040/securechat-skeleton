"""MySQL users table + salted hashing (no chat storage)."""
import os
import pymysql
import secrets
import hashlib
from dotenv import load_dotenv

load_dotenv()

# Database configuration from environment
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'user': os.getenv('DB_USER', 'scuser'),
    'password': os.getenv('DB_PASSWORD', 'scpass'),
    'database': os.getenv('DB_NAME', 'securechat'),
}

def get_connection():
    """Create and return a database connection."""
    return pymysql.connect(**DB_CONFIG)

def init_database():
    """Initialize database schema."""
    conn = get_connection()
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()

    print("[+] Database initialized successfully")

def register_user(email: str, username: str, salt: bytes, pwd_hash: str) -> bool:
    """Register a new user.

    Args:
        email: User email
        username: Username
        salt: 16-byte salt
        pwd_hash: hex(SHA256(salt || password))

    Returns:
        True if registration successful, False if user already exists
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )

        conn.commit()
        cursor.close()
        conn.close()

        return True

    except pymysql.err.IntegrityError:
        # User already exists
        return False
    except Exception as e:
        print(f"[!] Database error: {e}")
        return False

def get_user_by_email(email: str):
    """Get user by email.

    Args:
        email: User email

    Returns:
        User dict with keys: id, email, username, salt, pwd_hash
        None if user not found
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        cursor.execute(
            "SELECT id, email, username, salt, pwd_hash FROM users WHERE email = %s",
            (email,)
        )

        user = cursor.fetchone()

        cursor.close()
        conn.close()

        return user

    except Exception as e:
        print(f"[!] Database error: {e}")
        return None

def verify_login(email: str, pwd_hash: str) -> bool:
    """Verify login credentials.

    Args:
        email: User email
        pwd_hash: hex(SHA256(salt || password)) computed by client

    Returns:
        True if credentials valid, False otherwise
    """
    user = get_user_by_email(email)

    if not user:
        return False

    # Constant-time comparison to prevent timing attacks
    stored_hash = user['pwd_hash']

    # Simple constant-time compare
    if len(pwd_hash) != len(stored_hash):
        return False

    result = 0
    for a, b in zip(pwd_hash, stored_hash):
        result |= ord(a) ^ ord(b)

    return result == 0

if __name__ == "__main__":
    import sys
    if "--init" in sys.argv:
        init_database()
