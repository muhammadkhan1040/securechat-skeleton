# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This is a **console-based, PKI-enabled Secure Chat System** implemented in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

## 🎓 Project Overview

This project implements a secure client-server chat application using:
- **AES-128 (ECB mode)** with PKCS#7 padding for encryption
- **RSA with X.509 certificates** for authentication
- **Diffie-Hellman (DH)** for key exchange
- **SHA-256** for hashing and signatures
- **MySQL** for secure credential storage
- **Digital signatures** for message integrity and non-repudiation

## 🏗️ Architecture

The system follows a 4-phase protocol:

1. **Control Plane**: Certificate exchange and mutual authentication
2. **Key Agreement**: Diffie-Hellman key exchange for session keys
3. **Data Plane**: Encrypted and signed message exchange
4. **Teardown**: Session receipt generation for non-repudiation

## 📦 Prerequisites

- Python 3.8+
- MySQL 8.0+
- Git

## ⚙️ Installation & Setup

### 1. Clone the Repository

```bash
git clone <your-fork-url>
cd securechat-skeleton
```

### 2. Create Virtual Environment

```bash
python -m venv .venv

# On Windows (Git Bash):
source .venv/Scripts/activate

# On Linux/Mac:
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
# Edit .env if needed with your MySQL credentials
```

### 5. Setup MySQL Database

#### Option A: Using Docker (Recommended)

```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

#### Option B: Using Existing MySQL Installation

Create a database and user manually:

```sql
CREATE DATABASE securechat;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
```

### 6. Initialize Database Schema

```bash
python -m app.storage.db --init
```

### 7. Generate PKI Certificates

```bash
# Generate Root CA
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Generate Server Certificate
python scripts/gen_cert.py --cn server.local --out certs/server

# Generate Client Certificate
python scripts/gen_cert.py --cn client.local --out certs/client
```

This will create the following files in the `certs/` directory:
- `ca_cert.pem` - Root CA certificate
- `ca_key.pem` - Root CA private key
- `server_cert.pem` - Server certificate
- `server_key.pem` - Server private key
- `client_cert.pem` - Client certificate
- `client_key.pem` - Client private key

## 🚀 Running the Application

### Start the Server

Open a terminal and run:

```bash
python -m app.server
```

Expected output:
```
[+] Server certificates loaded
[*] SecureChat Server listening on 127.0.0.1:8443
```

### Start the Client

Open another terminal and run:

```bash
python -m app.client
```

## 📝 Usage Example

### Registration Flow

```
[+] Client certificates loaded
[+] Connected to server 127.0.0.1:8443
[+] Sent hello to server
[+] Received server hello
[+] Server certificate verified
[+] Sent DH parameters
[+] Received DH server response
[+] Auth AES key established

--- Authentication ---
(1) Register  (2) Login
Choice: 1
Email: alice@fast.nu.edu.pk
Username: alice
Password: ********
[+] Registration request sent
[+] Registration successful
[+] Sent session DH parameters
[+] Received session DH response
[+] Session AES key established

[+] Chat session started
[*] Type /exit to quit

You: Hello, this is a secure message!
[Server]: Server received: Hello, this is a secure message!

You: /exit
[*] Exiting chat...
[+] Received session receipt from server
    Transcript SHA256: a1b2c3d4...
[+] Receipt signature verified
[+] Sent client session receipt
[+] Chat session ended
[+] Transcript saved
```

### Login Flow

```
--- Authentication ---
(1) Register  (2) Login
Choice: 2
Email: alice@fast.nu.edu.pk
Password: ********
[+] Login request sent
[+] Login successful
...
```

## 🔐 Security Features

### Confidentiality
- All credentials encrypted during transit using AES-128
- All chat messages encrypted using session-specific AES-128 keys
- No plaintext passwords stored (salted SHA-256 hashes only)

### Integrity
- Every message includes SHA-256 hash
- Tampered messages are rejected with `SIG_FAIL`

### Authenticity
- Mutual X.509 certificate validation
- RSA digital signatures on all messages
- Invalid certificates rejected with `BAD_CERT`

### Non-Repudiation
- Append-only transcripts maintained by both parties
- Session receipts with signed transcript hashes
- Offline verification possible

### Replay Protection
- Strictly increasing sequence numbers
- Replayed messages rejected with `REPLAY`
- Timestamps included in all messages

## 📂 Project Structure

```
securechat-skeleton/
├── app/
│   ├── client.py              # Client implementation
│   ├── server.py              # Server implementation
│   ├── crypto/
│   │   ├── aes.py             # AES-128 encryption/decryption
│   │   ├── dh.py              # Diffie-Hellman key exchange
│   │   ├── pki.py             # X.509 certificate validation
│   │   └── sign.py            # RSA signatures
│   ├── common/
│   │   ├── protocol.py        # Pydantic message models
│   │   └── utils.py           # Utility functions
│   └── storage/
│       ├── db.py              # MySQL database layer
│       └── transcript.py      # Transcript management
├── scripts/
│   ├── gen_ca.py              # Generate Root CA
│   └── gen_cert.py            # Issue certificates
├── certs/                     # Certificates and keys (gitignored)
├── transcripts/               # Session transcripts (gitignored)
├── .env.example               # Example environment configuration
├── .gitignore                 # Git ignore patterns
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🧪 Testing

### Test Certificate Validation

Generate an invalid (expired or self-signed) certificate and observe rejection:

```bash
# The system will reject with BAD_CERT error
```

### Test Message Tampering

Modify the ciphertext in transit (using a proxy or debugger) and observe:
```
[!] Signature verification failed!
Status: SIG_FAIL
```

### Test Replay Attack

Resend an old message and observe:
```
[!] Replay attack detected! Expected X, got Y
Status: REPLAY
```

### Wireshark Capture

1. Start Wireshark and capture on loopback interface
2. Filter: `tcp.port == 8443`
3. Verify all message payloads are encrypted (base64 ciphertext only)

## 📊 Message Formats

### Control Plane

**Hello:**
```json
{
  "type": "hello",
  "client_cert": "-----BEGIN CERTIFICATE-----...",
  "nonce": "base64..."
}
```

**Server Hello:**
```json
{
  "type": "server_hello",
  "server_cert": "-----BEGIN CERTIFICATE-----...",
  "nonce": "base64..."
}
```

**Registration:**
```json
{
  "type": "register",
  "data": "base64_encrypted_payload"
}
```

**Login:**
```json
{
  "type": "login",
  "data": "base64_encrypted_payload"
}
```

### Key Agreement

**DH Client:**
```json
{
  "type": "dh_client",
  "g": 2,
  "p": <large_prime>,
  "A": <g^a mod p>
}
```

**DH Server:**
```json
{
  "type": "dh_server",
  "B": <g^b mod p>
}
```

### Data Plane

**Chat Message:**
```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1234567890123,
  "ct": "base64_ciphertext",
  "sig": "base64_rsa_signature"
}
```

### Teardown

**Session Receipt:**
```json
{
  "type": "receipt",
  "peer": "client|server",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "hex_hash",
  "sig": "base64_signature"
}
```

## 🔍 Transcript Format

Each line in the transcript file follows this format:

```
seqno|timestamp|ciphertext|signature|peer_cert_fingerprint
```

Example:
```
1|1704067200000|aGVsbG8gd29ybGQ=|c2lnbmF0dXJl...|a1b2c3d4e5f6...
2|1704067201000|Z29vZGJ5ZQ==|c2lnbmF0dXJl...|f6e5d4c3b2a1...
```

## 🛡️ Important Security Notes

1. **Never commit secrets**: The `.gitignore` is configured to exclude `certs/`, `.env`, and `transcripts/`
2. **Per-user salts**: Each user has a unique 16-byte random salt
3. **No password reuse**: Passwords are hashed with salt before storage
4. **Constant-time comparison**: Login verification uses constant-time comparison to prevent timing attacks
5. **Forward separation**: Each session uses a new DH key exchange

## 🚫 Restrictions Followed

- ✅ No TLS/SSL or secure-channel abstractions used
- ✅ All crypto operations at application layer
- ✅ Using standard Python libraries (cryptography, PyMySQL)
- ✅ Not implementing crypto primitives from scratch
- ✅ No plaintext credentials in transit
- ✅ No chat messages stored in database

## 📚 Dependencies

- `cryptography` - RSA, AES, X.509, DH
- `PyMySQL` - MySQL database driver
- `python-dotenv` - Environment variable management
- `pydantic` - Data validation and serialization
- `rich` - Terminal formatting (optional)

## 🐛 Troubleshooting

### Database Connection Error

```
Error: Can't connect to MySQL server
```

**Solution**: Ensure MySQL is running and credentials in `.env` are correct.

### Certificate Validation Failed

```
BAD_CERT: Certificate signature verification failed
```

**Solution**: Regenerate certificates using the scripts in correct order (CA first, then server/client).

### Module Import Error

```
ModuleNotFoundError: No module named 'app'
```

**Solution**: Run commands with `-m` flag from project root:
```bash
python -m app.server
python -m app.client
```

## 📄 License

This is an educational project for CS-3002 Information Security course at FAST-NUCES.

## 👥 Author

[Muhammad Khan]
[22i-1040]

## 🔗 Repository

[Link to your GitHub fork]

---

**Note**: This implementation is for educational purposes and demonstrates cryptographic concepts. For production systems, use established protocols like TLS 1.3 and libraries like OpenSSL.
