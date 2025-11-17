"""Client skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import json
import os
import secrets
import hashlib
import threading

from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.dh import generate_dh_keypair, compute_shared_secret, derive_aes_key, DEFAULT_P, DEFAULT_G
from app.crypto.pki import verify_certificate, CertificateValidationError, get_certificate_fingerprint
from app.crypto.sign import sign_data, verify_signature, load_private_key_from_file, load_public_key_from_cert
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.common.protocol import *
from app.storage.transcript import Transcript

HOST = os.getenv('SERVER_HOST', '127.0.0.1')
PORT = int(os.getenv('SERVER_PORT', 8443))

CLIENT_CERT_PATH = "certs/client_cert.pem"
CLIENT_KEY_PATH = "certs/client_key.pem"
CA_CERT_PATH = "certs/ca_cert.pem"

class SecureChatClient:
    def __init__(self):
        # Load client certificate
        with open(CLIENT_CERT_PATH, 'r') as f:
            self.client_cert_pem = f.read()

        # Load CA certificate
        with open(CA_CERT_PATH, 'r') as f:
            self.ca_cert_pem = f.read()

        # Load client private key
        self.client_private_key = load_private_key_from_file(CLIENT_KEY_PATH)

        print(f"[+] Client certificates loaded")

        self.sock = None
        self.server_cert_pem = None
        self.server_public_key = None
        self.session_aes_key = None
        self.seqno_send = 1
        self.seqno_recv = 1
        self.transcript = None
        self.running = False

    def connect_and_authenticate(self):
        """Connect to server and complete authentication."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))
        print(f"[+] Connected to server {HOST}:{PORT}")

        # Phase 1: Certificate Exchange
        hello = HelloMessage(
            client_cert=self.client_cert_pem,
            nonce=b64e(secrets.token_bytes(16))
        )
        self.sock.send(hello.model_dump_json().encode())
        print(f"[+] Sent hello to server")

        # Receive server hello
        data = self.sock.recv(4096).decode()
        server_hello = ServerHelloMessage.model_validate_json(data)
        print(f"[+] Received server hello")

        # Verify server certificate
        try:
            verify_certificate(server_hello.server_cert, self.ca_cert_pem)
            self.server_cert_pem = server_hello.server_cert
            self.server_public_key = load_public_key_from_cert(self.server_cert_pem)
            print(f"[+] Server certificate verified")
        except CertificateValidationError as e:
            print(f"[!] Server certificate validation failed: {e}")
            return False

        # Phase 2: Authentication DH Exchange
        dh_private, dh_public = generate_dh_keypair(DEFAULT_P, DEFAULT_G)
        dh_client_msg = DHClientMessage(g=DEFAULT_G, p=DEFAULT_P, A=dh_public)
        self.sock.send(dh_client_msg.model_dump_json().encode())
        print(f"[+] Sent DH parameters")

        # Receive DH server response
        data = self.sock.recv(4096).decode()
        dh_server_msg = DHServerMessage.model_validate_json(data)
        print(f"[+] Received DH server response")

        # Compute shared secret and derive auth AES key
        shared_secret = compute_shared_secret(dh_server_msg.B, dh_private, DEFAULT_P)
        auth_aes_key = derive_aes_key(shared_secret)
        print(f"[+] Auth AES key established")

        # Phase 3: Registration or Login
        print("\n--- Authentication ---")
        choice = input("(1) Register  (2) Login\nChoice: ").strip()

        if choice == "1":
            # Registration
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()

            # Generate salt and hash password
            salt = secrets.token_bytes(16)
            pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()

            # Create registration data
            reg_data = {
                "email": email,
                "username": username,
                "pwd": pwd_hash,
                "salt": b64e(salt)
            }

            # Encrypt registration data
            reg_json = json.dumps(reg_data).encode()
            reg_ct = aes_encrypt(auth_aes_key, reg_json)

            # Send encrypted registration
            auth_msg = {
                "type": "register",
                "data": b64e(reg_ct)
            }
            self.sock.send(json.dumps(auth_msg).encode())
            print(f"[+] Registration request sent")

        elif choice == "2":
            # Login
            email = input("Email: ").strip()
            password = input("Password: ").strip()

            # Get user's salt from server (in real implementation)
            # For now, we need to fetch salt first
            # Simplified: assume client knows salt or server sends it
            # According to spec, client needs salt to compute hash

            # For login, we need to get the salt from the server
            # Let's implement a simplified version where we fetch user info first
            from app.storage.db import get_user_by_email

            user = get_user_by_email(email)
            if not user:
                print(f"[!] User not found")
                return False

            salt = user['salt']
            pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()

            # Create login data
            login_data = {
                "email": email,
                "pwd": pwd_hash,
                "nonce": b64e(secrets.token_bytes(16))
            }

            # Encrypt login data
            login_json = json.dumps(login_data).encode()
            login_ct = aes_encrypt(auth_aes_key, login_json)

            # Send encrypted login
            auth_msg = {
                "type": "login",
                "data": b64e(login_ct)
            }
            self.sock.send(json.dumps(auth_msg).encode())
            print(f"[+] Login request sent")

        else:
            print(f"[!] Invalid choice")
            return False

        # Receive authentication response
        data = self.sock.recv(4096).decode()
        response = ResponseMessage.model_validate_json(data)

        if response.status != "OK":
            print(f"[!] Authentication failed: {response.message}")
            return False

        print(f"[+] {response.message}")

        # Phase 4: Session DH Exchange (new key for chat)
        dh_private_session, dh_public_session = generate_dh_keypair(DEFAULT_P, DEFAULT_G)
        dh_client_msg = DHClientMessage(g=DEFAULT_G, p=DEFAULT_P, A=dh_public_session)
        self.sock.send(dh_client_msg.model_dump_json().encode())
        print(f"[+] Sent session DH parameters")

        # Receive DH server response
        data = self.sock.recv(4096).decode()
        dh_server_msg = DHServerMessage.model_validate_json(data)
        print(f"[+] Received session DH response")

        # Compute session shared secret and derive session AES key
        session_shared_secret = compute_shared_secret(dh_server_msg.B, dh_private_session, DEFAULT_P)
        self.session_aes_key = derive_aes_key(session_shared_secret)
        print(f"[+] Session AES key established")

        # Initialize transcript
        server_cert_fp = get_certificate_fingerprint(self.server_cert_pem)
        transcript_filename = f"transcripts/client_{email}_{now_ms()}.txt"
        self.transcript = Transcript(transcript_filename)

        self.running = True
        return True

    def receive_messages(self):
        """Thread to receive messages from server."""
        while self.running:
            try:
                data = self.sock.recv(8192).decode()
                if not data:
                    break

                # Try to parse as chat message or receipt
                msg_obj = json.loads(data)

                if msg_obj.get("type") == "msg":
                    msg = ChatMessage.model_validate(msg_obj)

                    # Verify sequence number
                    if msg.seqno != self.seqno_recv:
                        print(f"\n[!] Sequence error! Expected {self.seqno_recv}, got {msg.seqno}")
                        continue

                    # Verify signature
                    sig_data = f"{msg.seqno}{msg.ts}{msg.ct}".encode()
                    sig_hash = sha256_hex(sig_data).encode()
                    sig_bytes = b64d(msg.sig)

                    if not verify_signature(self.server_public_key, sig_hash, sig_bytes):
                        print(f"\n[!] Signature verification failed!")
                        continue

                    # Decrypt message
                    ct_bytes = b64d(msg.ct)
                    plaintext = aes_decrypt(self.session_aes_key, ct_bytes).decode()

                    print(f"\n[Server]: {plaintext}")
                    print("You: ", end="", flush=True)

                    # Append to transcript
                    server_cert_fp = get_certificate_fingerprint(self.server_cert_pem)
                    self.transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig, server_cert_fp)

                    self.seqno_recv += 1

                elif msg_obj.get("type") == "receipt":
                    receipt = ReceiptMessage.model_validate(msg_obj)
                    print(f"\n[+] Received session receipt from server")
                    print(f"    Transcript SHA256: {receipt.transcript_sha256}")

                    # Verify receipt signature
                    receipt_sig = b64d(receipt.sig)
                    if verify_signature(self.server_public_key, receipt.transcript_sha256.encode(), receipt_sig):
                        print(f"[+] Receipt signature verified")
                    else:
                        print(f"[!] Receipt signature verification failed")

                    # Generate and send client receipt
                    client_transcript_hash = self.transcript.compute_hash()
                    client_receipt_sig = sign_data(self.client_private_key, client_transcript_hash.encode())

                    client_receipt = ReceiptMessage(
                        peer="client",
                        first_seq=self.transcript.get_first_seqno(),
                        last_seq=self.transcript.get_last_seqno(),
                        transcript_sha256=client_transcript_hash,
                        sig=b64e(client_receipt_sig)
                    )

                    self.sock.send(client_receipt.model_dump_json().encode())
                    print(f"[+] Sent client session receipt")

                    self.running = False
                    break

            except Exception as e:
                if self.running:
                    print(f"\n[!] Error receiving message: {e}")
                break

    def send_message(self, text: str):
        """Send encrypted message to server."""
        # Encrypt message
        ct = aes_encrypt(self.session_aes_key, text.encode())

        # Compute signature
        sig_data = f"{self.seqno_send}{now_ms()}{b64e(ct)}".encode()
        sig_hash = sha256_hex(sig_data).encode()
        sig = sign_data(self.client_private_key, sig_hash)

        # Create message
        msg = ChatMessage(
            seqno=self.seqno_send,
            ts=now_ms(),
            ct=b64e(ct),
            sig=b64e(sig)
        )

        self.sock.send(msg.model_dump_json().encode())

        # Append to transcript
        client_cert_fp = get_certificate_fingerprint(self.client_cert_pem)
        self.transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig, client_cert_fp)

        self.seqno_send += 1

    def chat(self):
        """Start chat session."""
        print("\n[+] Chat session started")
        print("[*] Type /exit to quit\n")

        # Start receive thread
        recv_thread = threading.Thread(target=self.receive_messages, daemon=True)
        recv_thread.start()

        try:
            while self.running:
                text = input("You: ").strip()

                if not text:
                    continue

                self.send_message(text)

                if text.lower() == "/exit":
                    print("[*] Exiting chat...")
                    break

        except KeyboardInterrupt:
            print("\n[*] Chat interrupted")
            self.running = False

        # Wait for receipt exchange
        recv_thread.join(timeout=5)

        print(f"[+] Chat session ended")
        print(f"[+] Transcript saved")

    def run(self):
        """Run the client."""
        try:
            if self.connect_and_authenticate():
                self.chat()
        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.sock:
                self.sock.close()

def main():
    client = SecureChatClient()
    client.run()

if __name__ == "__main__":
    main()
