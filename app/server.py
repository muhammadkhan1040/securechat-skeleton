"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import json
import os
import secrets
from pathlib import Path

from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.dh import generate_dh_keypair, compute_shared_secret, derive_aes_key, DEFAULT_P, DEFAULT_G
from app.crypto.pki import verify_certificate, CertificateValidationError, get_certificate_fingerprint
from app.crypto.sign import sign_data, verify_signature, load_private_key_from_file, load_public_key_from_cert
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.common.protocol import *
from app.storage.db import register_user, verify_login, get_user_by_email
from app.storage.transcript import Transcript

HOST = os.getenv('SERVER_HOST', '127.0.0.1')
PORT = int(os.getenv('SERVER_PORT', 8443))

SERVER_CERT_PATH = "certs/server_cert.pem"
SERVER_KEY_PATH = "certs/server_key.pem"
CA_CERT_PATH = "certs/ca_cert.pem"

class SecureChatServer:
    def __init__(self):
        # Load server certificate
        with open(SERVER_CERT_PATH, 'r') as f:
            self.server_cert_pem = f.read()

        # Load CA certificate
        with open(CA_CERT_PATH, 'r') as f:
            self.ca_cert_pem = f.read()

        # Load server private key
        self.server_private_key = load_private_key_from_file(SERVER_KEY_PATH)

        print(f"[+] Server certificates loaded")

    def handle_client(self, conn, addr):
        """Handle client connection."""
        print(f"\n[*] New connection from {addr}")

        try:
            # State variables
            client_cert_pem = None
            client_public_key = None
            auth_aes_key = None  # AES key for authentication phase
            session_aes_key = None  # AES key for chat session
            authenticated_user = None
            seqno_send = 1
            seqno_recv = 1
            transcript = None

            # Phase 1: Certificate Exchange
            data = conn.recv(4096).decode()
            if not data:
                return

            hello_msg = HelloMessage.model_validate_json(data)
            print(f"[+] Received hello from client")

            # Verify client certificate
            try:
                verify_certificate(hello_msg.client_cert, self.ca_cert_pem)
                client_cert_pem = hello_msg.client_cert
                client_public_key = load_public_key_from_cert(client_cert_pem)
                print(f"[+] Client certificate verified")
            except CertificateValidationError as e:
                print(f"[!] Certificate validation failed: {e}")
                response = ResponseMessage(status="BAD_CERT", message=str(e))
                conn.send(response.model_dump_json().encode())
                return

            # Send server hello
            server_hello = ServerHelloMessage(
                server_cert=self.server_cert_pem,
                nonce=b64e(secrets.token_bytes(16))
            )
            conn.send(server_hello.model_dump_json().encode())
            print(f"[+] Sent server hello")

            # Phase 2: Authentication DH Exchange (temporary key for credentials)
            data = conn.recv(4096).decode()
            if not data:
                return

            dh_client_msg = DHClientMessage.model_validate_json(data)
            print(f"[+] Received DH client parameters")

            # Generate server DH keypair
            dh_private, dh_public = generate_dh_keypair(dh_client_msg.p, dh_client_msg.g)

            # Compute shared secret and derive AES key
            shared_secret = compute_shared_secret(dh_client_msg.A, dh_private, dh_client_msg.p)
            auth_aes_key = derive_aes_key(shared_secret)

            # Send DH server response
            dh_server_msg = DHServerMessage(B=dh_public)
            conn.send(dh_server_msg.model_dump_json().encode())
            print(f"[+] Sent DH server response, auth AES key established")

            # Phase 3: Registration or Login
            data = conn.recv(4096).decode()
            if not data:
                return

            # Decrypt the authentication message
            msg_obj = json.loads(data)
            msg_type = msg_obj.get("type")

            if msg_type == "register":
                # Decrypt registration data
                ct_bytes = b64d(msg_obj["data"])
                pt_bytes = aes_decrypt(auth_aes_key, ct_bytes)
                reg_data = json.loads(pt_bytes.decode())

                print(f"[*] Registration request for: {reg_data['email']}")

                # Register user
                salt = b64d(reg_data['salt'])
                success = register_user(
                    reg_data['email'],
                    reg_data['username'],
                    salt,
                    reg_data['pwd']
                )

                if success:
                    authenticated_user = reg_data['email']
                    response = ResponseMessage(status="OK", message="Registration successful")
                    print(f"[+] User registered: {reg_data['email']}")
                else:
                    response = ResponseMessage(status="ERROR", message="User already exists")
                    print(f"[!] Registration failed: user exists")

                conn.send(response.model_dump_json().encode())

                if not success:
                    return

            elif msg_type == "login":
                # Decrypt login data
                ct_bytes = b64d(msg_obj["data"])
                pt_bytes = aes_decrypt(auth_aes_key, ct_bytes)
                login_data = json.loads(pt_bytes.decode())

                print(f"[*] Login request for: {login_data['email']}")

                # Verify credentials
                if verify_login(login_data['email'], login_data['pwd']):
                    authenticated_user = login_data['email']
                    response = ResponseMessage(status="OK", message="Login successful")
                    print(f"[+] User authenticated: {login_data['email']}")
                else:
                    response = ResponseMessage(status="ERROR", message="Invalid credentials")
                    print(f"[!] Login failed: invalid credentials")

                conn.send(response.model_dump_json().encode())

                if not authenticated_user:
                    return
            else:
                print(f"[!] Unknown message type: {msg_type}")
                return

            # Phase 4: Session DH Exchange (new key for chat)
            data = conn.recv(4096).decode()
            if not data:
                return

            dh_client_msg = DHClientMessage.model_validate_json(data)
            print(f"[+] Received session DH parameters")

            # Generate server DH keypair for session
            dh_private_session, dh_public_session = generate_dh_keypair(dh_client_msg.p, dh_client_msg.g)

            # Compute session shared secret and derive session AES key
            session_shared_secret = compute_shared_secret(dh_client_msg.A, dh_private_session, dh_client_msg.p)
            session_aes_key = derive_aes_key(session_shared_secret)

            # Send DH server response
            dh_server_msg = DHServerMessage(B=dh_public_session)
            conn.send(dh_server_msg.model_dump_json().encode())
            print(f"[+] Session AES key established")

            # Initialize transcript
            client_cert_fp = get_certificate_fingerprint(client_cert_pem)
            transcript_filename = f"transcripts/server_{authenticated_user}_{now_ms()}.txt"
            transcript = Transcript(transcript_filename)

            # Phase 5: Chat Loop
            print(f"[+] Entering chat mode...")

            while True:
                data = conn.recv(8192).decode()
                if not data:
                    break

                try:
                    msg = ChatMessage.model_validate_json(data)

                    # Verify sequence number (replay protection)
                    if msg.seqno != seqno_recv:
                        print(f"[!] Replay attack detected! Expected {seqno_recv}, got {msg.seqno}")
                        response = ResponseMessage(status="REPLAY", message="Invalid sequence number")
                        conn.send(response.model_dump_json().encode())
                        continue

                    # Verify signature: SHA256(seqno || ts || ct)
                    sig_data = f"{msg.seqno}{msg.ts}{msg.ct}".encode()
                    sig_hash = sha256_hex(sig_data).encode()
                    sig_bytes = b64d(msg.sig)

                    if not verify_signature(client_public_key, sig_hash, sig_bytes):
                        print(f"[!] Signature verification failed!")
                        response = ResponseMessage(status="SIG_FAIL", message="Invalid signature")
                        conn.send(response.model_dump_json().encode())
                        continue

                    # Decrypt message
                    ct_bytes = b64d(msg.ct)
                    plaintext = aes_decrypt(session_aes_key, ct_bytes).decode()

                    print(f"[Client]: {plaintext}")

                    # Append to transcript
                    transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig, client_cert_fp)

                    # Increment receive sequence number
                    seqno_recv += 1

                    # Check for exit command
                    if plaintext.strip().lower() == "/exit":
                        print(f"[*] Client requested exit")
                        break

                    # Echo response or send server message
                    response_text = f"Server received: {plaintext}"

                    # Encrypt response
                    response_ct = aes_encrypt(session_aes_key, response_text.encode())

                    # Compute signature
                    resp_sig_data = f"{seqno_send}{now_ms()}{b64e(response_ct)}".encode()
                    resp_sig_hash = sha256_hex(resp_sig_data).encode()
                    resp_sig = sign_data(self.server_private_key, resp_sig_hash)

                    # Create response message
                    resp_msg = ChatMessage(
                        seqno=seqno_send,
                        ts=now_ms(),
                        ct=b64e(response_ct),
                        sig=b64e(resp_sig)
                    )

                    conn.send(resp_msg.model_dump_json().encode())

                    # Append to transcript
                    server_cert_fp = get_certificate_fingerprint(self.server_cert_pem)
                    transcript.append(resp_msg.seqno, resp_msg.ts, resp_msg.ct, resp_msg.sig, server_cert_fp)

                    seqno_send += 1

                except Exception as e:
                    print(f"[!] Error processing message: {e}")
                    break

            # Phase 6: Generate and send SessionReceipt
            if transcript:
                transcript_hash = transcript.compute_hash()
                receipt_sig = sign_data(self.server_private_key, transcript_hash.encode())

                receipt = ReceiptMessage(
                    peer="server",
                    first_seq=transcript.get_first_seqno(),
                    last_seq=transcript.get_last_seqno(),
                    transcript_sha256=transcript_hash,
                    sig=b64e(receipt_sig)
                )

                conn.send(receipt.model_dump_json().encode())
                print(f"[+] Session receipt sent")
                print(f"[+] Transcript saved to: {transcript_filename}")

        except Exception as e:
            print(f"[!] Error handling client: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
            print(f"[*] Connection closed: {addr}")

    def start(self):
        """Start the server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)

        print(f"[*] SecureChat Server listening on {HOST}:{PORT}")

        try:
            while True:
                conn, addr = sock.accept()
                self.handle_client(conn, addr)
        except KeyboardInterrupt:
            print("\n[*] Server shutdown")
        finally:
            sock.close()

def main():
    server = SecureChatServer()
    server.start()

if __name__ == "__main__":
    main()
