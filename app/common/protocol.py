"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""
from pydantic import BaseModel
from typing import Literal

class HelloMessage(BaseModel):
    """Client hello with certificate and nonce."""
    type: Literal["hello"] = "hello"
    client_cert: str  # PEM format
    nonce: str  # base64

class ServerHelloMessage(BaseModel):
    """Server hello with certificate and nonce."""
    type: Literal["server_hello"] = "server_hello"
    server_cert: str  # PEM format
    nonce: str  # base64

class RegisterMessage(BaseModel):
    """Registration request with credentials."""
    type: Literal["register"] = "register"
    email: str
    username: str
    pwd: str  # base64(sha256(salt||pwd))
    salt: str  # base64

class LoginMessage(BaseModel):
    """Login request with credentials."""
    type: Literal["login"] = "login"
    email: str
    pwd: str  # base64(sha256(salt||pwd))
    nonce: str  # base64

class DHClientMessage(BaseModel):
    """Diffie-Hellman client parameters."""
    type: Literal["dh_client"] = "dh_client"
    g: int
    p: int
    A: int  # g^a mod p

class DHServerMessage(BaseModel):
    """Diffie-Hellman server response."""
    type: Literal["dh_server"] = "dh_server"
    B: int  # g^b mod p

class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: Literal["msg"] = "msg"
    seqno: int
    ts: int  # Unix milliseconds
    ct: str  # base64 ciphertext
    sig: str  # base64(RSA_SIGN(SHA256(seqno||ts||ct)))

class ReceiptMessage(BaseModel):
    """Session receipt for non-repudiation."""
    type: Literal["receipt"] = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex
    sig: str  # base64(RSA_SIGN(transcript_sha256))

class ResponseMessage(BaseModel):
    """Generic response message."""
    type: Literal["response"] = "response"
    status: str  # "OK", "ERROR", "BAD_CERT", "SIG_FAIL", "REPLAY", etc.
    message: str = ""
