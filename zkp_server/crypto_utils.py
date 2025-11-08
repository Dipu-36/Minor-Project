import hashlib
import os
import hmac
import base64

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def secure_random_bytes(n: int) -> bytes:
    return os.urandom(n)

def constant_time_compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'little')

def int_to_bytes(x: int, size: int = 32) -> bytes:
    return x.to_bytes(size, 'little')

# Base64url encoding/decoding - FIXED for Ubuntu
def base64url_encode(data: bytes) -> str:
    encoded = base64.b64encode(data).decode('ascii')
    return encoded.replace('+', '-').replace('/', '_').replace('=', '')

def base64url_decode(data: str) -> bytes:
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    decoded = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(decoded)