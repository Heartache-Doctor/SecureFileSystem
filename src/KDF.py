from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os

def derive_key(password: bytes, salt: bytes = None, length: int = 32, iterations: int = 100000) -> tuple:
    # PBKDF2
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    
    key = kdf.derive(password)
    return key, salt # bytes, bytes


# password = b"my_secure_password"
# key, salt = derive_key(password)
# print(f"派生密钥: {key.hex()}")
# print(f"盐值: {salt.hex()}")
# print(type(key))
# print(type(salt))