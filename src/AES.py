from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def aes_encrypt(plaintext: bytes, key: bytes) -> tuple:
    # AES-CBC
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext, iv # bytes, bytes

def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    # AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext


# message = b"Hello, World! This is a secret message."
# key = os.urandom(32)

# ciphertext, iv = aes_encrypt(message, key)
# print(f"加密结果: {ciphertext.hex()}")
# print(type(ciphertext))# bytes型


# decrypted = aes_decrypt(ciphertext, key, iv)
# print(f"解密结果: {decrypted.decode()}")
# print(type(decrypted))# bytes型