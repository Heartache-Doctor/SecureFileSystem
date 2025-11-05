from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import cryptography

def generate_rsa_keypair() -> tuple:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsakey_to_bytes(private_key, public_key) -> tuple:
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_bytes, public_bytes # bytes, bytes

def bytes_to_rsakey(private_bytes: bytes, public_bytes: bytes) -> tuple:
    if private_bytes != None:
        private_key = serialization.load_pem_private_key(
            private_bytes,
            password=None,
            backend=default_backend()
        )
    else:
        private_key = None
    public_key = serialization.load_pem_public_key(
        public_bytes,
        backend=default_backend()
    )
    return private_key, public_key # rsa classes


def rsa_encrypt(plaintext: bytes, public_key) -> bytes:
    ciphertext = public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# prk, puk = generate_rsa_keypair()
# prb, pub = rsakey_to_bytes(prk, puk)
# prk1, puk1 = bytes_to_rsakey(prb, pub)
# message = b"Hello, World! This is a secret message."
# ct = rsa_encrypt(message, puk1)
# xx = rsa_decrypt(ct, prk)
# print(xx == message)