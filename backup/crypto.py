import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        data = f.read()
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    with open(path + ".enc", "wb") as f:
        f.write(nonce)
        f.write(ct)
    return key


def decrypt_file(path: str, key: bytes) -> None:
    aesgcm = AESGCM(key)
    with open(path, "rb") as f:
        nonce = f.read(12)
        data = f.read()

    try:
        pt = aesgcm.decrypt(nonce, data, None)
    except InvalidTag:
        raise RuntimeError("Decryption failed: authentication tag invalid")

    base, ext = os.path.splitext(path)
    if ext != ".enc":
        raise ValueError("Input file must have .enc extension")
    output = base

    with open(output, "wb") as f:
        f.write(pt)
