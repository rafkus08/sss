import hmac
import hashlib

nonce = input("nonce: ")
key_device = input("key_device: ")

nonce_bytes = bytes.fromhex(nonce)
hmac_bytes = hmac.new(bytes.fromhex(key_device), nonce_bytes, hashlib.sha256).digest()
print(hmac_bytes.hex())