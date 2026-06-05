import sys
import select
import json
import hashlib
import os
from cryptolib import aes

BLOCK_SIZE = 64
K_DEVICE = bytes.fromhex("d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00112233")
DEVICE_ID = "003"
authorized = False
current_nonce = None

def aes_ctr_crypt(key: bytes, data: bytes, nonce: bytes) -> bytes:
    cipher = aes(key, 1)  # ECB mode

    result = bytearray(len(data))

    counter = bytearray(nonce)

    for block_start in range(0, len(data), 16):
        block = data[block_start:block_start+16]

        keystream = cipher.encrypt(bytes(counter))

        for i in range(len(block)):
            result[block_start + i] = block[i] ^ keystream[i]

        for i in range(15, 11, -1):
            counter[i] = (counter[i] + 1) & 0xFF
            if counter[i] != 0:
                break

    return bytes(result)

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()
        
    if len(key) < BLOCK_SIZE:
        key = key + b'\x00' * (BLOCK_SIZE - len(key))
        
    o_key_pad = bytes([b ^ 0x5c for b in key])
    i_key_pad = bytes([b ^ 0x36 for b in key])
    
    inner = hashlib.sha256(i_key_pad + msg).digest()
    return hashlib.sha256(o_key_pad + inner).digest()

def send(msg: str):
    sys.stdout.write(msg + "\n")

def read_line():
    if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
        return sys.stdin.readline().strip()
    return None

def store_share(x_index, system_id_hex, share_hex):
    version = 1

    x_index = int(x_index)

    system_id = bytes.fromhex(system_id_hex)
    share = bytes.fromhex(share_hex)

    if len(share) != 32:
        send("INVALID_SHARE_LENGTH")
        return
    
    if len(system_id) != 16:
        send("INVALID_ID_LENGTH")
        return
    
    nonce = os.urandom(16)
    ciphertext = aes_ctr_crypt(K_DEVICE, share, nonce)
    mac = hmac_sha256(K_DEVICE, nonce + ciphertext)
    
    data = bytearray(1 + 1 + 2 + 16 + 16 + 32 + 32)  # version + index + reserved + system_id + nonce + ciphertext + mac

    data[0] = version
    data[1] = x_index

    # data[2:4] reserved (stays zero)

    data[4:20] = system_id
    data[20:36] = nonce
    data[36:68] = ciphertext
    data[68:100] = mac

    with open("share.bin", "wb") as f:
        f.write(data)

def load_share():
    try:
        with open("share.bin", "rb") as f:
            data = f.read()

        if len(data) != 100:
            return None

        version = data[0]
        x_index = data[1]

        system_id = data[4:20]
        nonce = data[20:36]
        ciphertext = data[36:68]
        mac_stored = data[68:100]

        mac_calc = hmac_sha256(K_DEVICE, nonce + ciphertext)

        if mac_calc != mac_stored:
            send("MAC_FAIL")
            return None

        share = aes_ctr_crypt(K_DEVICE, ciphertext, nonce)

        return {
            "version": version,
            "x_index": x_index,
            "system_id": system_id.hex(),
            "share": share.hex()
        }

    except:
        return None

send("TOKEN_READY")

state = "IDLE"

while True:
    line = read_line()

    if not line:
        continue

    if state == "IDLE":
        if line == "PING":
            send("PONG")
        if line == "IDENTIFY":
            send(DEVICE_ID)

        elif line == "STORE":
            state = "STORE_X"

        elif line == "GET_SHARE":
            if authorized:
                data = load_share()
                if data:
                    send(f"{data['x_index']}-{data['system_id']}-{data['share']}")
                else:
                    send("NO_DATA")
                authorized = False
            else:
                send("NOT_AUTHORIZED")
                
        elif line == "AUTH":
            current_nonce = os.urandom(32)
            authorized = False
            send(current_nonce.hex())
            state = "AUTH_WAIT"
        else:
            send("UNKNOWN")

    elif state == "STORE_X":
        x_index = line
        state = "STORE_SYSTEM"

    elif state == "STORE_SYSTEM":
        system_id = line
        state = "STORE_SHARE"

    elif state == "STORE_SHARE":
        share_hex = line
        store_share(x_index, system_id, share_hex)
        send("OK")
        state = "IDLE"
    
    elif state == "AUTH_WAIT":
        response = bytes.fromhex(line)
        expected = hmac_sha256(K_DEVICE, current_nonce)
        
        if response == expected:
            authorized = True
            send("AUTH_OK")
        else:
            send("AUTH_FAIL")
            
        state = "IDLE"


