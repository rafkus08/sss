import time
from typing import Dict, Any
from serial.tools import list_ports
import serial
import hashlib
import hmac
from config import DEVICE_KEYS


def open_serial(port: str):
    ser = serial.Serial(port, 115200, timeout=1, dsrdtr=False, rtscts=False)
    ser.setDTR(False)
    time.sleep(2)
    ser.reset_input_buffer()
    return ser


def detect_tokens() -> list[str]:
    ports = []
    for port in list_ports.comports():
        if port.vid == 0x2E8A:
            ports.append(port.device)
    return ports


def detect_active_tokens() -> list[str]:
    ports = detect_tokens()
    active_tokens = []
    for port in ports:
        try:
            port_id = identify(port)
            if port_id in DEVICE_KEYS:
                active_tokens.append(port)
        except Exception:
            continue
    return active_tokens


def identify(port, ser=None) -> str:
    is_external_ser = ser is not None
    active_ser = ser if is_external_ser else open_serial(port)

    try:
        active_ser.write(b'IDENTIFY\r\n')
        port_id = active_ser.readline().decode().strip()
        if not port_id:
            raise ConnectionError(f'Port "{port}" is empty')
        return port_id
    finally:
        if not is_external_ser:
            active_ser.close()


def store_share(mc_port: str, x_index: int, system_id_hex: str, share_hex: str, unlock_share_hex: str, unlock_hash_hex: str) -> bool:
    ser = open_serial(mc_port)
    ser.write(b"STORE\r\n")
    time.sleep(0.05)
    ser.write(str(x_index).encode() + b"\r\n")
    time.sleep(0.05)
    ser.write(system_id_hex.encode() + b"\r\n")
    time.sleep(0.05)
    ser.write(share_hex.encode() + b"\r\n")
    time.sleep(0.05)
    ser.write(unlock_share_hex.encode() + b"\r\n")
    time.sleep(0.05)
    ser.write(unlock_hash_hex.encode() + b"\r\n")
    response = ser.readline().decode().strip()
    ser.close()
    return response == "OK"


def auth_token(ser, key_device: bytes) -> str:
    ser.write(b"AUTH\r\n")
    start = time.time()
    while True:
        line = ser.readline().decode().strip()
        if line:
            nonce = line
            break
        if time.time() - start > 3:
            return False

    if len(nonce) != 64:
        return False
    nonce_bytes = bytes.fromhex(nonce)
    hmac_bytes = hmac.new(key_device, nonce_bytes, hashlib.sha256).digest()
    ser.write(hmac_bytes.hex().encode() + b"\r\n")
    unlock_share = ser.readline().decode().strip()
    if "-" not in unlock_share or len(unlock_share.split("-", 1)[1]) != 64:
        raise Exception(f'Invalid unlock share format')
    return unlock_share


def get_unlock_share(ser):
    unlock_share = ser.readline().decode().strip()
    return unlock_share


def send_unlock_key(ser, unlock_key_hex: str):
    ser.write(unlock_key_hex.encode() + b"\r\n")
    response = ser.readline().decode().strip()
    return response == "AUTH_OK"


def get_share(ser) -> dict[str, Any]:
    ser.write(b"GET_SHARE\r\n")
    share = ser.readline().decode().strip()
    if "-" not in share:
        raise RuntimeError(f"Invalid share format: {share}")
    parts = share.split("-", 2)
    if len(parts) != 3:
        raise RuntimeError(f"Invalid share format")
    x_index, system_id, share_hex = parts
    if len(system_id) != 32:
        raise RuntimeError("Invalid system_id length")

    if len(share_hex) != 64:
        raise RuntimeError("Invalid share length")
    return {
        "x_index": x_index,
        "system_id": system_id,
        "share": share_hex,
    }
