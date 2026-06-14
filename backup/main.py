import hashlib
import sys
import os
import sss
import crypto
import token_client
from config import DEVICE_KEYS


def encrypt_flow(path: str):
    ports = token_client.detect_active_tokens()

    if len(ports) < 3:
        print("Not enough tokens connected.")
        return

    key = crypto.encrypt_file(path)
    shares = sss.split_key(key)

    k_unlock = os.urandom(32)
    k_unlock_shares = sss.split_key(k_unlock)
    k_unlock_hash = hashlib.sha256(k_unlock).hexdigest()

    system_id = os.urandom(16).hex()

    print(f"System ID: {system_id}")
    print("Writing shares to tokens...")

    for i, port in enumerate(ports[:3]):
        share_line = shares[i]
        unlock_line = k_unlock_shares[i]
        unlock_hex = unlock_line.split("-", 1)[1]
        x_index, share_hex = share_line.split("-", 1)

        ok = token_client.store_share(port, int(x_index), system_id, share_hex, unlock_hex, k_unlock_hash)

        if ok:
            print(f"  {port}: OK (index {x_index})")
        else:
            print(f"  {port}: FAIL")

    print("\nOffline backup shares (store securely)")
    for backup in shares[3:]:
        print(" ", backup)


def decrypt_flow(path: str):
    shares = []
    system_ids = set()
    unlock_shares = []

    ports = token_client.detect_active_tokens()
    if len(ports) < 3:
        print("Not enough tokens connected.")
        return
    connections = {port: token_client.open_serial(port) for port in ports}
    for port in ports[:3]:
        try:
            key_device = DEVICE_KEYS[token_client.identify(port, connections[port])]
            unlock_shares.append(f"{token_client.auth_token(connections[port], key_device)}")
        except Exception as e:
            print(f"{port} failed to authenticate, error: {e}")
    try:
        k_unlock = sss.combine_shares(unlock_shares)
    except RuntimeError as e:
        print("Failed to unlock tokens: ", e)
    for port in ports[:3]:
        try:
            if token_client.send_unlock_key(connections[port], k_unlock.hex()):
                share_data = token_client.get_share(connections[port])
                if share_data:
                    system_ids.add(share_data["system_id"])
                    shares.append(f"{share_data['x_index']}-{share_data['share']}")
                    print(f"Got share from {port}")
                if len(shares) == 3:
                    break
        except Exception as e:
            print(f"{port} failed: {e}")

    if len(shares) < 3:
        print("Not enough shares.")
        for port in ports[:3]:
            connections[port].close()
        return
    if len(system_ids) != 1:
        print("System IDs mismatch between tokens.")
        for port in ports[:3]:
            connections[port].close()
        return

    for port in ports[:3]:
        connections[port].close()

    try:
        key = sss.combine_shares(shares)
        crypto.decrypt_file(path, key)
        print("Decryption complete.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python main.py encrypt <file>")
        print("  python main.py decrypt <file.enc>")
        sys.exit(1)

    mode = sys.argv[1]
    path = sys.argv[2]

    if mode == "encrypt":
        encrypt_flow(path)
    elif mode == "decrypt":
        decrypt_flow(path)
    else:
        print("Unknown mode")
