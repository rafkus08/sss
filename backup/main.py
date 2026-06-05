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

    system_id = os.urandom(16).hex()

    print(f"System ID: {system_id}")
    print("Writing shares to tokens...")

    for i, port in enumerate(ports[:3]):
        share_line = shares[i]
        x_index, share_hex = share_line.split("-", 1)

        ok = token_client.store_share(port, int(x_index), system_id, share_hex)

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

    ports = token_client.detect_active_tokens()

    if len(ports) < 3:
        print("Not enough tokens connected.")
        return

    for port in ports[:3]:
        try:
            key_device = DEVICE_KEYS[token_client.identify(port)]
            share_data = token_client.get_share(port, key_device)
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
        return
    if len(system_ids) != 1:
        print("System IDs mismatch between tokens.")
        return

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