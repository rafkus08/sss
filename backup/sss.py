import subprocess


def split_key(key: bytes) -> list[str]:
    key_hex = key.hex()

    proc = subprocess.Popen(
        ["wsl", "ssss-split", "-t", "3", "-n", "5", "-x", "-s", "256", "-q"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    out, err = proc.communicate(input=key_hex + "\n")

    if proc.returncode != 0:
        raise RuntimeError(err)

    shares = []
    for line in out.splitlines():
        if "-" in line:
            shares.append(line.strip())

    if len(shares) != 5:
        raise RuntimeError(f"Expected 5 shares, got {len(shares)}")

    return shares


def combine_shares(shares: list[str]) -> bytes:
    input_data: str = "\n".join(shares) + "\n"
    proc = subprocess.Popen(
        ["wsl", "ssss-combine", "-t", "3", "-x", "-q"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    out, err = proc.communicate(input=input_data)

    if proc.returncode != 0:
        raise RuntimeError(err)

    result_hex = err.strip()  # # ssss-combine writes resulting secret to stderr
    return bytes.fromhex(result_hex)


if __name__ == "__main__":
    print("no arguments given")
