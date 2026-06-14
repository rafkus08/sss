import os
import random

x_index = random.randint(1, 10)
system_id = os.urandom(16).hex()
share_hex = os.urandom(32).hex()
unlock_hex = os.urandom(32).hex()
unlock_hash = os.urandom(32).hex()

print(
    f"x_index: {x_index}\nsystem_id: {system_id}\nshare_hex: {share_hex}\nunlock_hex: {unlock_hex}\nunlock_hash: {unlock_hash}\n"
)