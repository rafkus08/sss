path = "../../architektura_projektu.txt.enc"

with open(path, "rb") as f:
    data = bytearray(f.read())

# zmieniamy jeden bajt (np. 20-ty)
data[20] ^= 0xFF   # odwracamy bity

with open("../../corrupted.enc", "wb") as f:
    f.write(data)

print("Corrupted file created.")