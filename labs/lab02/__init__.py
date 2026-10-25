import hashlib

password = b"Marconi"
salt = bytes.fromhex("7acf95fd2716f0040c080fdb29b38bdf")

key = hashlib.sha256(password + salt).digest()

for _ in range(119999):
    key = hashlib.sha256(key).digest()

print(key.hex())
