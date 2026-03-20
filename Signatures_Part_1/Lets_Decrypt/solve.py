import json
from pwn import *
from Crypto.Util.number import bytes_to_long
from pkcs1 import emsa_pkcs1_v15
io = remote('socket.cryptohack.org', 13391) 
io.recvline()
io.sendline(json.dumps({"option": "get_signature"}).encode())
res1 = json.loads(io.recvline().decode())
signature = int(res1['signature'], 16)
print(f"Lấy được signature: {hex(signature)[:50]}...")
msg = "I am Mallory and I own CryptoHack.org"
digest_bytes = emsa_pkcs1_v15.encode(msg.encode(), 256)
digest_int = bytes_to_long(digest_bytes)
forged_e = 1
forged_n = signature - digest_int
print(f"N: {hex(forged_n)}")
print(f"e: {hex(forged_e)}")
payload = {
    "option": "verify",
    "msg": msg,
    "N": hex(forged_n),
    "e": hex(forged_e)
}
io.sendline(json.dumps(payload).encode())
res2 = json.loads(io.recvline().decode())
print(res2)