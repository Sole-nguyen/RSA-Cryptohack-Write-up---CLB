from Crypto.Util.number import *
from pwn import *
from json import *
r = remote('socket.cryptohack.org', 13376)
r.recvline()
r.sendline(dumps({"option": "get_pubkey"}))
recv = loads(r.recvline())
x = 459922107199558918501733
N = int(recv["N"], 16)
e = int(recv["e"], 16)
sign = (pow(3, e)* x) % N
r.sendline(dumps({"option": "sign", "msg": hex(sign)[2:]}))
recv = loads(r.recvline())
msg = int(recv["msg"], 16)
signature = int(recv["signature"], 16)
r.sendline(dumps({"option": "verify", "msg": hex(x)[2:],"signature": hex(signature* pow(3, -1, N) % N)[2:] }))
print(r.recvline())
