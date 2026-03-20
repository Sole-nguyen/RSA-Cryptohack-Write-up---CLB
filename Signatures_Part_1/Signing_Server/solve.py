from pwn import *
import json

r = remote("socket.cryptohack.org", 13374)
r.recvline()
r.sendline(json.dumps({'option': 'get_secret'}))
data = json.loads(r.recvline().decode())
ciphertext = data['secret'][2:]
r.sendline(json.dumps({'option': 'sign', 'msg': ciphertext}).encode())
data = json.loads(r.recvline().decode())
print(data)
r.close()
