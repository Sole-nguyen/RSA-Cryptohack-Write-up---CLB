# Signing Server - writeup
![image](https://hackmd.io/_uploads/HJORKo75be.png)
- Challenge ta chỉ cần gửi ngược lại $c$ là có được flag.
```python
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
```
![image](https://hackmd.io/_uploads/BkE7co7c-e.png)

Bỏ vô cyberchef và nấu nó lại bằng Hex là có flag:
![image](https://hackmd.io/_uploads/SkiH5jXq-e.png)
