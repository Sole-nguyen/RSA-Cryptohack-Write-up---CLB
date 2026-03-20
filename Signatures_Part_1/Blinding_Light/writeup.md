# Blinding Light - Writeup

Challenge này bắt vận dụng kiến thức của kỹ thuật `Blinding`: $r^e mod(N)$

Với challenge này thì em chọn $r = 3$
$C_1= (3^eM)\ mod(N)$
$=> M_1= C_1^d\ mod(N)= 3^{ed} M^d\ mod(N)$

Sau đó sẽ verified $c^e\ mod(N)=$ ADMIN_TOKEN, với ADMIN_TOKEN= "admin=True"= 459922107199558918501733.
Script giải:
```python 
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
```

**Flag**: crypto{m4ll34b1l17y_c4n_b3_d4n63r0u5}"}

![image](https://hackmd.io/_uploads/BkdUpvq5-x.png)
