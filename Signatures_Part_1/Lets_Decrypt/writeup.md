# Let's Decrypt - Writeup

## Đề bài

Server cho sẵn một `SIGNATURE` cố định và cho phép ta gửi:
- `msg`
- `N`
- `e`
để server kiểm tra:

```python
digest = emsa_pkcs1_v15.encode(msg.encode(), 256)
calculated_digest = pow(SIGNATURE, e, n)
if bytes_to_long(digest) == calculated_digest:
```

Lỗi nằm ở chỗ server không verify chữ ký theo public key chuẩn, mà lại so sánh trực tiếp với `SIGNATURE` cố định và public key do user tự đưa lên.

## Ý tưởng khai thác
Chọn:
- `e = 1`

Khi đó:
```text
pow(SIGNATURE, 1, N) = SIGNATURE mod N
```

Ta cần:

```text
SIGNATURE mod N = bytes_to_long(EMSA(msg))
```
Đặt:
```text
target = bytes_to_long(EMSA(msg))
N = SIGNATURE - target
```
thì:
```text
SIGNATURE mod (SIGNATURE - target) = target
```
=> check pass.

Sau đó chọn message thỏa regex:

```regex
I am Mallory.*own CryptoHack.org$
```
Ví dụ:

```text
I am Mallory and I own CryptoHack.org
```

## Giải mã:
```python
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
```

**Flag**: `crypto{dupl1c4t3_s1gn4tur3_k3y_s3l3ct10n}`
![image](https://hackmd.io/_uploads/ryet5PcqWe.png)
