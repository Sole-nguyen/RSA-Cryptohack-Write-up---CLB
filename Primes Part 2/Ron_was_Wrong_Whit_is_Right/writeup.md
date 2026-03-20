# Ron was Wrong, Whit is Right - Writeup

## Phân tích challenge
Bài này cung cấp cho mình file python là đoạn mẫu và 1 file zip chứa 50 cặp `public key (.pem)` và `ciphertext`
```python
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
msg = "???"
with open('21.pem') as f:
    key = RSA.importKey(f.read())
cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(msg)
with open('21.ciphertext', 'w') as f:
    f.write(ciphertext.hex())
```

## Ý tưởng chính

Đoạn mã mẫu cho thấy mã hóa dùng `RSAES-OAEP` (`PKCS1_OAEP`), nên nếu có private key đúng thì giải mã trực tiếp được.

Điểm yếu nằm ở quá trình sinh prime: có 2 modulus RSA dùng chung một prime.
Khi đó:

- `n1 = p * q1`
- `n2 = p * q2`
- `gcd(n1, n2) = p`

Chỉ cần tính `gcd` giữa các modulus là tách được prime dùng chung.

## Các bước tấn công

1. Parse tất cả file `.pem`, lấy `(n, e)`.
2. Tính `gcd` cho mọi cặp modulus.
3. Phát hiện cặp yếu: `21.pem` và `34.pem` có `gcd(n21, n34) > 1`.
4. Khôi phục private key:
   - `q = n / p`
   - `phi = (p-1)(q-1)`
   - `d = e^{-1} mod phi`
5. Dùng private key với `PKCS1_OAEP` để giải mã `21.ciphertext` và `34.ciphertext`.

## Kết quả
Chạy file solve.py này
```python
import math
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

k21, k34 = [RSA.import_key(open(f"keys_and_messages/{i}.pem").read()) for i in (21, 34)]
p = math.gcd(k21.n, k34.n)

for k, idx in [(k21, 21), (k34, 34)]:
    d = pow(k.e, -1, (p - 1) * (k.n // p - 1))
    priv = RSA.construct((k.n, k.e, d, p, k.n // p))
    ct = bytes.fromhex(open(f"keys_and_messages/{idx}.ciphertext").read().strip())
    print(f"[{idx}]:", PKCS1_OAEP.new(priv).decrypt(ct).decode(errors='ignore'))
```
Giải mã được thông điệp:

- Từ `21.ciphertext`:
  `crypto{3ucl1d_w0uld_b3_pr0ud} If you haven't already, check out https://eprint.iacr.org/2012/064.pdf`
- Từ `34.ciphertext`: một chuỗi random/base32-like không phải flag chính.

**Flag:** `crypto{3ucl1d_w0uld_b3_pr0ud}`
