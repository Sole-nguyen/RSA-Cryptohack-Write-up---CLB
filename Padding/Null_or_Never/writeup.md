# Null or Never - Writeup

## Challenge cung cấp
Challenge này cung cấp cho 2 file:
* pad_encrypt.py
```python
#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
FLAG = b"crypto{???????????????????????????????????}"
def pad100(msg):
    return msg + b'\x00' * (100 - len(msg))
key = RSA.generate(1024, e=3)
n, e = key.n, key.e
m = bytes_to_long(pad100(FLAG))
c = pow(m, e, n)
print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
```
* output.txt: cung cấp cho n,e,c

Key chính của bài này là ở đoạn này
```python
def pad100(msg):
    return msg + b'\x00' * (100 - len(msg))

m = bytes_to_long(pad100(FLAG))
c = pow(m, e, n)
```

Nghĩa là message không padding chuẩn PKCS/OAEP, mà chỉ **nối thêm byte `0x00` ở cuối** cho đủ 100 byte.

## 2. Ý tưởng chính
Giả sử `FLAG` (trước khi pad) có dạng số nguyên là `x`, và số byte `0x00` thêm vào là `k`.
Khi đó:
- `m = x * 2^(8k)` (dịch trái `8k` bit vì nối `k` byte 0 ở cuối)
- `c ≡ m^3 ≡ x^3 * 2^(24k) (mod n)`

Vì `n` là số lẻ, `2^(24k)` khả nghịch modulo `n`, nên:
`x^3 ≡ c * (2^(24k))^{-1} (mod n)`
Đặt:
`c' = c * (2^(24k))^{-1} mod n`
Thì tồn tại số nguyên `t` sao cho:
`x^3 = c' + t*n`
Vấn đề còn lại: tìm `t` để `c' + t*n` là lập phương hoàn hảo.

## 3) Vì sao brute-force `t` được?

Trong file challenge, placeholder:

```python
FLAG = b"crypto{???????????????????????????????????}"
```

Cho thấy độ dài flag là 43 byte, nên:

- `k = 100 - 43 = 57`
- `x < 2^(8*43)` => `x^3 < 2^(24*43) = 2^1032`
- Trong khi `n` cỡ 1024 bit (`~2^1024`)

Suy ra `t` khá nhỏ (xấp xỉ dưới `2^8`), nên quét vài trăm giá trị là đủ.

## 4) Thuật toán

1. Tính `k = 57`.
2. Tính `c' = c * inv(2^(24k), n) mod n`.
3. Lặp `t = 0..511`:
   - `y = c' + t*n`
   - Lấy căn bậc 3 nguyên của `y`
   - Nếu `root^3 == y`, đổi sang bytes, kiểm tra pattern `crypto{...}`
4. In ra flag.

## 5) Kết quả
```python
n = 95341235345618011251857577682324351171197688101180707030749869409235726634345899397258784261937590128088284421816891826202978052640992678267974129629670862991769812330793126662251062120518795878693122854189330426777286315442926939843468730196970939951374889986320771714519309125434348512571864406646232154103
c = 63476139027102349822147098087901756023488558030079225358836870725611623045683759473454129221778690683914555720975250395929721681009556415292257804239149809875424000027362678341633901036035522299395660255954384685936351041718040558055860508481512479599089561391846007771856837130233678763953257086620228436828

# Tính c' một lần duy nhất, pow hỗ trợ mũ âm để tính luôn nghịch đảo module
c_adj = (c * pow(2, -1368, n)) % n

def icbrt(val):
    """Tìm căn bậc 3 nguyên bằng tìm kiếm nhị phân"""
    low, high = 0, 1 << ((val.bit_length() + 2) // 3)
    while low < high:
        mid = (low + high) // 2
        if mid**3 < val: low = mid + 1
        else: high = mid
    return low

for t in range(512):
    y = c_adj + t * n
    x = icbrt(y)
    
    # Nếu là căn bậc 3 hoàn hảo, in ra flag và dừng chương trình
    if x**3 == y:
        print(x.to_bytes((x.bit_length() + 7) // 8, "big").decode())
        break
```

**Flag**: `crypto{n0n_574nd4rd_p4d_c0n51d3r3d_h4rmful}`