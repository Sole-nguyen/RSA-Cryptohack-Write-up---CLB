# Fast Primes - Writeup

## 1. Tóm tắt bài toán
Challenge này cung cấp cho mình 3 file là:
- `fast_primes.py`: code sinh RSA key
- `key.pem`: public key
- `ciphertext.txt`: ciphertext OAEP

Điểm quan trọng nhất nằm ở hàm sinh prime:

```python
def get_fast_prime():
    M = get_primorial(40)
    while True:
        k = random.randint(2**28, 2**29-1)
        a = random.randint(2**20, 2**62-1)
        p = k * M + pow(e, a, M)

        if is_prime(p):
            return p
```

Thay vì chọn prime gần như ngẫu nhiên, tác giả ép prime vào dạng:

```text
p = kM + 65537^a mod M
q = lM + 65537^b mod M
```

với `M` là primorial của 40 prime đầu tiên.

Đây là một cấu trúc prime cực kỳ nguy hiểm, rất giống lỗi **ROCA**: prime không còn phân bố đều trong không gian số nguyên lớn nữa, mà bị bó buộc vào một tập residue rất nhỏ modulo `M`.


## 2. Vì sao cách sinh prime này yếu?

Gọi:

```text
M = 2 * 3 * 5 * 7 * ... * 173
```

Khi đó:

```text
p mod M = 65537^a mod M
q mod M = 65537^b mod M
```

Nói cách khác, `p` và `q` chỉ có thể rơi vào các residue class sinh bởi lũy thừa của `65537` modulo `M`.

Nếu prime thật sự ngẫu nhiên, thì `p mod M` có thể là gần như mọi phần tử khả nghịch modulo `M`.

Nhưng ở đây, `p mod M` chỉ nằm trong subgroup:

```text
<65537> subset (Z / MZ)^*
```

Việc giới hạn prime như vậy làm lộ rất nhiều cấu trúc đại số. Đây chính là tinh thần của ROCA:

- prime có dạng `kM + r`
- `k` nhỏ
- `r` không ngẫu nhiên mà bị ép vào một tập nhỏ, có cấu trúc

Khi hội đủ ba điều đó, ta có thể factor `n = pq` bằng kỹ thuật lattice/Coppersmith thay vì brute-force RSA thông thường.


## 3. Liên hệ với ROCA

ROCA (Return of Coppersmith's Attack) là lỗi nổi tiếng của Infineon, nơi prime được sinh theo một dạng residue có cấu trúc modulo một số đặc biệt.

Bài này gần như là một bản ROCA thu nhỏ:

- `M` là primorial lớn
- residue được tạo bởi `65537^a mod M`
- phần multiplier `k` chỉ có 28-29 bit

Điều đó có nghĩa:

```text
p = kM + r
```

trong đó:

- `r` thuộc một tập rất nhỏ so với toàn bộ không gian modulo `M`
- `k` đủ nhỏ để Coppersmith/lattice attack hoạt động

Đây là lý do public writeup của challenge này đều giải bằng hướng ROCA-like factorization.


## 4. Dữ liệu cụ thể của challenge

Từ `key.pem`, ta lấy được:

```text
n = 4013610727845242593703438523892210066915884608065890652809524328518978287424865087812690502446831525755541263621651398962044653615723751218715649008058509
e = 65537
```

Ciphertext:

```text
249d72cd1d287b1a15a3881f2bff5788bc4bf62c789f2df44d88aae805b54c9a94b8944c0ba798f70062b66160fee312b98879f1dd5d17b33095feb3c5830d28
```


## 5. Recover prime factors

Từ khai thác ROCA-like trên modulus này, ta thu được:

```text
p = 51894141255108267693828471848483688186015845988173648228318286999011443419469
q = 77342270837753916396402614215980760127245056504361515489809293852222206596161
```

Kiểm tra:

```text
p * q = n
```

chuẩn xác.


## 6. Khôi phục private key

Khi đã có `p, q`, phần còn lại là RSA tiêu chuẩn:

```text
phi(n) = (p - 1)(q - 1)
d = e^(-1) mod phi(n)
```

Sau đó dựng lại private key:

```python
key = RSA.construct((n, e, d, p, q))
```

và decrypt OAEP:

```python
plaintext = PKCS1_OAEP.new(key).decrypt(ciphertext)
```


## 7. Flag

Flag thu được là:

```text
crypto{p00R_3570n14}
```


## 8. Nội dung `solve.py`

File `solve.py` trong thư mục này:

- đọc `key.pem`
- đọc `ciphertext.txt`
- dựng lại private key từ `p, q`
- giải mã ciphertext
- in ra `p`, `q` và flag

Chạy bằng:

```bash
python3 solve.py
```


## 9. Kết luận

Sai lầm của challenge không nằm ở OAEP hay ở tham số `e = 65537`, mà nằm ở việc sinh prime có cấu trúc quá mạnh:

```text
p = kM + 65537^a mod M
```

Prime “nhanh” nhưng không “ngẫu nhiên”.

Khi prime bị bó vào một subgroup residue modulo một primorial lớn, ta vô tình tạo ra đúng kiểu điều kiện để ROCA-like attacks hoạt động. Một khi factor được `n`, toàn bộ RSA sụp đổ ngay lập tức.
