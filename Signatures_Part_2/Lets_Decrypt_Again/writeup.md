# CryptoHack RSA - Signatures Part 2: Let's Decrypt Again (13394)

## 1) Đề bài và bề mặt tấn công

Server có 3 API chính:

- `get_signature`: trả về `N`, `E`, và **một chữ ký cố định** `SIGNATURE`.
- `set_pubkey`: cho phép user tự set modulus `pubkey` (chỉ cấm số nguyên tố), rồi server trả `suffix` ngẫu nhiên.
- `claim`: server kiểm tra:

```python
digest = emsa_pkcs1_v15.encode(msg.encode(), 96)
calculated_digest = pow(SIGNATURE, e, n)   # n do mình set
if bytes_to_long(digest) == calculated_digest:
    # nếu msg[:-len(suffix)] match pattern[index] -> trả 1 share
```

Điểm yếu cốt lõi:

1. Server **không verify chữ ký theo chuẩn RSA** (không có message/signature do user gửi để verify bằng public key thật).
2. Server dùng `SIGNATURE` cố định, nhưng lại cho attacker chọn tự do `n` và `e`.
3. Cần pass 3 pattern khác nhau để lấy 3 share rồi XOR ra flag.

---

## 2) Logic cần phá

Ta cần với mỗi message:

\[
\text{pow}(S, e, n) = D
\]

Trong đó:
- \(S = SIGNATURE\) (biết),
- \(D = \text{bytes\_to\_long}(\text{EMSA}(msg))\) (tự tính được),
- \(n\) chỉ set được **một lần** cho cả session.

Vì `msg` chứa `suffix` random (server trả sau khi set pubkey), nên không dùng trick đơn giản kiểu \(n = S-D\) riêng lẻ cho từng message như bài Part 1.

---

## 3) Ý tưởng khai thác tổng quát

### 3.1 Chọn modulus composite đặc biệt

Chọn:

\[
n = 2p
\]

với \(p\) là prime lớn, sao cho:

- \(p - 1\) là **smooth** (phân tích thừa số nhỏ, biết trước),
- \(S \bmod p\) là **generator** của \(\mathbb{Z}_p^*\).

Khi đó bài toán trở thành discrete log mod \(p\):

\[
S^e \equiv D \pmod p
\]

Nếu \(S\) là generator thì mọi \(D \not\equiv 0 \pmod p\) đều có nghiệm \(e\).

Ta giải DLP bằng **Pohlig-Hellman** rất nhanh vì \(p-1\) smooth.

### 3.2 Điều kiện modulo 2

Vì \(n=2p\), cần đồng thời:

- \(S^e \equiv D \pmod p\)  (giải bằng DLP),
- \(S^e \equiv D \pmod 2\).

Điều kiện mod 2 rất nhẹ:
- nếu \(S\) lẻ thì \(S^e \equiv 1 \pmod 2\), nên cần \(D\) lẻ.
- nếu \(S\) chẵn và \(e>0\) thì \(S^e \equiv 0 \pmod 2\), nên cần \(D\) chẵn.

Ta **bruteforce biến tự do trong message** để ép parity của \(D\) đúng ý.

---

## 4) Vì sao bruteforce message làm được?

Ba pattern đều có phần tự do:

1. `^This is a test(.*)for a fake signature.$`  
   -> thay đổi chuỗi trong `(.*)`.

2. `^My name is ([a-zA-Z\s]+) and I own CryptoHack.org$`  
   -> thay đổi `name` bằng chữ cái/spaces.

3. `Please send all my money to <btc_address>`  
   -> tạo nhiều địa chỉ Bitcoin Base58Check hợp lệ khác nhau.

Vì hash trong EMSA phụ thuộc toàn bộ message (kể cả suffix), chỉ cần thử counter tăng dần là parity \(D \bmod 2\) sẽ đổi ngẫu nhiên; kỳ vọng vài lần là đạt.

---

## 5) Chi tiết toán rời rạc (Pohlig-Hellman dạng gọn)

Giả sử:

\[
|G| = p-1 = \prod_i q_i
\]

với \(q_i\) là các prime nhỏ, **không lặp**.

Cần tìm \(x\) sao cho:

\[
g^x = h \pmod p
\]

Với từng \(q_i\):

\[
g_i = g^{(p-1)/q_i}, \quad h_i = h^{(p-1)/q_i}
\]

Khi đó \(g_i\) có order \(q_i\), nên brute-force \(x_i \in [0, q_i-1]\):

\[
g_i^{x_i} = h_i \pmod p
\]

=> thu được hệ:

\[
x \equiv x_i \pmod{q_i}
\]

Ghép bằng CRT để ra \(x \pmod{p-1}\).

---

## 6) Một bẫy quan trọng: EMSA dùng SHA-1

Dù file challenge import `hashlib.sha256` cho phần check Bitcoin, phần chữ ký dùng:

```python
from pkcs1 import emsa_pkcs1_v15
digest = emsa_pkcs1_v15.encode(msg.encode(), 96)
```

Trong bộ challenge này, `emsa_pkcs1_v15.encode` mặc định là **SHA-1** (như bài Part 1).
Nếu tự dựng EMSA-SHA256 sẽ luôn sai chữ ký.

`DigestInfo` đúng cho SHA-1:

```
3021300906052b0e03021a05000414 || SHA1(msg)
```

---

## 7) Luồng exploit trong `solve.py`

1. Kết nối `socket.cryptohack.org:13394`.
2. Gọi `get_signature`, lấy `S`.
3. Sinh prime \(p\) thỏa:
   - `p = order + 1` prime,
   - `order` là tích nhiều prime nhỏ khác nhau,
   - `S mod p` là primitive root.
4. Set `pubkey = 2*p`, lấy `suffix`.
5. Với từng `index = 0,1,2`:
   - Sinh message hợp pattern tương ứng + suffix.
   - Điều chỉnh biến tự do để thỏa parity modulo 2 và `D % p != 0`.
   - Tính \(e = \log_S(D) \mod (p-1)\) bằng Pohlig-Hellman.
   - Gửi `claim`.
6. XOR 3 share -> flag.

---

## 8) Kết quả

Chạy:

```bash
python3 solve.py
```

Output nhận được:

```text
crypto{let's_decrypt_w4s_t0o_ez_do_1t_ag41n}
```

---

## 9) Tóm tắt lỗi thiết kế

- Không bao giờ cho attacker tự chọn tham số RSA (`n`, `e`) trong logic verify chữ ký thật.
- Không verify theo chuẩn “signature của message dưới public key đáng tin”.
- Reuse chữ ký cố định + so sánh trực tiếp số học modular tạo điều kiện dựng bài toán DLP “theo ý attacker”.

Đây là lỗi thiết kế giao thức (protocol design flaw), không phải bug implementation nhỏ.
