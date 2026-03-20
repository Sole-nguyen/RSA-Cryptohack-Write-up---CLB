# CryptoHack 13386 - Bespoke Padding

## Ý tưởng chính

Server dùng:

- `m = bytes_to_long(FLAG)`
- random `a, b`
- `M = a*m + b`
- `c = M^e mod N`, với `e = 11`

Điểm yếu là server **trả luôn `a, b`** và cho gọi nhiều lần với cùng `m`, cùng `N`.

Mỗi lần gọi ta có:

`(a_i * m + b_i)^e ≡ c_i (mod N)`

Với 2 mẫu khác nhau:

- `f1(x) = (a1*x + b1)^e - c1`
- `f2(x) = (a2*x + b2)^e - c2`

Trong vành `Z_N[x]`, nghiệm chung của `f1, f2` là `x = m`, nên:

`gcd(f1, f2) = u*x + v` (thường là bậc 1)

=> `m = -v * u^{-1} mod N`.

Đây là dạng Franklin-Reiter related-message attack (biến thể tuyến tính theo cùng thông điệp gốc).

## Cách script hoạt động (`solve.py`)

1. Kết nối `socket.cryptohack.org:13386`.
2. Gửi `{"option":"get_flag"}` nhiều lần để lấy ~8 mẫu.
3. Dựng 2 đa thức cho từng cặp mẫu.
4. Tính GCD đa thức modulo `N` bằng Euclid (code thuần Python, không cần Sage).
5. Nếu GCD bậc 1, suy ra `m`.
6. Đổi `m` -> bytes và regex `crypto{...}`.

## Chạy

```bash
python3 solve.py
```

Nếu hiếm khi chưa ra flag (do cặp mẫu không đẹp), tăng số mẫu trong script (ví dụ 12 hoặc 16).
