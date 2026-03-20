# CryptoHack - Vote for Pedro (Signatures Part 2)

## 1) Tom tat de bai

Server nhan input:

```python
vote = int(your_input['vote'], 16)
verified_vote = long_to_bytes(pow(vote, ALICE_E, ALICE_N))
vote = verified_vote.split(b'\x00')[-1]
if vote == b'VOTE FOR PEDRO':
    return {"flag": FLAG}
```

Public key:

- `e = 3`
- `n` la so RSA rat lon (2048-bit)

Muc tieu: tim gia tri `vote` (thuc chat la signature) sao cho khi server tinh `vote^e mod n`, sau do tach theo byte `0x00`, phan sau byte `0x00` cuoi cung la chuoi `VOTE FOR PEDRO`.

---

## 2) Lo hong nam o dau?

Server verify signature theo kieu "raw RSA", sau do parse padding rat long leo:

- Khong kiem tra format PKCS#1 v1.5 / PSS.
- Khong kiem tra hash ASN.1.
- Chi can co suffix hop le sau `\x00`.

Dong:

```python
verified_vote.split(b'\x00')[-1]
```

co nghia la:

- Neu trong `verified_vote` co nhieu byte `0x00`, server lay doan **sau byte 0x00 cuoi cung**.
- Neu ta tao duoc `... \x00 VOTE FOR PEDRO` (khong co `0x00` trong message), check se pass.

---

## 3) Bien doi thanh bai toan dong du

Dat:

- `M = bytes_to_long(b"VOTE FOR PEDRO")`
- Can tim `s` (signature) sao cho:

`long_to_bytes(s^3 mod n)` co suffix `\x00 || "VOTE FOR PEDRO"`.

Neu ta ep:

`s^3 ≡ M (mod 2^120)`

thi 15 byte cuoi cua `s^3` se la:

- 1 byte `0x00` (byte thu 15 tu cuoi)
- 14 byte message `"VOTE FOR PEDRO"`

Vi sao `120` bit?

- message dai 14 byte = 112 bit
- can them 1 byte `0x00` truoc message
- tong = 15 byte = 120 bit

---

## 4) Tai sao giai duoc `s^3 ≡ M (mod 2^120)`?

`M` la so le (byte cuoi `'O' = 0x4f`), nen `M` thuoc nhom don vi modulo `2^k`.

Voi `k >= 3`, phep nang mu 3 tren cac so le modulo `2^k` la kha nghich (vi `gcd(3, 2^(k-2)) = 1`), nen ton tai nghiem cube root modulo `2^k`.

Ta dung Newton/Hensel lifting trong 2-adic:

`x_{new} = x - (x^3 - M) * (3x^2)^(-1) mod 2^t`

lap lai voi so bit tang dan den `t = 120`.

---

## 5) Trick quan trong de tranh modulo n pha vo suffix

Server tinh `pow(s, 3, n)`.

Neu `s^3 < n` thi:

`s^3 mod n = s^3`

nghia la khong bi wrap-around theo `n`, suffix ta vua dung se giu nguyen.

Nghiem `s` modulo `2^120` co kich thuoc xap xi 120 bit, nen `s^3` xap xi 360 bit, nho hon rat nhieu so voi `n` 2048-bit. Do do dieu kien `s^3 < n` de dang dat duoc.

---

## 6) Script giai (`solve.py`)

Script da tao:

- Doc `N, e` tu `alice.key`
- Tinh cube root modulo `2^120`
- Tao forged signature `s`
- Tu verify local:
  - tinh `pow(s, e, n)`
  - split theo `\x00`
  - check ra dung `b"VOTE FOR PEDRO"`
- Co tuy chon gui remote (`--host --port`)

Chay local:

```bash
python3 solve.py
```

Ket qua mau:

```text
[+] Forged vote (hex): a4c46bfb65e7eccc4e76a1ce2afc6f
[+] pow(vote, e, n) bytes: b'... \x00VOTE FOR PEDRO'
[+] Extracted after split: b'VOTE FOR PEDRO'
```

Gui len server:

```bash
python3 solve.py --host <host> --port 13375
```

---

## 7) Vi sao day la bai "signature forgery" kinh dien?

Day la mau loi thuong gap:

- Dung raw RSA thay vi verify dung chuan.
- Parse "padding" bang string operation don gian.
- Khong rang buoc cau truc signature day du.

Voi `e = 3`, viec tao gia tri co dang mong muon o cac bit thap tro nen de dang (dac biet voi phep dong du tren luy thua cua 2).

---

## 8) Cach fix dung (defense)

Khong tu implement verify signature theo kieu `pow(sig, e, n)` + parse tay.

Can:

- Dung thu vien crypto uy tin.
- Dung RSA-PSS hoac PKCS#1 v1.5 verify dung chuan.
- Verify tren hash + ASN.1 + full padding structure.
- Reject ngay neu signature format sai bat ky byte nao.

---

## 9) Ket luan

Exploit thanh cong nho 3 diem:

1. Server chi check suffix sau `0x00` cuoi.
2. `e = 3` cho phep dung cube root modulo `2^120`.
3. Chon `s` nho de `s^3 < n`, giu nguyen payload khi verify.

Tu do tao duoc forged vote hop le va lay flag.
