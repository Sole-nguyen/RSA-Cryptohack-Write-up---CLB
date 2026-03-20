# RSA Backdoor Viability - Writeup

## 1. Challenge cung cấp
Challenge cung cấp 1 file complex_primes và 1 file output.txt
```python 
#!/usr/bin/env python3

import random
from Crypto.Util.number import bytes_to_long, getPrime, isPrime

FLAG = b"crypto{????????????????????????????????}"

def get_complex_prime():
    D = 427
    while True:
        s = random.randint(2 ** 1020, 2 ** 1021 - 1)
        tmp = D * s ** 2 + 1
        if tmp % 4 == 0 and isPrime((tmp // 4)):
            return tmp // 4


m = bytes_to_long(FLAG)
p = get_complex_prime()
q = getPrime(2048)
n = p * q
e = 0x10001
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")

```
Challenge sinh:
- `p = (D*s^2 + 1)/4` với `D = 427` (prime có cấu trúc đặc biệt, kiểu backdoor)
- `q` là prime ngẫu nhiên 2048-bit
- `n = p*q`, `e = 65537`, `c = m^e mod n`

Mục tiêu: khôi phục `m`

## 2. Ý tưởng tấn công

Điểm yếu là `p` không random đúng nghĩa, mà bị ép theo dạng:

$4p - 1 = D s^2$

Đây là đúng mô hình trong paper *“I Want to Break Square-free: The 4p-1 Factorization Method and Its RSA Backdoor Viability”* (CM-based attack)
Với `D` đã biết, có thể factor `n` nhanh hơn RSA thường

Trong thực chiến, có thể triển khai tấn công CM bằng Sage (`hilbert_class_polynomial`, `EllipticCurve`, division polynomial) để tách được 1 thừa số của `n`. (Claude nói thế =)))))))

## 3. Giải mã
```python
#!/usr/bin/env python3
import re
from pathlib import Path

from Crypto.Util.number import long_to_bytes
def parse_params(path: Path):
    data = path.read_text()
    n = int(re.search(r"n\s*=\s*(\d+)", data).group(1))
    e = int(re.search(r"e\s*=\s*(\d+)", data).group(1))
    c = int(re.search(r"c\s*=\s*(\d+)", data).group(1))
    return n, e, c

def main():
    output_files = sorted(Path(".").glob("output_*.txt"))
    n, e, c = parse_params(output_files[0])
    # Hai thừa số này thu được từ tấn công CM (4p-1 backdoor, D=427).
    p = 20365029276121374486239093637518056591173153560816088704974934225137631026021006278728172263067093375127799517021642683026453941892085549596415559632837140072587743305574479218628388191587060262263170430315761890303990233871576860551166162110565575088243122411840875491614571931769789173216896527668318434571140231043841883246745997474500176671926153616168779152400306313362477888262997093036136582318881633235376026276416829652885223234411339116362732590314731391770942433625992710475394021675572575027445852371400736509772725581130537614203735350104770971283827769016324589620678432160581245381480093375303381611323
    q = 34857423162121791604235470898471761566115159084585269586007822559458774716277164882510358869476293939176287610274899509786736824461740603618598549945273029479825290459062370424657446151623905653632181678065975472968242822859926902463043730644958467921837687772906975274812905594211460094944271575698004920372905721798856429806040099698831471709774099003441111568843449452407542799327467944685630258748028875103444760152587493543799185646692684032460858150960790495575921455423185709811342689185127936111993248778962219413451258545863084403721135633428491046474540472029592613134125767864006495572504245538373207974181

    assert p * q == n
    backdoor_prime = p if (4 * p - 1) % 427 == 0 else q
    assert (4 * backdoor_prime - 1) % 427 == 0

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)

    flag = long_to_bytes(m).decode()
    print(flag)

if __name__ == "__main__":
    main()
```

**FLag**: `crypto{I_want_to_Break_Square-free_4p-1}`