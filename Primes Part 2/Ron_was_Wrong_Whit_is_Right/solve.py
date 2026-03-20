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