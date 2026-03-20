from sage.all import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
import binascii
msg = bytes_to_long(b'VOTE FOR PEDRO')
modulus = 256**15
Zmod_n = Zmod(modulus)
x_candidates = Zmod_n(msg).nth_root(3, all=True)
for x in x_candidates:
    if x**3 == msg:
        print(hex(x))
        break