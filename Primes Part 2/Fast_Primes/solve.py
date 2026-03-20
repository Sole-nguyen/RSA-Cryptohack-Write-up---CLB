#!/usr/bin/env python3

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse


N = 4013610727845242593703438523892210066915884608065890652809524328518978287424865087812690502446831525755541263621651398962044653615723751218715649008058509
E = 65537

# Recovered from the ROCA-like structure used by the challenge generator.
P = 51894141255108267693828471848483688186015845988173648228318286999011443419469
Q = 77342270837753916396402614215980760127245056504361515489809293852222206596161


def load_inputs():
    public_key = RSA.import_key(open("key.pem", "rb").read())
    ciphertext = bytes.fromhex(open("ciphertext.txt", "r", encoding="utf-8").read().strip())
    return public_key, ciphertext


def build_private_key():
    if P * Q != N:
        raise ValueError("Recovered factors do not match the expected modulus")

    phi = (P - 1) * (Q - 1)
    d = inverse(E, phi)
    return RSA.construct((N, E, d, P, Q))


def main():
    public_key, ciphertext = load_inputs()
    if public_key.n != N or public_key.e != E:
        raise ValueError("This solver is tailored to the provided challenge instance only")

    private_key = build_private_key()
    plaintext = PKCS1_OAEP.new(private_key).decrypt(ciphertext)

    print(f"p = {P}")
    print(f"q = {Q}")
    print(plaintext.decode())


if __name__ == "__main__":
    main()
