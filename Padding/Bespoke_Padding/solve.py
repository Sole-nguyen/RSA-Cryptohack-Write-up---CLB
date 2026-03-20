#!/usr/bin/env python3
import itertools
import json
import re
import socket
HOST = "socket.cryptohack.org"
PORT = 13386
E = 11
def trim(poly):
    while poly and poly[-1] == 0:
        poly.pop()
    return poly
def poly_mul(a, b, mod):
    if not a or not b:
        return []
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] = (out[i + j] + x * y) % mod
    return trim(out)
def poly_pow_linear(a, b, e, mod):
    # (a*x + b)^e, biểu diễn theo hệ số tăng dần bậc: [c0, c1, c2, ...]
    base = [b % mod, a % mod]
    out = [1]
    for _ in range(e):
        out = poly_mul(out, base, mod)
    return out


def poly_divmod(a, b, mod):
    a = trim(a[:])
    b = trim(b[:])
    if not b:
        raise ZeroDivisionError("divide by zero polynomial")
    if len(a) < len(b):
        return [], a

    q = [0] * (len(a) - len(b) + 1)
    inv_lead = pow(b[-1], -1, mod)

    while a and len(a) >= len(b):
        k = len(a) - len(b)
        coeff = (a[-1] * inv_lead) % mod
        q[k] = coeff
        for i in range(len(b)):
            a[i + k] = (a[i + k] - coeff * b[i]) % mod
        trim(a)

    return trim(q), trim(a)


def poly_gcd(a, b, mod):
    a = trim(a[:])
    b = trim(b[:])
    while b:
        _, r = poly_divmod(a, b, mod)
        a, b = b, r
    if not a:
        return []
    inv = pow(a[-1], -1, mod)
    return [(x * inv) % mod for x in a]


def int_to_bytes(x):
    if x == 0:
        return b"\x00"
    size = (x.bit_length() + 7) // 8
    return x.to_bytes(size, "big")


def recv_json(io):
    while True:
        line = io.readline()
        if not line:
            raise ConnectionError("server closed connection")
        s = line.decode(errors="ignore").strip()
        if not s:
            continue
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            # CryptoHack service đôi khi gửi banner text trước JSON
            continue


def request_sample(io):
    io.write(json.dumps({"option": "get_flag"}).encode() + b"\n")
    io.flush()
    data = recv_json(io)
    return (
        data["padding"][0],
        data["padding"][1],
        data["encrypted_flag"],
        data["modulus"],
    )


def recover_flag(samples):
    n = samples[0][3]
    for (a1, b1, c1, _), (a2, b2, c2, _) in itertools.combinations(samples, 2):
        f1 = poly_pow_linear(a1, b1, E, n)
        f2 = poly_pow_linear(a2, b2, E, n)
        f1[0] = (f1[0] - c1) % n
        f2[0] = (f2[0] - c2) % n

        try:
            g = poly_gcd(f1, f2, n)
        except ValueError:
            continue

        # gcd dạng tuyến tính: g(x) = u*x + v  =>  x = -v/u (mod n)
        if len(g) == 2:
            u = g[1]
            v = g[0]
            try:
                m = (-v * pow(u, -1, n)) % n
            except ValueError:
                continue
            msg = int_to_bytes(m)
            mobj = re.search(rb"crypto\{[^}]*\}", msg)
            if mobj:
                return mobj.group(0).decode()
    return None


def main():
    with socket.create_connection((HOST, PORT)) as sock:
        io = sock.makefile("rwb", buffering=0)
        banner = recv_json(io)
        print("[*] banner:", banner.get("message", "").strip())

        samples = [request_sample(io) for _ in range(8)]
        if len({s[3] for s in samples}) != 1:
            raise RuntimeError("modulus changed between samples")

        flag = recover_flag(samples)
        if not flag:
            raise RuntimeError("could not recover flag, try increasing sample count")
        print("[+] flag:", flag)


if __name__ == "__main__":
    main()
