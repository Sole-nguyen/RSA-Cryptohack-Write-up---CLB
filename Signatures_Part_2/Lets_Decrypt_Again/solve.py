#!/usr/bin/env python3
import hashlib
import json
import random
import socket
from typing import Dict, List, Tuple


HOST = "socket.cryptohack.org"
PORT = 13394
K = 96  # 768-bit block size
SHA1_DER_PREFIX = bytes.fromhex("3021300906052b0e03021a05000414")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def emsa_pkcs1_v15_sha1(msg: bytes, k: int = K) -> bytes:
    digest = hashlib.sha1(msg).digest()
    t = SHA1_DER_PREFIX + digest
    ps_len = k - len(t) - 3
    if ps_len < 8:
        raise ValueError("Intended encoded message length too short")
    return b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t


def digest_int(msg: str) -> int:
    return int.from_bytes(emsa_pkcs1_v15_sha1(msg.encode()), "big")


def crt_pairwise(congruences: List[Tuple[int, int]]) -> Tuple[int, int]:
    x, m = 0, 1
    for a, n in congruences:
        if m % n == 0:
            x %= m
            continue
        inv = pow(m, -1, n)
        t = ((a - x) % n) * inv % n
        x += m * t
        m *= n
        x %= m
    return x, m


def primes_upto(n: int) -> List[int]:
    sieve = [True] * (n + 1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(n**0.5) + 1):
        if sieve[i]:
            step = i
            start = i * i
            sieve[start:n + 1:step] = [False] * (((n - start) // step) + 1)
    return [i for i, ok in enumerate(sieve) if ok]


def is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def find_smooth_prime_with_generator(sig: int, target_bits: int = 754) -> Tuple[int, int, List[int]]:
    base_primes = [p for p in primes_upto(1400) if p != 2]
    attempt = 0
    while True:
        attempt += 1
        used = set()
        factors = [2]
        order = 2
        while order.bit_length() < target_bits:
            q = random.choice(base_primes)
            if q in used:
                continue
            used.add(q)
            factors.append(q)
            order *= q

        p = order + 1
        if not is_probable_prime(p):
            continue
        if sig % p == 0:
            continue

        g = sig % p
        primitive = True
        for q in factors:
            if pow(g, order // q, p) == 1:
                primitive = False
                break
        if primitive:
            print(f"[+] Found smooth prime p on attempt {attempt} (bits={p.bit_length()}, factors={len(factors)})")
            return p, order, factors

        if attempt % 100 == 0:
            print(f"[*] Prime search attempts: {attempt}")


def dlog_smooth_prime(g: int, h: int, p: int, order: int, factors: List[int]) -> int:
    congruences = []
    for q in factors:
        gq = pow(g, order // q, p)
        hq = pow(h, order // q, p)
        found = None
        cur = 1
        for x in range(q):
            if cur == hq:
                found = x
                break
            cur = (cur * gq) % p
        if found is None:
            raise ValueError(f"Discrete log failed in subgroup q={q}")
        congruences.append((found, q))
    x, _ = crt_pairwise(congruences)
    return x


def base58_encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    x = int.from_bytes(data, "big")
    out = []
    while x > 0:
        x, r = divmod(x, 58)
        out.append(alphabet[r])
    out = "".join(reversed(out)) if out else "1"
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeroes + out


def btc_address_from_counter(counter: int) -> str:
    payload20 = counter.to_bytes(20, "big", signed=False)
    versioned = b"\x00" + payload20
    chk = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58_encode(versioned + chk)


class Remote:
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port))
        self.sock.settimeout(10)
        self.buf = b""
        self._drain_banner()

    def _readline(self) -> bytes:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("Connection closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line + b"\n"

    def _drain_banner(self) -> None:
        self.sock.settimeout(1.0)
        try:
            while True:
                line = self._readline().decode(errors="ignore").strip()
                if not line:
                    continue
                if line.startswith("{") and line.endswith("}"):
                    self.buf = line.encode() + b"\n" + self.buf
                    break
        except Exception:
            pass
        finally:
            self.sock.settimeout(10)

    def req(self, payload: Dict) -> Dict:
        raw = json.dumps(payload).encode() + b"\n"
        self.sock.sendall(raw)
        while True:
            s = self._readline().decode(errors="ignore").strip()
            if not s:
                continue
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                continue

    def close(self) -> None:
        self.sock.close()


def make_msg(index: int, counter: int) -> str:
    if index == 0:
        return f"This is a test{'A' * counter}for a fake signature."
    if index == 1:
        return f"My name is Alice{'A' * counter} and I own CryptoHack.org"
    if index == 2:
        return f"Please send all my money to {btc_address_from_counter(counter)}"
    raise ValueError("invalid index")


def find_valid_message(index: int, suffix: str, sig: int, p: int, required_mod2: int) -> Tuple[str, int]:
    counter = 0
    while True:
        prefix = make_msg(index, counter)
        full = prefix + suffix
        d = digest_int(full)
        if (d & 1) == required_mod2 and (d % p) != 0:
            return full, d
        counter += 1


def main() -> None:
    io = Remote(HOST, PORT)
    try:
        info = io.req({"option": "get_signature"})
        sig = int(info["signature"], 16)
        print(f"[+] Retrieved signature S ({sig.bit_length()} bits)")

        p, order, factors = find_smooth_prime_with_generator(sig, target_bits=754)
        n = 2 * p
        setpk = io.req({"option": "set_pubkey", "pubkey": hex(n)})
        if "error" in setpk:
            raise RuntimeError(f"set_pubkey failed: {setpk}")
        suffix = setpk["suffix"]
        print(f"[+] Received suffix: {suffix}")

        required_mod2 = 1 if (sig & 1) else 0
        shares = []
        for idx in range(3):
            msg, d = find_valid_message(idx, suffix, sig, p, required_mod2)
            e = dlog_smooth_prime(sig % p, d % p, p, order, factors)
            if (sig & 1) == 0 and e == 0:
                e += order
            if pow(sig, e, n) != d:
                raise RuntimeError(f"Internal check failed before claim (index={idx})")

            ans = io.req({
                "option": "claim",
                "msg": msg,
                "e": hex(e),
                "index": idx
            })
            if "secret" not in ans:
                raise RuntimeError(f"claim failed for index {idx}: {ans}")
            shares.append(bytes.fromhex(ans["secret"]))
            print(f"[+] Got share {idx}: {ans['secret']}")

        flag = shares[0]
        for s in shares[1:]:
            flag = xor_bytes(flag, s)
        print(f"[+] FLAG: {flag.decode(errors='replace')}")
    finally:
        io.close()


if __name__ == "__main__":
    main()
