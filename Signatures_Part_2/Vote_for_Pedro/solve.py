#!/usr/bin/env python3
import argparse
import json
import re
import socket
from pathlib import Path


MSG = b"VOTE FOR PEDRO"


def long_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def parse_key_file(path: Path) -> tuple[int, int]:
    data = path.read_text(encoding="utf-8")
    n_match = re.search(r"^\s*N\s*=\s*(\d+)\s*$", data, flags=re.MULTILINE)
    e_match = re.search(r"^\s*e\s*=\s*(\d+)\s*$", data, flags=re.MULTILINE)
    if not n_match or not e_match:
        raise ValueError(f"Invalid key format in {path}")
    return int(n_match.group(1)), int(e_match.group(1))


def cube_root_mod_power_of_two(m: int, k: int) -> int:
    if m % 2 == 0:
        raise ValueError("m must be odd for inverse modulo 2^k to exist during lifting")

    x = 1  # x ≡ 1 (mod 2)
    bits = 1
    while bits < k:
        bits = min(bits * 2, k)
        mod = 1 << bits
        denom = (3 * x * x) % mod
        inv_denom = pow(denom, -1, mod)
        x = (x - ((x * x * x - m) * inv_denom)) % mod
    return x


def forge_vote_signature(n: int, e: int, msg: bytes = MSG) -> int:
    if e != 3:
        raise ValueError(f"Expected e=3, got e={e}")

    m = int.from_bytes(msg, "big")
    k = (len(msg) + 1) * 8  # one leading 0x00 byte before message
    s = cube_root_mod_power_of_two(m, k)

    verified = pow(s, e, n)
    extracted = long_to_bytes(verified).split(b"\x00")[-1]
    if extracted != msg:
        raise RuntimeError("Forge failed: extracted vote is not target message")
    return s


def send_remote_vote(host: str, port: int, vote_hex: str) -> str:
    payload = json.dumps({"option": "vote", "vote": vote_hex}).encode() + b"\n"
    with socket.create_connection((host, port), timeout=10) as sock:
        _ = sock.recv(4096)  # banner
        sock.sendall(payload)
        response = sock.recv(4096)
    return response.decode(errors="replace").strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve CryptoHack Vote for Pedro challenge")
    parser.add_argument("--key", default="alice.key", help="Path to alice.key")
    parser.add_argument("--host", help="Remote host")
    parser.add_argument("--port", type=int, help="Remote port")
    args = parser.parse_args()

    n, e = parse_key_file(Path(args.key))
    forged_sig = forge_vote_signature(n, e)
    vote_hex = format(forged_sig, "x")

    print(f"[+] Forged vote (hex): {vote_hex}")
    verified = long_to_bytes(pow(forged_sig, e, n))
    extracted = verified.split(b"\x00")[-1]
    print(f"[+] pow(vote, e, n) bytes: {verified!r}")
    print(f"[+] Extracted after split: {extracted!r}")

    if args.host and args.port:
        reply = send_remote_vote(args.host, args.port, vote_hex)
        print(f"[+] Server reply: {reply}")


if __name__ == "__main__":
    main()
