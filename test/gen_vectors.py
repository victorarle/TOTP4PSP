#!/usr/bin/env python3
"""Generate test/vectors.txt: reference TOTP codes (SHA1, 6 digits, 30 s) for keys of 10 to 65 bytes.

Public data only: the key is the RFC 6238 seed ("12345678901234567890")
repeated or cut; in the "z" variant byte 10 (the last one if the key has 10
bytes) is set to 0x00. Line format: size variant time code secret_base32
"""
import base64, hashlib, hmac, struct

TIMES = (59, 1111111109, 1234567890, 2000000000)
SIZES = (10, 20, 32, 40, 63, 64, 65)
RFC = b"12345678901234567890"


def totp(key: bytes, t: int) -> str:
    h = hmac.new(key, struct.pack(">Q", t // 30), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10**6).zfill(6)


def make_key(n: int, zero: bool) -> bytes:
    k = bytearray((RFC * 4)[:n])
    if zero:
        k[min(10, n - 1)] = 0
    return bytes(k)


if __name__ == "__main__":
    # RFC 6238 appendix B (8 digits) cut to 6
    assert [totp(RFC, t) for t in TIMES] == ["287082", "081804", "005924", "279037"]
    for n in SIZES:
        for var, zero in (("n", False), ("z", True)):
            k = make_key(n, zero)
            b32 = base64.b32encode(k).decode().rstrip("=")
            for t in TIMES:
                print(n, var, t, totp(k, t), b32)
