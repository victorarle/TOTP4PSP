#!/usr/bin/env python3
"""Gera test/vetores.txt: gabarito TOTP (SHA1, 6 dígitos, 30 s) para chaves de 10 a 65 bytes.

Só dados públicos: a chave é a semente da RFC 6238 ("12345678901234567890")
repetida ou cortada; na variante "z" o byte 10 (o último, se a chave tem 10
bytes) vira 0x00. Formato: tamanho variante instante codigo segredo_base32
"""
import base64, hashlib, hmac, struct

INSTANTES = (59, 1111111109, 1234567890, 2000000000)
TAMANHOS = (10, 20, 32, 40, 63, 64, 65)
RFC = b"12345678901234567890"


def totp(chave: bytes, t: int) -> str:
    h = hmac.new(chave, struct.pack(">Q", t // 30), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10**6).zfill(6)


def chave(n: int, zero: bool) -> bytes:
    k = bytearray((RFC * 4)[:n])
    if zero:
        k[min(10, n - 1)] = 0
    return bytes(k)


if __name__ == "__main__":
    # a RFC 6238 apêndice B (8 dígitos) truncada a 6
    assert [totp(RFC, t) for t in INSTANTES] == ["287082", "081804", "005924", "279037"]
    for n in TAMANHOS:
        for var, zero in (("n", False), ("z", True)):
            k = chave(n, zero)
            b32 = base64.b32encode(k).decode().rstrip("=")
            for t in INSTANTES:
                print(n, var, t, totp(k, t), b32)
