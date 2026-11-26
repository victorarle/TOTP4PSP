#!/usr/bin/env python3
"""Teste nativo do totp.c (build: make -C test).

    python3 test/run.py                      # espera o comportamento do v0.0.1
    python3 test/run.py --esperado corrigido # espera tudo certo

Só segredos públicos (semente da RFC 6238). Sai com 0 se o resultado bate com
o esperado do modo escolhido.
"""
import argparse, base64, hashlib, hmac, os, struct, subprocess, sys, tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
from gerar_vetores import RFC, totp  # noqa: E402

HOST = os.path.join(AQUI, "host")
ENV = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
CAB = "otpauth://totp/{n}?algorithm=SHA1&digits=6&issuer=T&period=30&secret={s}"
B32 = base64.b32encode(RFC).decode().rstrip("=")
VALIDA = CAB.format(n="OK", s=B32).encode()  # t=59 -> "OK 287082"


def roda(conteudo, t=59):
    """Roda o host sobre um arquivo; devolve ('ok', saída) ou ('crash'|'travou', detalhe)."""
    with tempfile.TemporaryDirectory() as d:
        caminho = os.path.join(d, "OTPAUTH_KEYS")
        if conteudo is not None:
            open(caminho, "wb").write(conteudo)
        try:
            p = subprocess.run([HOST, caminho, str(t)], capture_output=True, env=ENV, timeout=10)
        except subprocess.TimeoutExpired:
            return "travou", ""
    if p.returncode != 0:
        linha = next((l for l in p.stderr.decode(errors="replace").splitlines() if "Sanitizer" in l or "runtime error" in l), f"rc={p.returncode}")
        return "crash", linha.strip()[:80]
    return "ok", p.stdout.decode()


def emula_v001(k: bytes):
    """Prevê o v0.0.1 (defeito 1): 'OK', 'ERRADO' ou 'INDEF' (lê memória não inicializada)."""
    d = k + b"\0"
    comp = d.index(b"\0")
    buflen = 21 if comp < 20 else comp + 1
    if buflen > len(k) + 1:
        return "INDEF"
    usada = d[:buflen]
    return "OK" if totp(usada, 59) == totp(k, 59) and totp(usada, 1234567890) == totp(k, 1234567890) else "ERRADO"


def matriz(esperado):
    linhas, falhas = [], 0
    casos = {}
    for l in open(os.path.join(AQUI, "vetores.txt")):
        n, var, t, cod, b32 = l.split()
        casos.setdefault((int(n), var, b32), []).append((int(t), cod))
    for (n, var, b32), vet in casos.items():
        k = base64.b32decode(b32 + "=" * (-len(b32) % 8))
        prev = emula_v001(k)
        reais = []
        for t, cod in vet:
            st, saida = roda(CAB.format(n="K", s=b32).encode() + b"\n", t)
            reais.append("CRASH" if st != "ok" else ("OK" if saida.strip() == "K " + cod else "ERRADO"))
        real = "OK" if set(reais) == {"OK"} else ("CRASH" if "CRASH" in reais else "ERRADO")
        if esperado == "corrigido":
            bate = real == "OK"; quer = "OK"
        else:
            # INDEF: lê memória não inicializada; qualquer resultado sem crash vale
            bate = real != "CRASH" if prev == "INDEF" else real == prev; quer = prev
        falhas += not bate
        linhas.append(f"{'ok ' if bate else 'XX '} {n:>3} bytes {'com zero ' if var == 'z' else 'sem zero '} real={real:<6} esperado={quer}")
    return linhas, falhas


def malformadas(esperado):
    big = b"otpauth://totp/" + b"A" * 3000
    k11 = RFC[:11]
    pad = base64.b32encode(k11).decode()  # termina em ======
    casos = [  # nome, conteúdo, saída certa, o que o v0.0.1 deve fazer (ok|falha)
        ("arquivo ausente", None, "", "falha"),
        ("arquivo vazio", b"", "", "ok"),
        ("linha em branco", b"\n" + VALIDA + b"\n", "OK 287082\n", "falha"),
        ("linha curta", b"abc\n" + VALIDA + b"\n", "OK 287082\n", "falha"),
        ("sem '?'", b"otpauth://totp/X\n" + VALIDA + b"\n", "OK 287082\n", "falha"),
        ("sem secret=", b"otpauth://totp/X?algorithm=SHA1&digits=6\n" + VALIDA + b"\n", "OK 287082\n", "falha"),
        ("sem algorithm=", b"otpauth://totp/X?digits=6&secret=" + B32.encode() + b"\n" + VALIDA + b"\n", "X 287082\nOK 287082\n", "falha"),  # ausente = SHA1
        ("parametro sem '='", b"otpauth://totp/X?algorithm=SHA1&digits&secret=" + B32.encode() + b"\n" + VALIDA + b"\n", "X 287082\nOK 287082\n", "falha"),  # par ignorado, digits = padrão
        ("secret com '='", CAB.format(n="P", s=pad).encode() + b"\n", f"P {totp(k11, 59)}\n", "falha"),
        ("base32 invalido", CAB.format(n="X", s="!!!!!!!!").encode() + b"\n" + VALIDA + b"\n", "OK 287082\n", "falha"),
        ("linha de 3000", big + b"\n" + VALIDA + b"\n", "OK 287082\n", "falha"),
        ("CRLF", VALIDA + b"\r\n", "OK 287082\n", "ok"),
    ]
    linhas, falhas = [], 0
    for nome, cont, certo, prev in casos:
        st, saida = roda(cont)
        real = "ok" if st == "ok" and saida == certo else "falha"
        quer = "ok" if esperado == "corrigido" else prev
        bate = real == quer
        falhas += not bate
        det = "" if real == "ok" else (f"{st}: {saida}" if st != "ok" else f"saída {saida!r}")
        linhas.append(f"{'ok ' if bate else 'XX '} {nome:<18} real={real:<5} esperado={quer:<5} {det[:70]}")
    return linhas, falhas


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--esperado", choices=("v0.0.1", "corrigido"), default="v0.0.1")
    a = ap.parse_args()
    if not os.path.exists(HOST):
        sys.exit("falta test/host: make -C test")
    total = 0
    for titulo, f in (("Matriz de tamanhos (RFC 6238, 4 instantes cada)", matriz), ("Linhas malformadas", malformadas)):
        ls, fl = f(a.esperado)
        print(f"\n{titulo}  [esperado: {a.esperado}]")
        print("\n".join(ls))
        total += fl
    print(f"\n{'TUDO COMO ESPERADO' if not total else str(total) + ' DIVERGÊNCIA(S) do esperado'} (modo {a.esperado})")
    sys.exit(1 if total else 0)
