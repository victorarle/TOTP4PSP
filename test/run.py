#!/usr/bin/env python3
"""Host test for totp.c (build: make -C test).

    python3 test/run.py                           # build, expect everything right
    python3 test/run.py --expect v0.0.1 --host BIN  # binary built from the unfixed code: expect the known defects

Public secrets only (the RFC 6238 seed). Exits 0 if the result matches what
the chosen mode expects.
"""
import argparse, base64, hashlib, hmac, os, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gen_vectors import RFC, totp  # noqa: E402

HOST = os.path.join(HERE, "host")
ENV = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
URI = "otpauth://totp/{n}?algorithm=SHA1&digits=6&issuer=T&period=30&secret={s}"
B32 = base64.b32encode(RFC).decode().rstrip("=")
VALID = URI.format(n="OK", s=B32).encode()  # t=59 -> "OK 287082"


def run(content, t=59):
    """Run the host binary on a key file; returns ('ok', stdout) or ('crash'|'hang', detail)."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "OTPAUTH_KEYS")
        if content is not None:
            open(path, "wb").write(content)
        try:
            p = subprocess.run([HOST, path, str(t)], capture_output=True, env=ENV, timeout=10)
        except subprocess.TimeoutExpired:
            return "hang", ""
    if p.returncode != 0:
        line = next((l for l in p.stderr.decode(errors="replace").splitlines() if "Sanitizer" in l or "runtime error" in l), f"rc={p.returncode}")
        return "crash", line.strip()[:80]
    return "ok", p.stdout.decode()


def emulate_v001(k: bytes):
    """Predict v0.0.1 (defect 1): 'OK', 'WRONG' or 'UNDEF' (reads uninitialised memory)."""
    d = k + b"\0"
    strlen = d.index(b"\0")
    buflen = 21 if strlen < 20 else strlen + 1
    if buflen > len(k) + 1:
        return "UNDEF"
    used = d[:buflen]
    return "OK" if totp(used, 59) == totp(k, 59) and totp(used, 1234567890) == totp(k, 1234567890) else "WRONG"


def matrix(expect):
    lines, failures = [], 0
    cases = {}
    for l in open(os.path.join(HERE, "vectors.txt")):
        n, var, t, code, b32 = l.split()
        cases.setdefault((int(n), var, b32), []).append((int(t), code))
    for (n, var, b32), vec in cases.items():
        k = base64.b32decode(b32 + "=" * (-len(b32) % 8))
        predicted = emulate_v001(k)
        actuals = []
        for t, code in vec:
            st, out = run(URI.format(n="K", s=b32).encode() + b"\n", t)
            actuals.append("CRASH" if st != "ok" else ("OK" if out.strip() == "K " + code else "WRONG"))
        actual = "OK" if set(actuals) == {"OK"} else ("CRASH" if "CRASH" in actuals else "WRONG")
        if expect == "fixed":
            match = actual == "OK"; want = "OK"
        else:
            # UNDEF: reads uninitialised memory; any result without a crash is fine
            match = actual != "CRASH" if predicted == "UNDEF" else actual == predicted; want = predicted
        failures += not match
        lines.append(f"{'ok ' if match else 'XX '} {n:>3} bytes {'with zero ' if var == 'z' else 'no zero   '} actual={actual:<6} expected={want}")
    return lines, failures


def report(cases, expect, lines, failures):
    """Shared by the groups below: case = (name, file content, right output, what v0.0.1 does: ok|fail)."""
    for name, content, right, prev in cases:
        st, out = run(content)
        actual = "ok" if st == "ok" and out == right else "fail"
        want = "ok" if expect == "fixed" else prev
        match = actual == want
        failures += not match
        detail = "" if actual == "ok" else (f"{st}: {out}" if st != "ok" else f"output {out!r}")
        lines.append(f"{'ok ' if match else 'XX '} {name:<26} actual={actual:<5} expected={want:<5} {detail[:70]}")
    return lines, failures


def malformed(expect):
    big = b"otpauth://totp/" + b"A" * 3000
    k11 = RFC[:11]
    pad = base64.b32encode(k11).decode()  # ends in ======
    cases = [
        ("missing file", None, "", "fail"),
        ("empty file", b"", "", "ok"),
        ("blank line", b"\n" + VALID + b"\n", "OK 287082\n", "fail"),
        ("short line", b"abc\n" + VALID + b"\n", "OK 287082\n", "fail"),
        ("no '?'", b"otpauth://totp/X\n" + VALID + b"\n", "OK 287082\n", "fail"),
        ("no secret=", b"otpauth://totp/X?algorithm=SHA1&digits=6\n" + VALID + b"\n", "OK 287082\n", "fail"),
        ("no algorithm=", b"otpauth://totp/X?digits=6&secret=" + B32.encode() + b"\n" + VALID + b"\n", "X 287082\nOK 287082\n", "fail"),  # missing = SHA1
        ("parameter without '='", b"otpauth://totp/X?algorithm=SHA1&digits&secret=" + B32.encode() + b"\n" + VALID + b"\n", "X 287082\nOK 287082\n", "fail"),  # pair ignored, digits = default
        ("secret with '='", URI.format(n="P", s=pad).encode() + b"\n", f"P {totp(k11, 59)}\n", "fail"),
        ("invalid base32", URI.format(n="X", s="!!!!!!!!").encode() + b"\n" + VALID + b"\n", "OK 287082\n", "fail"),
        ("3000 character line", big + b"\n" + VALID + b"\n", "OK 287082\n", "fail"),
        ("CRLF", VALID + b"\r\n", "OK 287082\n", "ok"),
    ]
    return report(cases, expect, [], 0)


def parameters(expect):
    def line(params, after=()):
        return ("otpauth://totp/P?" + "&".join(params + ["secret=" + B32] + list(after)) + "\n").encode()
    cases = [
        ("lowercase sha1", line(["algorithm=sha1", "digits=6", "period=30"]), "P 287082\n", "ok"),
        ("digits missing", line(["algorithm=SHA1", "period=30"]), "P 287082\n", "fail"),
        ("period missing", line(["algorithm=SHA1", "digits=6"]), "P 287082\n", "ok"),
        ("SHA256", line(["algorithm=SHA256", "digits=6", "period=30"]), "P ------\n", "fail"),
        ("8 digits", line(["algorithm=SHA1", "digits=8", "period=30"]), "P ------\n", "fail"),
        ("digits=262", line(["algorithm=SHA1", "digits=262", "period=30"]), "P ------\n", "fail"),
        ("period=60", line(["algorithm=SHA1", "digits=6", "period=60"]), "P ------\n", "fail"),
        # "nx" has the same 8-bit hash as "secret" (defect 9): it must be ignored
        ("name hashing like secret", line(["algorithm=SHA1", "digits=6", "period=30"], ["nx=!!!!!!!!"]), "P 287082\n", "fail"),
    ]
    return report(cases, expect, [], 0)


def clock(expect):
    cases = [  # time, right footer (compare with: date -u -r <time>)
        (59, "UTC 1970-01-01 00:00:59  1 s"),
        (60, "UTC 1970-01-01 00:01:00  30 s"),
        (1111111109, "UTC 2005-03-18 01:58:29  1 s"),
        (2000000000, "UTC 2033-05-18 03:33:20  10 s"),
        (4102444800, "UTC 2100-01-01 00:00:00  30 s"),  # past 2038
    ]
    lines, failures = [], 0
    for t, right in cases:
        p = subprocess.run([HOST, "--clock", str(t)], capture_output=True, env=ENV)
        out = p.stdout.decode().strip()
        actual = "ok" if p.returncode == 0 and out == right else "fail"
        want = "ok" if expect == "fixed" else "fail"  # v0.0.1 has no footer
        match = actual == want
        failures += not match
        lines.append(f"{'ok ' if match else 'XX '} t={t:<11} actual={actual:<5} expected={want:<5} {'' if actual == 'ok' else repr(out)[:60]}")
    return lines, failures


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect", choices=("v0.0.1", "fixed"), default="fixed")
    ap.add_argument("--host", help="prebuilt binary (to run against older code)")
    a = ap.parse_args()
    if a.host:
        HOST = os.path.abspath(a.host)
    else:
        subprocess.run(["make", "-C", HERE], check=True, capture_output=True)
    total = 0
    for title, f in (("Key size matrix (RFC 6238, 4 times each)", matrix), ("Malformed lines", malformed), ("URI parameters", parameters), ("UTC footer", clock)):
        ls, fl = f(a.expect)
        print(f"\n{title}  [expect: {a.expect}]")
        print("\n".join(ls))
        total += fl
    print(f"\n{'ALL AS EXPECTED' if not total else str(total) + ' MISMATCH(ES) with what was expected'} (mode {a.expect})")
    sys.exit(1 if total else 0)
