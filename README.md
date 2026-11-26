# Time-based One-Time Password for PlayStation Portable (TOTP4PSP) 
<p align="center">
    <img src="totp4psp.jpg" width="65%" />
</p>

This homebrew program implements TOTP (RFC 6238) and lets you use your PSP as a hardware token generator to many 2FA authentication systems. Other 2FA methods are weaker (SMS-based 2FA is susceptible to SIM swapping attacks for instance) and so the safest option is still to have an offline generator.

The user must provide their own OTPAUTH_KEYS file with each line as a seperate TOTP authenticator URI, which can be exported from Google Authenticator for example with a tool such as [otpauth](https://github.com/dim13/otpauth). The exact format is explained [here](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) and is discussed further under [Installation](#installation); an example OTPAUTH_KEYS file is also provided for reference.

Here is a YouTube link to my PSPHDC24' talk: https://www.youtube.com/live/0rxTPSFSC-k?t=2512s

> **This is a fork** of [arcyleung/TOTP4PSP](https://github.com/arcyleung/TOTP4PSP) (v0.0.1) with bug fixes, released as **v0.1.0**. The program, the talk and the original text of this README are Arthur Leung's; the section below and the notes marked *(v0.1.0)* describe what the fork changes. See [Credits and licenses](#credits-and-licenses) for everyone whose work is in here. The original repository also has an open [pull request](https://github.com/arcyleung/TOTP4PSP/pull/1) from its author with an overlapping fix for the key-length bug; this fork was developed and tested separately.

## What v0.1.0 fixes

| v0.0.1 | v0.1.0 |
|---|---|
| Wrong codes for secrets of 64 bytes or more, and for secrets of more than 20 bytes that contain a zero byte. The HMAC key length was taken from `strlen()+1` instead of the decoded length. Secrets under 20 bytes read uninitialised memory | The decoded length is used. Checked for 10 to 65 bytes, with and without a zero byte |
| The PSP powers off at "Reading OTPauth keys..." when the key file is missing or has a blank, short or malformed line | Unusable lines are skipped and counted on screen; a missing file shows where it is expected |
| A missing `digits=` shows `000000` for every code; `digits` above 6 overflows a buffer; `algorithm` and `period` are read but ignored, so a SHA256 or 60 s account shows a valid-looking wrong code | Missing parameters default to SHA1, 6 digits, 30 s. Anything else shows `------` |
| A secret with `=` padding, or with invalid Base32, is used anyway and reads past its buffer | Padding is cut off; invalid Base32 skips the line |
| No way to tell which time the codes are computed from | A footer shows the UTC date and time in use and the seconds left for the current code |
| Parameter names matched by an 8-bit hash, so unrelated names could be taken for `secret` or `digits` | Names are compared exactly |
| Does not build from a fresh clone (broken submodule URL, missing include path) nor with GCC 14 or newer | Builds with `git clone --recurse-submodules` and `make` on the current PSPDEV toolchain |

Still not implemented: SHA256/SHA512, 8 digits, periods other than 30 s. Such accounts show `------` instead of a code.

**Status:** tested on a PSP with custom firmware on 2026-11-26: five accounts, among them one with a 64-byte secret, match a phone authenticator, and a real login used a code read from the PSP. The same 64-byte account shows a wrong code on the original v0.0.1; the footer's UTC time matches the computer's. The `EBOOT.PBP` in this repository is that tested v0.1.0 build (SHA-256 `1da1c460277ebfcaaf1b2a97a0e798260ab157be55d0421f50101a4e2048121d`); the original v0.0.1 binary is in the history at tag `v0.0.1`.

## Prerequisites

- A PSP 1000/2000/3000 with any CFW
- A memory stick and sufficient free space for EBOOT.PBP and your keyfile
- For emulators like PPSSPP: The original PSP .pgf font files should be present under "C:\Program Files\PPSSPP\assets\flash0\font\", which you must copy from a physical PSP's flash0:/font/ directory, or obtain them elsewhere ;). (This is because intraFont 0.31 cannot load the "open source" .pgf alternative fonts shipped with PPSSPP)

## Installation
1. Copy the EBOOT.PBP into a new game folder on the memory stick ie. `ms0:/PSP/GAME/TOTP4PSP/EBOOT.PBP`
2. Copy the OTPAUTH_KEYS file into `ms0:/PSP/COMMON/OTPAUTH_KEYS`

An example OTPAUTH_KEYS is provided for reference, please note the following format: 
- one line per OTP provider
- `secret=` field is the base32 encoded representation of the secret, and not the plaintext secret itself!
    - Ex. Using the RFC doc's [test vector example](https://www.rfc-editor.org/rfc/rfc6238#appendix-B):   
    Plaintext Secret: `12345678901234567890` -> Base32 Secret: `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`
- `issuer=` field is optional, everything else is required
    - *(v0.1.0)* only `secret=` is required; `algorithm`, `digits` and `period` default to SHA1, 6 and 30
- *(v0.1.0)* lines that are not a usable `otpauth://totp/` entry are skipped, and the screen says how many

OTPAUTH_KEYS
```
otpauth://totp/<name1>?algorithm=SHA1&digits=6&period=30&secret=<base32_secret1>
otpauth://totp/<name2>?algorithm=SHA1&digits=6&issuer=<issuer2>&period=30&secret=<base32_secret2>
...
``` 
3. Ensure the system time of the PSP is correctly set in "Settings" > "Date & Time Settings", either set manually or via internet, and also paying attention to whether Daylight Saving Time is enabled. 
4. Launch the app from the XMB as you would with any homebrew. The screen displays up to 12 OTP codes at once but you can scroll with Up/Down on the Dpad.

*(v0.1.0)* The screen shows 11 codes at once; the last row is a footer such as `UTC 2026-11-26 04:08:54  6 s  v0.1.0` (the UTC time in use, the seconds left for the current code, the version). Compare it with a clock you trust (`date -u` on a computer). If it is off by whole hours, the time zone or Daylight Saving setting of the PSP is wrong, and every code will be wrong with it.

The program only reads `OTPAUTH_KEYS`, so v0.0.1 and v0.1.0 can be installed side by side in different game folders (for example `ms0:/PSP/GAME/TOTP4PSP_V2/`). The XMB title of the fixed build is "TOTP 4 PSP v0.1.0".

## OTP Parameters

The following fields and parameters are currently supported:
```
algorithm=[SHA1]        <- TODO: Implement SHA256|SHA512 
digits=[6]              <- TODO: Implement 8 digits
period=[30s]            <- TODO: Implement 60s
issuer=<any string>     <- TODO: Display it in some useful way
secret=<base32 secret>
```

*(v0.1.0)* An account with any other `algorithm`, `digits` or `period` is listed with `------` in place of the code. Secrets of any length work; `=` padding is accepted.

## Building from Source

Prerequisites: a working installation of the [PSPDEV toolchain](https://pspdev.github.io/) (`psp-gcc`, `psp-config`)
1. Clone this repository and its submodule: `git clone --recurse-submodules <repository URL> TOTP4PSP/`
2. `cd ./TOTP4PSP`
3. Verify that `psp-config --pspdev-path` answers in your current shell
4. Run `make` and use the generated `EBOOT.PBP` for the steps in [Installation](#installation)

The project uses the PSPSDK `build.mak`, not CMake. `make` overwrites the `EBOOT.PBP` and `totp_4_psp.elf` that are committed in the repository. The committed `totp_4_psp.elf` was built with `-ffile-prefix-map` so it carries no local paths; it strips to the same `EBOOT.PBP` byte for byte.

v0.1.0 was built with:

| | |
|---|---|
| PSPDEV release | [`v20261101`](https://github.com/pspdev/pspdev/releases/tag/v20261101), `psp-gcc` 15.2.0 |
| Package | `pspdev-macos-latest-arm64.tar.gz`, 154483118 bytes |
| SHA-256 of the package | `066a20cf743bcf9ff948cc8c2f1204ad705ad018e9f80ccd444e488f44bc22c8` |
| Host | macOS on Apple Silicon |

`libpng` and `zlib` come with that package. The build is warning-free; it needed one added line, `#include <string.h>` in `intrafont031g/libraries/graphics.c`, because GCC 14 and newer reject the implicit `memset` and `strlen` it relied on.

## Tests

`totp.c` holds everything that does not depend on the PSP (parsing a key file line, computing a code, the footer text) and also builds with the host compiler:

```
python3 test/run.py
```

This builds `test/host` with AddressSanitizer and UndefinedBehaviorSanitizer and checks:
- the RFC 6238 appendix B vectors (SHA1), and keys of 10, 20, 32, 40, 63, 64 and 65 bytes, each with and without a zero byte, at four instants (`test/vectors.txt`, regenerated by `test/gen_vectors.py`)
- malformed input: missing or empty file, blank and short lines, missing `?`, `secret=` or `algorithm=`, a parameter without `=`, padded and invalid Base32, a 3000 character line, CRLF
- URI parameters: defaults, and `------` for SHA256, 8 digits or 60 s
- the footer text

`python3 test/run.py --host <binary> --expect v0.0.1` runs the same cases against a binary built from the unfixed code and expects exactly the v0.0.1 defects, which shows that the test can see them.

All test secrets derive from the public RFC 6238 seed. Never commit a real secret, in a test or in `OTPAUTH_KEYS`.

The host test uses the host C library; the PSP uses newlib. It covers the logic, not the hardware.

## Credits and licenses

TOTP4PSP exists because of the people below. Their code is used as published, with its licenses and headers untouched.

| Who | What | License |
|---|---|---|
| **Arthur Leung** ([arcyleung](https://github.com/arcyleung)) | Original author of TOTP4PSP: the program, the README text and the PSPHDC24 talk. All upstream commits in this repository's history are his and keep his authorship | ISC, see `LICENSE` |
| Dimitri Sokolyuk | Holds the copyright line in `LICENSE` (2020), kept exactly as published upstream. The same ISC text and copyright line are published by his project [otpauth](https://github.com/dim13/otpauth), the export tool the original README recommends; the original repository does not say whether any of its code is used here | ISC |
| BenHur | [intraFont](https://github.com/PSP-Archive/intraFont) 0.31, in `intrafont031g/`. It builds on parts of pgeFont by InsertWittyName and G-spec code by Geecko (2010), as its README and headers say | CC BY-SA 3.0, `intrafont031g/LICENSE`. The Share-Alike terms cover those files and any change to them; none was made to the intraFont files |
| [Akagi201](https://github.com/Akagi201) | [hmac-sha1](https://github.com/Akagi201/hmac-sha1), the git submodule `hmac-sha1/` (copyright line: Bob Liu, 2014) | MIT, `hmac-sha1/LICENSE` |
| Creytiv.com | `hmac_sha1.c`, the HMAC implementation inside that submodule (2010) | per its header |
| Steve Reid and James H. Brown | `sha1.c`, SHA-1, inside that submodule | public domain, per its header |
| Markus Gutschke / Google Inc. | [Base32 implementation](https://github.com/google/google-authenticator-libpam/tree/master/src), `base32/` (2010) | Apache 2.0, per its headers |
| The [PSPDEV](https://pspdev.github.io/) community | The toolchain and PSPSDK (`build.mak`, `libpng`, `zlib`) the program is built with | their respective licenses |

Files without an author header upstream: `common/callback.*`, `intrafont031g/libraries/graphics.*` and `framebuffer.*`. Their origin is not stated in the original repository; if you recognise it, please open an issue so the credit can be added. The only change this fork made to any of them is the `#include <string.h>` line in `graphics.c`.

**Changes in this fork (v0.1.0):** the fixes, the split into `totp.c`/`totp.h`, the host tests, the footer and this documentation, by Victor Arlé, released under the same ISC license as the original program. The `LICENSE` file is unchanged; keep its copyright notice with every copy.

The specifications behind the program: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) (TOTP) and the [Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

## Contact
The original author: please reach out at arcyleung@gmail.com for feature requests or consider supporting his work over at [ko-fi](https://ko-fi.com/arcyleung).

For anything specific to v0.1.0, open an issue on this fork.
