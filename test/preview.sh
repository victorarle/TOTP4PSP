#!/bin/sh
# Look at the screen without a PSP: build with -DUI_PREVIEW and run it in PPSSPP.
#
#   source env.sh && sh test/preview.sh
#
# Works in a temporary copy of the tree, so the tracked EBOOT.PBP is not rebuilt, and gives
# PPSSPP a home directory of its own, so your PPSSPP settings and memory stick are not touched.
# The preview build plays a fixed sequence of button presses and saves the screen once a
# second, and a few frames in a row while the selection slides; the pictures end up in the
# directory printed at the end.
#
# Two workarounds for PPSSPP 1.19.2, both only in this build: the fonts are PPSSPP's own,
# copied to ms0:/font (flash0:/font does not open there), and they are read with the
# intraFont of the PSPDEV toolchain (the bundled 0.31g cannot read them). They are not the
# PSP's fonts: sizes and spacing on a real PSP differ.
set -eu

PPSSPP=${PPSSPP:-/Applications/PPSSPPSDL.app}
SECONDS_TO_RUN=${SECONDS_TO_RUN:-20}
src=$(cd "$(dirname "$0")/.." && pwd)
work=${TMPDIR:-/tmp}/totp4psp-preview
card=$work/home/.config/ppsspp

rm -rf "$work"
mkdir -p "$work/build" "$card/PSP/GAME/TOTP4PSP" "$card/PSP/COMMON" "$card/PSP/SYSTEM" "$card/font"

# Build
(cd "$src" && git ls-files -z | tar -cf - --null -T -) | tar -xf - -C "$work/build"
cp -R "$src/hmac-sha1/src" "$work/build/hmac-sha1/"
rm -f "$work/build/EBOOT.PBP" "$work/build"/*.elf   # the tracked release build: make must not take it as up to date
make -C "$work/build" CC="psp-gcc -DUI_PREVIEW" OBJS="main.o totp.o \
    ./hmac-sha1/src/hmac/hmac_sha1.o ./hmac-sha1/src/sha/sha1.o ./base32/base32.o ./common/callback.o \
    ./intrafont031g/libraries/graphics.o ./intrafont031g/libraries/framebuffer.o \
    $(psp-config --psp-prefix)/lib/libintrafont.a" >"$work/build.log" 2>&1 || { tail -20 "$work/build.log"; exit 1; }
cp "$work/build/EBOOT.PBP" "$card/PSP/GAME/TOTP4PSP/"
cp "$PPSSPP"/Contents/Resources/assets/flash0/font/ltn[048].pgf "$card/font/"

# Key file: the public RFC 6238 seed of the sample OTPAUTH_KEYS under made-up names,
# plus one unsupported key and two unusable lines
sample=$(head -n 1 "$src/OTPAUTH_KEYS")
{
    for name in "Correio Lumen" "Nuvem Boreal" "Forja Git" "Banco Aurora"; do
        echo "$sample" | sed "s|totp/[^?]*|totp/$name|"
    done
    echo "$sample" | sed "s|totp/[^?]*|totp/Cofre Antigo (SHA256)|; s|SHA1|SHA256|"
    echo "this line is not a key"
    for name in "Loja Pixel" "Arena Orbe: a.rather.long.account.name@example.invalid (primary)" "Forum Mare" "Wiki Estudio"; do
        echo "$sample" | sed "s|totp/[^?]*|totp/$name|"
    done
    echo "otpauth://hotp/not-totp"
} >"$card/PSP/COMMON/OTPAUTH_KEYS"

# The program saves its own framebuffer, which only holds the picture with the software renderer
printf '[General]\nFirstRun = False\nCheckForNewVersion = False\n[Graphics]\nSoftwareRenderer = True\n' \
    >"$card/PSP/SYSTEM/ppsspp.ini"

# PPSSPP has no "run for N seconds": stop it with an alarm
HOME=$work/home perl -e 'alarm shift; exec @ARGV' "$SECONDS_TO_RUN" \
    "$PPSSPP/Contents/MacOS/PPSSPPSDL" --windowed "$card/PSP/GAME/TOTP4PSP/EBOOT.PBP" >"$work/ppsspp.log" 2>&1 || true

ls "$card"/totp4psp-preview-*.png "$card"/totp4psp-slide-*.png
