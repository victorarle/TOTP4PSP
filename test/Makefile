# Host build of totp.c for tests: make -C test && python3 test/run.py
HMAC = ../hmac-sha1/src
host: host.c ../totp.c ../base32/base32.c $(HMAC)/hmac/hmac_sha1.c $(HMAC)/sha/sha1.c
	cc -g -O0 -Wall -fsanitize=address,undefined -fno-sanitize-recover=undefined \
	   -I.. -I$(HMAC) -o $@ $^ -lm
