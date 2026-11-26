// Host test driver: host <OTPAUTH_KEYS file> <unix time>
// Prints "<name> <code>" for each account, same math as main.c (6 digits shown
// with the account's own digits value, 30 s step).
#include <stdio.h>
#include <stdlib.h>
#include "../totp.h"

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: %s file time\n", argv[0]); return 2; }
    uint32_t counter = strtoul(argv[2], NULL, 10) / 30;
    for (struct OTPKey *k = readOTPFile(argv[1]); k != NULL; k = k->next) {
        uint32_t code = calcToken(k, counter);
        printf("%s %06lu\n", k->name, (unsigned long)mod_hotp(code, k->digits));
    }
    return 0;
}
