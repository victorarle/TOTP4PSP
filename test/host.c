// Host test driver: host <OTPAUTH_KEYS file> <unix time>
// Prints "<name> <code>" for each account, through the same totp_code() as main.c.
#include <stdio.h>
#include <stdlib.h>
#include "../totp.h"

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: %s file time\n", argv[0]); return 2; }
    uint32_t counter = strtoul(argv[2], NULL, 10) / 30;
    for (struct OTPKey *k = readOTPFile(argv[1]); k != NULL; k = k->next) {
        char code[7];
        totp_code(k, counter, code);
        printf("%s %s\n", k->name, code);
    }
    return 0;
}
