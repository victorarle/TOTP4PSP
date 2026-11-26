#ifndef TOTP_H
#define TOTP_H

#include <stdint.h>

// Supported parameter fields of the otpauth://totp/ string
#define ALG 70
#define DIG 67
#define ISS 26
#define PER 66
#define SEC 133

// Simple linked list of TOTP key field info, appended as they are parsed from the file
struct OTPKey
{
    char *name;
    char *issuer;
    char *algorithm;
    uint8_t digits;
    uint8_t period;
    char *secret;

    struct OTPKey *next;
};

extern int num_otp_keys;

struct OTPKey *readOTPFile(char *filePath);
uint32_t mod_hotp(uint32_t bin_code, int digits);
int calcToken(struct OTPKey *key, uint32_t counter);

#endif
