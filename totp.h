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
    char *secret;      // decoded key bytes (may contain 0x00)
    int secret_len;    // number of decoded bytes

    struct OTPKey *next;
};

extern int num_otp_keys;
extern int num_skipped_lines;  // lines of the key file that were not usable

struct OTPKey *readOTPFile(char *filePath);
uint32_t mod_hotp(uint32_t bin_code);
int calcToken(struct OTPKey *key, uint32_t counter);
int totp_supported(const struct OTPKey *key);
// 6-digit code for the time step `counter`, or "------" if the key is not SHA1/6/30
void totp_code(struct OTPKey *key, uint32_t counter, char out[7]);

#endif
