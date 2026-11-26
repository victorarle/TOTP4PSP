// Platform-independent part of TOTP4PSP: otpauth:// parsing and code calculation.
// Lives apart from main.c so it also builds on the host for testing (see test/).
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include "totp.h"
#include "hmac-sha1/src/hmac/hmac.h"
#include "base32/base32.h"

int num_otp_keys = 0;
int num_skipped_lines = 0;

// Modified djb2 to convert string to some id
uint8_t
lookup(char *str)
{
    uint8_t hash = 31;
    uint8_t c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

#define PREFIX "otpauth://totp/"
#define PREFIX_LEN 15

// Parse one line of the key file into a new OTPKey. Returns NULL when the line
// is not a usable otpauth://totp/ entry (the caller skips it). Edits `line`.
static struct OTPKey *
parseOTPLine(char *line)
{
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';

    if (strncmp(line, PREFIX, PREFIX_LEN) != 0)
        return NULL;
    char *query = strchr(line, '?');
    if (query == NULL)
        return NULL;
    *query++ = '\0';

    char *alg = NULL;
    uint8_t dig = 0;
    char *iss = NULL;
    uint8_t per = 0;
    char *sec = NULL;

    // Parse "name=value" pairs separated by '&'; a pair without '=' is ignored
    char *segment = query;
    while (segment != NULL)
    {
        char *next = strchr(segment, '&');
        if (next != NULL)
            *next++ = '\0';
        char *value = strchr(segment, '=');
        if (value != NULL)
        {
            *value++ = '\0';
            switch (lookup(segment))
            {
            case ALG:
                alg = value;
                break;
            case DIG:
                dig = strtol(value, NULL, 10);
                break;
            case ISS:
                iss = value;
                break;
            case PER:
                per = strtol(value, NULL, 10);
                break;
            case SEC:
                sec = value;
                break;
            }
        }
        segment = next;
    }

    if (sec == NULL)
        return NULL;

    // Secret is Base32 string, so must first decode back to normal string
    // Base32 uses 5 bits per character, but also must be multiple of 40 bits length
    uint32_t decodedSize = ((strlen(sec) + 1) * 8 + 4) / 5;
    char *secret = malloc(decodedSize);
    int secretLen = base32_decode(sec, secret, decodedSize);
    if (secretLen <= 0)
    {
        free(secret);
        return NULL;
    }

    struct OTPKey *key = calloc(1, sizeof(struct OTPKey));
    key->name = strdup(line + PREFIX_LEN);
    if (alg != NULL)
        key->algorithm = strdup(alg);
    key->digits = dig;
    key->period = per;
    if (iss != NULL)
        key->issuer = strdup(iss);
    key->secret = secret;
    key->secret_len = secretLen;
    return key;
}

struct OTPKey *
readOTPFile(char *filePath)
{
    struct OTPKey *head = NULL;
    struct OTPKey **cur = &head;

    char buffer[2048];
    FILE *filePointer = fopen(filePath, "r");
    if (filePointer == NULL)
        return NULL;

    while (fgets(buffer, sizeof(buffer), filePointer))
    {
        size_t len = strlen(buffer);
        // Line longer than the buffer: drop all of it, not just the first chunk
        if (len == sizeof(buffer) - 1 && buffer[len - 1] != '\n')
        {
            int c;
            while ((c = fgetc(filePointer)) != EOF && c != '\n')
                ;
            num_skipped_lines += 1;
            continue;
        }

        struct OTPKey *key = parseOTPLine(buffer);
        if (key == NULL)
        {
            // blank lines are not worth reporting
            if (buffer[strspn(buffer, " \t\r\n")] != '\0')
                num_skipped_lines += 1;
            continue;
        }
        *cur = key;
        cur = &key->next;
        num_otp_keys += 1;
    }

    fclose(filePointer);
    return head;
}

uint32_t
mod_hotp(uint32_t bin_code, int digits)
{
    int power = pow(10, digits);
    uint32_t otp = bin_code % power;

    return otp;
}

int
calcToken(struct OTPKey *key, uint32_t counter)
{
    uint8_t text[8];
    for (int i = 7; i >= 0; i--)
    {
        text[i] = (counter & 0xff);
        counter >>= 8;
    }

    // HMAC key is the decoded bytes, exactly secret_len of them (a 0x00 byte
    // inside the key is data, not a terminator).
    uint8_t output[20];
    size_t outLen = sizeof(output);

    hmac_sha1((const uint8_t *)key->secret, key->secret_len, text, 8, output, &outLen);

    int offset = output[outLen-1] & 0xf;

    int bin_code = (output[offset] & 0x7f) << 24
        | (output[offset+1] & 0xff) << 16
        | (output[offset+2] & 0xff) <<  8
        | (output[offset+3] & 0xff);

    return bin_code;
}
