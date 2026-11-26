// Platform-independent part of TOTP4PSP: otpauth:// parsing and code calculation.
// Lives apart from main.c so it also builds on the host for testing (see test/).
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "totp.h"
#include "hmac-sha1/src/hmac/hmac.h"
#include "base32/base32.h"

int num_otp_keys = 0;
int num_skipped_lines = 0;

// Defaults when the URI leaves a parameter out
#define DEFAULT_DIGITS 6
#define DEFAULT_PERIOD 30

// Number from a URI parameter; 0 (never valid here) when it is not 1..255
static uint8_t
parseByte(const char *value)
{
    long v = strtol(value, NULL, 10);
    return (v < 1 || v > 255) ? 0 : (uint8_t)v;
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
    uint8_t dig = DEFAULT_DIGITS;
    char *iss = NULL;
    uint8_t per = DEFAULT_PERIOD;
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
            if (strcmp(segment, "algorithm") == 0)
                alg = value;
            else if (strcmp(segment, "digits") == 0)
                dig = parseByte(value);
            else if (strcmp(segment, "issuer") == 0)
                iss = value;
            else if (strcmp(segment, "period") == 0)
                per = parseByte(value);
            else if (strcmp(segment, "secret") == 0)
                sec = value;
        }
        segment = next;
    }

    if (sec == NULL)
        return NULL;

    // Base32 padding is not part of the key: cut at the first '='
    char *pad = strchr(sec, '=');
    if (pad != NULL)
        *pad = '\0';

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

// Last 6 decimal digits; 6 is the only length supported (see totp_supported)
uint32_t
mod_hotp(uint32_t bin_code)
{
    return bin_code % 1000000;
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

// Only SHA1, 6 digits, 30 s are implemented; anything else must not show a
// code that would look valid but be wrong.
int
totp_supported(const struct OTPKey *key)
{
    return (key->algorithm == NULL || strcasecmp(key->algorithm, "SHA1") == 0)
        && key->digits == DEFAULT_DIGITS
        && key->period == DEFAULT_PERIOD;
}

void
totp_code(struct OTPKey *key, uint32_t counter, char out[7])
{
    if (totp_supported(key))
        snprintf(out, 7, "%06lu", (unsigned long)mod_hotp(calcToken(key, counter)));
    else
        strcpy(out, "------");
}
