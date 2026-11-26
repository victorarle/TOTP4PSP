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

struct OTPKey * 
readOTPFile(char *filePath)
{
    struct OTPKey *head = NULL;
    struct OTPKey **cur = &head;

    FILE *filePointer;
    uint32_t bufferLength = 2048;
    char buffer[bufferLength]; /* not ISO 90 compatible */

    filePointer = fopen(filePath, "r");

    while (fgets(buffer, bufferLength, filePointer))
    {
        char *optauth;
        char *rest;
        optauth = strtok_r(buffer, "?", &rest);

        char *alg = NULL;
        uint8_t dig = 0;
        char *iss = NULL;
        uint8_t per = 0;
        char *sec = NULL;

        // Parse
        while (rest != NULL)
        {
            char *segment = strtok_r(rest, "&", &rest);
            char *paramName;
            char *value;
            paramName = strtok_r(segment, "=", &value);

            switch (lookup(paramName))
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

        if ((*cur) == NULL) {
            (*cur) = (struct OTPKey *) malloc(sizeof(struct OTPKey));
        }
        
        int offset = 15;
        (*cur)->name = malloc((strlen(optauth) - offset) + 1);
        memcpy((*cur)->name, optauth+offset, (strlen(optauth) - offset) + 1);
        
        (*cur)->algorithm = malloc(strlen(alg) + 1);
        strcpy((*cur)->algorithm, alg);
        (*cur)->digits = dig;
        (*cur)->period = per;
        if (iss != NULL) {
            (*cur)->issuer = malloc(strlen(iss) + 1);
            strcpy((*cur)->issuer, iss);
        }

        // Secret is Base32 string, so must first decode back to normal string
        // Base32 uses 5 bits per character, but also must be multiple of 40 bits length
        uint32_t decodedSize = ((strlen(sec) + 1) * 8 + 4) / 5;
        (*cur)->secret = malloc(decodedSize);
        (*cur)->secret_len = base32_decode(sec, (*cur)->secret, decodedSize);
        (*cur)->next = NULL;

        cur = &(*cur)->next;
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
