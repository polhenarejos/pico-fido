/*
 * This file is part of the Pico HSM SDK distribution (https://github.com/polhenarejos/pico-hsm-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CTAP_H_
#define _CTAP_H_

#ifdef _MSC_VER  // Windows
typedef unsigned char     uint8_t;
typedef unsigned short    uint16_t;
typedef unsigned int      uint32_t;
typedef unsigned long int uint64_t;
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// General constants

#define CTAP_EC_KEY_SIZE         32      // EC key size in bytes
#define CTAP_EC_POINT_SIZE       ((CTAP_EC_KEY_SIZE * 2) + 1) // Size of EC point
#define CTAP_MAX_KH_SIZE         128     // Max size of key handle
#define CTAP_MAX_ATT_CERT_SIZE   2048    // Max size of attestation certificate
#define CTAP_MAX_EC_SIG_SIZE     72      // Max size of DER coded EC signature
#define CTAP_CTR_SIZE            4       // Size of counter field
#define CTAP_APPID_SIZE          32      // Size of application id
#define CTAP_CHAL_SIZE           32      // Size of challenge

#define ENC_SIZE(x)             ((x + 7) & 0xfff8)

// EC (uncompressed) point

#define CTAP_POINT_UNCOMPRESSED  0x04    // Uncompressed point format

typedef struct {
    uint8_t pointFormat;                // Point type
    uint8_t x[CTAP_EC_KEY_SIZE];         // X-value
    uint8_t y[CTAP_EC_KEY_SIZE];         // Y-value
} CTAP_EC_POINT;

// CTAP MSG commands

#define CTAP_REGISTER            0x01    // Registration command
#define CTAP_AUTHENTICATE        0x02    // Authenticate/sign command
#define CTAP_VERSION             0x03    // Read version string command

#define CTAP_VENDOR_FIRST        0x40    // First vendor defined command
#define CTAP_VENDOR_LAST         0xbf    // Last vendor defined command

// CTAP_CMD_REGISTER command defines

#define CTAP_REGISTER_ID         0x05    // Version 2 registration identifier
#define CTAP_REGISTER_HASH_ID    0x00    // Version 2 hash identintifier

typedef struct {
    uint8_t chal[CTAP_CHAL_SIZE];        // Challenge
    uint8_t appId[CTAP_APPID_SIZE];      // Application id
} CTAP_REGISTER_REQ;

typedef struct {
    uint8_t registerId;                 // Registration identifier (CTAP_REGISTER_ID_V2)
    CTAP_EC_POINT pubKey;                // Generated public key
    uint8_t keyHandleLen;               // Length of key handle
    uint8_t keyHandleCertSig[
        CTAP_MAX_KH_SIZE +               // Key handle
        CTAP_MAX_ATT_CERT_SIZE +         // Attestation certificate
        CTAP_MAX_EC_SIG_SIZE];           // Registration signature
} CTAP_REGISTER_RESP;

// CTAP_CMD_AUTHENTICATE command defines

// Authentication control byte

#define CTAP_AUTH_ENFORCE        0x03    // Enforce user presence and sign
#define CTAP_AUTH_CHECK_ONLY     0x07    // Check only
#define CTAP_AUTH_FLAG_TUP       0x01    // Test of user presence set

typedef struct {
    uint8_t chal[CTAP_CHAL_SIZE];        // Challenge
    uint8_t appId[CTAP_APPID_SIZE];      // Application id
    uint8_t keyHandleLen;               // Length of key handle
    uint8_t keyHandle[CTAP_MAX_KH_SIZE]; // Key handle
} CTAP_AUTHENTICATE_REQ;

typedef struct {
    uint8_t flags;                      // CTAP_AUTH_FLAG_ values
    uint8_t ctr[CTAP_CTR_SIZE];          // Counter field (big-endian)
    uint8_t sig[CTAP_MAX_EC_SIG_SIZE];   // Signature
} CTAP_AUTHENTICATE_RESP;

// Command status responses

#define CTAP_SW_NO_ERROR                 0x9000 // SW_NO_ERROR
#define CTAP_SW_WRONG_DATA               0x6A80 // SW_WRONG_DATA
#define CTAP_SW_CONDITIONS_NOT_SATISFIED 0x6985 // SW_CONDITIONS_NOT_SATISFIED
#define CTAP_SW_COMMAND_NOT_ALLOWED      0x6986 // SW_COMMAND_NOT_ALLOWED
#define CTAP_SW_INS_NOT_SUPPORTED        0x6D00 // SW_INS_NOT_SUPPORTED

#ifdef __cplusplus
}
#endif

#endif  // _CTAP_H_
