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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

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

// CTAP CBOR commands

#define CTAP_MAKE_CREDENTIAL     0x01
#define CTAP_GET_ASSERTION       0x02
#define CTAP_GET_INFO            0x04
#define CTAP_CLIENT_PIN          0x06
#define CTAP_RESET               0x07
#define CTAP_GET_NEXT_ASSERTION  0x08
#define CTAP_CREDENTIAL_MGMT     0x0A
#define CTAP_SELECTION           0x0B
#define CTAP_LARGE_BLOBS         0x0C
#define CTAP_CONFIG              0x0D

#define CTAP_CONFIG_AUT_ENABLE      0x03e43f56b34285e2
#define CTAP_CONFIG_AUT_DISABLE     0x1831a40f04a25ed9
#define CTAP_CONFIG_PHY_VIDPID      0x6fcb19b0cbe3acfa
#define CTAP_CONFIG_PHY_LED_GPIO    0x7b392a394de9f948
#define CTAP_CONFIG_PHY_LED_BTNESS  0x76a85945985d02fd
#define CTAP_CONFIG_PHY_OPTS        0x969f3b09eceb805f

#define CTAP_VENDOR_CBOR            (CTAPHID_VENDOR_FIRST + 1)

#define CTAP_VENDOR_BACKUP              0x01
#define CTAP_VENDOR_MSE                 0x02
#define CTAP_VENDOR_UNLOCK              0x03
#define CTAP_VENDOR_EA                  0x04
#define CTAP_VENDOR_PHY_OPTS            0x05
#define CTAP_VENDOR_MEMORY              0x06

#define CTAP_PERMISSION_MC              0x01  // MakeCredential
#define CTAP_PERMISSION_GA              0x02  // GetAssertion
#define CTAP_PERMISSION_CM              0x04  // CredentialManagement
#define CTAP_PERMISSION_BE              0x08  // BioEnrollment
#define CTAP_PERMISSION_LBW             0x10  // LargeBlobWrite
#define CTAP_PERMISSION_ACFG            0x20  // AuthenticatorConfiguration
#define CTAP_PERMISSION_PCMR            0x40  // PerCredentialManagementReadOnly

typedef struct mse {
    uint8_t Qpt[65];
    uint8_t key_enc[12 + 32];
    bool init;
} mse_t;
extern mse_t mse;

extern int mse_decrypt_ct(uint8_t *, size_t);

// Command status responses

#define CTAP_SW_NO_ERROR                 0x9000 // SW_NO_ERROR
#define CTAP_SW_WRONG_DATA               0x6A80 // SW_WRONG_DATA
#define CTAP_SW_CONDITIONS_NOT_SATISFIED 0x6985 // SW_CONDITIONS_NOT_SATISFIED
#define CTAP_SW_COMMAND_NOT_ALLOWED      0x6986 // SW_COMMAND_NOT_ALLOWED
#define CTAP_SW_INS_NOT_SUPPORTED        0x6D00 // SW_INS_NOT_SUPPORTED

#define CTAP2_OK                            0x00
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE      0x11
#define CTAP2_ERR_INVALID_CBOR              0x12
#define CTAP2_ERR_MISSING_PARAMETER         0x14
#define CTAP2_ERR_LIMIT_EXCEEDED            0x15
#define CTAP2_ERR_FP_DATABASE_FULL          0x17
#define CTAP2_ERR_LARGE_BLOB_STORAGE_FULL   0x18
#define CTAP2_ERR_CREDENTIAL_EXCLUDED       0x19
#define CTAP2_ERR_PROCESSING                0x21
#define CTAP2_ERR_INVALID_CREDENTIAL        0x22
#define CTAP2_ERR_USER_ACTION_PENDING       0x23
#define CTAP2_ERR_OPERATION_PENDING         0x24
#define CTAP2_ERR_NO_OPERATIONS             0x25
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM     0x26
#define CTAP2_ERR_OPERATION_DENIED          0x27
#define CTAP2_ERR_KEY_STORE_FULL            0x28
#define CTAP2_ERR_UNSUPPORTED_OPTION        0x2B
#define CTAP2_ERR_INVALID_OPTION            0x2C
#define CTAP2_ERR_KEEPALIVE_CANCEL          0x2D
#define CTAP2_ERR_NO_CREDENTIALS            0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT       0x2F
#define CTAP2_ERR_NOT_ALLOWED               0x30
#define CTAP2_ERR_PIN_INVALID               0x31
#define CTAP2_ERR_PIN_BLOCKED               0x32
#define CTAP2_ERR_PIN_AUTH_INVALID          0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED          0x34
#define CTAP2_ERR_PIN_NOT_SET               0x35
#define CTAP2_ERR_PUAT_REQUIRED             0x36
#define CTAP2_ERR_PIN_POLICY_VIOLATION      0x37
#define CTAP2_ERR_REQUEST_TOO_LARGE         0x39
#define CTAP2_ERR_ACTION_TIMEOUT            0x3A
#define CTAP2_ERR_UP_REQUIRED               0x3B
#define CTAP2_ERR_UV_BLOCKED                0x3C
#define CTAP2_ERR_INTEGRITY_FAILURE         0x3D
#define CTAP2_ERR_INVALID_SUBCOMMAND        0x3E
#define CTAP2_ERR_UV_INVALID                0x3F
#define CTAP2_ERR_UNAUTHORIZED_PERMISSION   0x40
#define CTAP2_ERR_SPEC_LAST                 0xDF
#define CTAP2_ERR_EXTENSION_FIRST           0xE0
#define CTAP2_ERR_EXTENSION_LAST            0xEF
#define CTAP2_ERR_VENDOR_FIRST              0xF0
#define CTAP2_ERR_VENDOR_LAST               0xFF

#ifdef __cplusplus
}
#endif

#endif  // _CTAP_H_
