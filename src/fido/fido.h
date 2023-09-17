/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
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

#ifndef _FIDO_H_
#define _FIDO_H_

#ifndef ENABLE_EMULATION
#include "pico/stdlib.h"
#endif
#include "common.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/eddsa.h"
#ifndef ENABLE_EMULATION
#include "ctap_hid.h"
#else
#include <stdbool.h>
#endif

#define CTAP_PUBKEY_LEN (65)
#define KEY_PATH_LEN (32)
#define KEY_PATH_ENTRIES (KEY_PATH_LEN / sizeof(uint32_t))
#define SHA256_DIGEST_LENGTH (32)
#define KEY_HANDLE_LEN (KEY_PATH_LEN + SHA256_DIGEST_LENGTH)

extern int scan_files();
extern int derive_key(const uint8_t *app_id,
                      bool new_key,
                      uint8_t *key_handle,
                      int,
                      mbedtls_ecp_keypair *key);
extern int verify_key(const uint8_t *appId, const uint8_t *keyHandle, mbedtls_ecp_keypair *);
extern bool wait_button_pressed();
extern void init_fido();
extern mbedtls_ecp_group_id fido_curve_to_mbedtls(int curve);
extern int mbedtls_curve_to_fido(mbedtls_ecp_group_id id);
extern int fido_load_key(int curve, const uint8_t *cred_id, mbedtls_ecp_keypair *key);
extern int load_keydev(uint8_t *key);
extern int encrypt(uint8_t protocol,
                   const uint8_t *key,
                   const uint8_t *in,
                   size_t in_len,
                   uint8_t *out);
extern int decrypt(uint8_t protocol,
                   const uint8_t *key,
                   const uint8_t *in,
                   size_t in_len,
                   uint8_t *out);
extern int ecdh(uint8_t protocol, const mbedtls_ecp_point *Q, uint8_t *sharedSecret);

#define FIDO2_ALG_ES256     -7 //ECDSA-SHA256 P256
#define FIDO2_ALG_EDDSA     -8 //EdDSA
#define FIDO2_ALG_ES384     -35 //ECDSA-SHA384 P384
#define FIDO2_ALG_ES512     -36 //ECDSA-SHA512 P521
#define FIDO2_ALG_ECDH_ES_HKDF_256 -25 //ECDH-ES + HKDF-256
#define FIDO2_ALG_ES256K    -47
#define FIDO2_ALG_RS256     -257
#define FIDO2_ALG_RS384     -258
#define FIDO2_ALG_RS512     -259

#define FIDO2_CURVE_P256        1
#define FIDO2_CURVE_P384        2
#define FIDO2_CURVE_P521        3
#define FIDO2_CURVE_X25519      4
#define FIDO2_CURVE_X448        5
#define FIDO2_CURVE_ED25519     6
#define FIDO2_CURVE_ED448       7
#define FIDO2_CURVE_P256K1      8

#define FIDO2_AUT_FLAG_UP       0x1
#define FIDO2_AUT_FLAG_UV       0x4
#define FIDO2_AUT_FLAG_AT       0x40
#define FIDO2_AUT_FLAG_ED       0x80

#define FIDO2_OPT_EA            0x01 // Enterprise Attestation

#define MAX_PIN_RETRIES 8
extern bool getUserPresentFlagValue();
extern bool getUserVerifiedFlagValue();
extern void clearUserPresentFlag();
extern void clearUserVerifiedFlag();
extern void clearPinUvAuthTokenPermissionsExceptLbw();
extern void send_keepalive();
extern uint32_t get_sign_counter();
extern uint8_t get_opts();
extern void set_opts(uint8_t);
#define MAX_CREDENTIAL_COUNT_IN_LIST 16
#define MAX_CRED_ID_LENGTH        1024
#define MAX_RESIDENT_CREDENTIALS  256
#define MAX_CREDBLOB_LENGTH       128
#define MAX_MSG_SIZE              1024
#define MAX_FRAGMENT_LENGTH       (MAX_MSG_SIZE - 64)
#define MAX_LARGE_BLOB_SIZE       2048

typedef struct known_app {
    const uint8_t *rp_id_hash;
    const char *label;
    const bool *use_sign_count;
    const bool *use_self_attestation;
} known_app_t;

extern const known_app_t *find_app_by_rp_id_hash(const uint8_t *rp_id_hash);

#define TRANSPORT_TIME_LIMIT (30 * 1000) //USB

bool check_user_presence();

typedef struct pinUvAuthToken {
    uint8_t *data;
    size_t len;
    bool in_use;
    uint8_t permissions;
    uint8_t rp_id_hash[32];
    bool has_rp_id;
    bool user_present;
    bool user_verified;
} pinUvAuthToken_t;

extern uint32_t user_present_time_limit;

extern pinUvAuthToken_t paut;
extern int verify(uint8_t protocol,
                  const uint8_t *key,
                  const uint8_t *data,
                  size_t len,
                  uint8_t *sign);

#endif //_FIDO_H
