/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _CREDENTIAL_H_
#define _CREDENTIAL_H_

#include "ctap2_cbor.h"
#include "file.h"
#include "fido.h"

typedef struct CredOptions {
    const bool *rk;
    const bool *up;
    const bool *uv;
    bool present;
} CredOptions;

typedef struct CredExtensions {
    const bool *hmac_secret;
    uint64_t credProtect;
    const bool *minPinLength;
    CborByteString credBlob;
    const bool *largeBlobKey;
    const bool *thirdPartyPayment;
    bool present;
} CredExtensions;

typedef struct Credential {
    CborCharString rpId;
    CborByteString userId;
    CborCharString userName;
    CborCharString userDisplayName;
    uint64_t board_creation;
    CredExtensions extensions;
    const bool *use_sign_count;
    int64_t alg;
    int64_t curve;
    CborByteString id;
    CborByteString residentId;
    CredOptions opts;
    bool present;
    uint64_t rtc_creation;
} Credential;

typedef struct CredentialRp {
    uint8_t id_hash[RP_ID_HASH_LEN];
    uint8_t *id;
    size_t id_len;
} CredentialRp;

#define CRED_PROT_UV_OPTIONAL               0x01
#define CRED_PROT_UV_OPTIONAL_WITH_LIST     0x02
#define CRED_PROT_UV_REQUIRED               0x03

#define CRED_PROTO_21_S                     "\xf1\xd0\x02\x01"
#define CRED_PROTO_22_S                     "\xf1\xd0\x02\x02" // Contains silent tag for silent authentication
#define CRED_PROTO_23_S                     "\xf1\xd0\x02\x03" // Exclusive for resident credentials
#define CRED_PROTO_RP_S                     "\xf1\xd0\x02\x04" // Exclusive for RP records magic marker
#define CRED_PROTO_25_S                     "\xf1\xd0\x02\x05" // Contains ephemeral silent tag
#define CRED_PROTO_26_S                     "\xf1\xd0\x02\x06" // Resident credential ID with stable key seed

#define CRED_PROTO                          CRED_PROTO_25_S

#define CRED_PROTO_LEN                      4
#define CRED_IV_LEN                         12
#define CRED_TAG_LEN                        16
#define CRED_SILENT_HMAC_LEN                32
#define CRED_SILENT_TAG_LEN                 16
#define CRED_CIPHERTEXT_OFFSET              (CRED_PROTO_LEN + CRED_IV_LEN)
#define CRED_ENVELOPE_OVERHEAD              (CRED_CIPHERTEXT_OFFSET + CRED_TAG_LEN)
#define CRED_SILENT_ENVELOPE_OVERHEAD       (CRED_ENVELOPE_OVERHEAD + CRED_SILENT_TAG_LEN)

#define CRED_PROTO_RESIDENT                 CRED_PROTO_26_S
#define CRED_PROTO_RESIDENT_LEN             4
#define CRED_RESIDENT_HEADER_LEN            (CRED_PROTO_RESIDENT_LEN + 6)
#define CRED_RESIDENT_LEN                   (CRED_RESIDENT_HEADER_LEN + 32)
#define CRED_RESIDENT_SILENT_VERSION        1u
#define CRED_RESIDENT_SILENT_VERSION_OFFSET CRED_RESIDENT_LEN
#define CRED_RESIDENT_SILENT_TAG_OFFSET     (CRED_RESIDENT_SILENT_VERSION_OFFSET + 1u)
#define CRED_RESIDENT_RECORD_LEN            (CRED_RESIDENT_SILENT_TAG_OFFSET + CRED_SILENT_TAG_LEN)

typedef enum
{
    CRED_PROTO_21 = 0x01,
    CRED_PROTO_22 = 0x02,
    CRED_PROTO_25 = 0x05
} cred_proto_t;

extern int credential_verify(uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, bool silent);
extern int credential_create(CborCharString *rpId,
                             CborByteString *userId,
                             CborCharString *userName,
                             CborCharString *userDisplayName,
                             CredOptions *opts,
                             CredExtensions *extensions,
                             bool use_sign_count,
                             int alg,
                             int curve,
                             uint8_t *cred_id,
                             uint16_t *cred_id_len);
extern void credential_free(Credential *cred);
extern int credential_store(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, const uint8_t *public_key, size_t public_key_len);
extern int credential_load(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, Credential *cred);
extern int credential_derive_hmac_key(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk);
extern int credential_derive_large_blob_key(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk);
extern int credential_derive_resident(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk);
extern bool credential_is_resident(const uint8_t *cred_id, size_t cred_id_len);
extern bool credential_resident_id_uses_stable_keys(const uint8_t *resident_id, size_t resident_id_len);
extern int credential_load_resident(const file_t *ef, const uint8_t *rp_id_hash, Credential *cred);
extern bool credential_resident_matches_rp(const file_t *ef, const uint8_t rp_id_hash[RP_ID_HASH_LEN]);
extern bool credential_resident_matches_id(const file_t *ef, const uint8_t *resident_id, size_t resident_id_len);
extern int credential_resident_rp_id_hash(const file_t *ef, uint8_t rp_id_hash[RP_ID_HASH_LEN]);
extern int credential_resident_public_key(const file_t *ef, uint8_t **public_key, size_t *public_key_len);
extern int credential_resident_update(const file_t *ef, const uint8_t *credential, size_t credential_len);
extern int credential_resident_delete(const file_t *ef);
extern int credential_resident_verify(const file_t *ef, const uint8_t rp_id_hash[RP_ID_HASH_LEN], bool silent);
extern int credential_rp_id_decrypt(const file_t *ef, uint8_t **rp_id, size_t *rp_id_len);
extern int credential_migrate_rp_secure(void);
extern int credential_rp_count(uint16_t *count);
extern int credential_rp_load(uint16_t index, CredentialRp *rp);
extern void credential_rp_free(CredentialRp *rp);
extern int credential_rp_legacy_decrement(const uint8_t rp_id_hash[RP_ID_HASH_LEN]);

#endif // _CREDENTIAL_H_
