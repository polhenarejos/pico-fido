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

#ifndef _CREDENTIAL_H_
#define _CREDENTIAL_H_

#include "ctap2_cbor.h"

typedef struct CredOptions {
    const bool *rk;
    const bool *up;
    const bool *uv;
    bool present;
} CredOptions;

typedef struct Credential {
    CborCharString rpId;
    CborByteString userId;
    uint64_t creation;
    const bool *hmac_secret;
    const bool *use_sign_count;
    int64_t alg;
    int64_t curve;
    bool present;
} Credential;

extern int credential_verify(uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash);
extern int credential_create(CborCharString *rpId, CborByteString *userId, CborCharString *userName, CborCharString *userDisplayName, const bool *hmac_secret, bool use_sign_count, int alg, int curve, uint8_t *cred_id, size_t *cred_id_len);
extern void credential_free(Credential *cred);
extern int credential_store(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash);

#endif // _CREDENTIAL_H_
