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

#include "picokeys.h"
#include "fido.h"
#include "ctap.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#include "hid/ctap_hid.h"
#include "cbor_make_credential.h"
#include "files.h"
#include "apdu.h"
#include "credential.h"
#include "resident_container.h"
#include "mbedtls/constant_time.h"

uint16_t rp_counter = 1;
uint16_t rp_total = 0;
uint16_t cred_counter = 1;
uint16_t cred_total = 0;
uint32_t rp_channel = 0;
uint32_t cred_channel = 0;
uint32_t rp_timer = 0;
uint32_t cred_timer = 0;
bool rp_walk_active = false;
bool cred_walk_active = false;
CborByteString rpIdHashx = { 0 };

void cbor_cred_mgmt_tick(void) {
    uint32_t now = board_millis();
    if (rp_walk_active && now - rp_timer >= STATEFUL_WALK_IDLE_MS) {
        rp_counter = rp_total;
        rp_channel = 0;
        rp_walk_active = false;
    }
    if (cred_walk_active && now - cred_timer >= STATEFUL_WALK_IDLE_MS) {
        cred_counter = cred_total + 1;
        cred_channel = 0;
        cred_walk_active = false;
    }
}

int cbor_cred_mgmt(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    uint64_t subcommand = 0, pinUvAuthProtocol = 0;
    CborByteString pinUvAuthParam = { 0 }, rpIdHash = { 0 };
    PublicKeyCredentialDescriptor credentialId = { 0 };
    PublicKeyCredentialUserEntity user = { 0 };
    CredentialRp rp_record = { 0 };
    size_t resp_size = 0;
    CborEncoder encoder, mapEncoder, mapEncoder2;
    uint8_t *raw_subpara = NULL;
    size_t raw_subpara_len = 0;
    bool asserted = false, is_preview = *(data - 1) == 0x41, pinUvAuthProtocol_present = false; // Backwards compatibility

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 1 && val_c != val_u) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (val_u < val_c) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x02) {
            uint64_t subpara = 0;
            raw_subpara = (uint8_t *) cbor_value_get_next_byte(&_f1);
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_UINT(subpara, 2);
                if (subpara == 0x01) {
                    CBOR_FIELD_GET_BYTES(rpIdHash, 2);
                }
                else if (subpara == 0x02) {

                    CBOR_PARSE_MAP_START(_f2, 3)
                    {
                        CBOR_FIELD_GET_KEY_TEXT(3);
                        CBOR_FIELD_KEY_TEXT_VAL_BYTES(3, "id", credentialId.id);
                        CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "type", credentialId.type);
                        if (strcmp(_fd3, "transports") == 0) {
                            CBOR_PARSE_ARRAY_START(_f3, 4)
                            {
                                if (credentialId.transports_len >= sizeof(credentialId.transports) / sizeof(credentialId.transports[0])) {
                                    CBOR_ERROR(CTAP2_ERR_LIMIT_EXCEEDED);
                                }
                                CBOR_FIELD_GET_TEXT(credentialId.transports[credentialId.transports_len], 4);
                                credentialId.transports_len++;
                            }
                            CBOR_PARSE_ARRAY_END(_f3, 4);
                        }
                    }
                    CBOR_PARSE_MAP_END(_f2, 3);
                }
                else if (subpara == 0x03) {
                    CBOR_PARSE_MAP_START(_f2, 3)
                    {
                        CBOR_FIELD_GET_KEY_TEXT(3);
                        CBOR_FIELD_KEY_TEXT_VAL_BYTES(3, "id", user.id);
                        CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "name", user.parent.name);
                        CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "displayName", user.displayName);
                    }
                    CBOR_PARSE_MAP_END(_f2, 3);
                }
            }
            CBOR_PARSE_MAP_END(_f1, 2);
            raw_subpara_len = cbor_value_get_next_byte(&_f1) - raw_subpara;
        }
        else if (val_u == 0x03) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
            pinUvAuthProtocol_present = true;
        }
        else if (val_u == 0x04) { // pubKeyCredParams
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    if ((rpIdHash.present && rpIdHash.len != RP_ID_HASH_LEN) || (credentialId.id.present && credentialId.id.len != CRED_RESIDENT_LEN)) {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }

    if (pinUvAuthProtocol_present && pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }
    if (subcommand != 0x03 && subcommand != 0x05) {
        if (pinUvAuthParam.present == false) {
            CBOR_ERROR(CTAP2_ERR_PUAT_REQUIRED);
        }
        if (pinUvAuthProtocol_present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
    }

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);
    if (subcommand == 0x01) {
        if (verify((uint8_t)pinUvAuthProtocol, ppaut.data, (const uint8_t *) "\x01", 1, pinUvAuthParam.data) == CborNoError) {
            if (!(ppaut.permissions & CTAP_PERMISSION_PCMR)) {
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
            }
        }
        else {
            if (verify((uint8_t)pinUvAuthProtocol, paut.data, (const uint8_t *) "\x01", 1, pinUvAuthParam.data) != CborNoError) {
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
            }
            if (is_preview == false &&
                (!(paut.permissions & CTAP_PERMISSION_CM) || paut.has_rp_id == true)) {
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
            }
        }
        uint8_t existing = 0;
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            if (file_has_data(file_search((uint16_t)(EF_CRED + i)))) {
                existing++;
            }
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, existing));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_RESIDENT_CREDENTIALS - existing));
    }
    else if (subcommand == 0x02 || subcommand == 0x03) {
        if (subcommand == 0x02) {
            if (verify((uint8_t)pinUvAuthProtocol, ppaut.data, (const uint8_t *) "\x02", 1, pinUvAuthParam.data) == CborNoError) {
                if (!(ppaut.permissions & CTAP_PERMISSION_PCMR)) {
                    CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
                }
            }
            else {
                if (verify((uint8_t)pinUvAuthProtocol, paut.data, (const uint8_t *) "\x02", 1, pinUvAuthParam.data) != CborNoError) {
                    CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
                }
                if (is_preview == false && (!(paut.permissions & CTAP_PERMISSION_CM) || paut.has_rp_id == true)) {
                    CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
                }
            }
            rp_counter = 0;
            rp_channel = ctap_req ? ctap_req->cid : 0;
            if (credential_rp_count(&rp_total) != PICOKEYS_OK) {
                CBOR_ERROR(CTAP2_ERR_PROCESSING);
            }
        }
        else {
            uint32_t channel = ctap_req ? ctap_req->cid : 0;
            if (rp_channel != channel || rp_counter >= rp_total) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
        }
        int rp_ret = credential_rp_load(rp_counter, &rp_record);
        if (rp_ret != PICOKEYS_OK) {
            CBOR_ERROR(rp_ret == PICOKEYS_ERR_FILE_NOT_FOUND ? CTAP2_ERR_NO_CREDENTIALS : CTAP2_ERR_PROCESSING);
        }
        rp_counter++;
        if (rp_counter < rp_total) {
            rp_timer = board_millis();
            rp_walk_active = true;
        }
        else {
            rp_walk_active = false;
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, subcommand == 0x02 ? 3 : 2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, 1));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
        error = cbor_encode_text_string(&mapEncoder2, (char *) rp_record.id, rp_record.id_len);
        if (error != CborNoError) {
            printf("Cannot encode CBOR [%s:%d]: cbor_encode_text_string(&mapEncoder2, (char *) rp_record.id, rp_record.id_len) (%d)\n", __FILE__, __LINE__, error);
            goto err;
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, rp_record.id_hash, sizeof(rp_record.id_hash)));
        if (subcommand == 0x02) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, rp_total));
        }
        credential_rp_free(&rp_record);
    }
    else if (subcommand == 0x04 || subcommand == 0x05) {
        if (subcommand == 0x04 && rpIdHash.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (subcommand == 0x04) {
            *(raw_subpara - 1) = 0x04;
            if (verify((uint8_t)pinUvAuthProtocol, ppaut.data, raw_subpara - 1, (uint16_t)(raw_subpara_len + 1), pinUvAuthParam.data) == CborNoError) {
                if (!(ppaut.permissions & CTAP_PERMISSION_PCMR)) {
                    CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
                }
            }
            else {
                if (verify((uint8_t)pinUvAuthProtocol, paut.data, raw_subpara - 1, (uint16_t)(raw_subpara_len + 1), pinUvAuthParam.data) != CborNoError) {
                    CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
                }
                if (is_preview == false &&
                    (!(paut.permissions & CTAP_PERMISSION_CM) ||
                    (paut.has_rp_id == true && memcmp(paut.rp_id_hash, rpIdHash.data, RP_ID_HASH_LEN) != 0))) {
                    CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
                }
            }
            cred_counter = 1;
            cred_total = 0;
            cred_channel = ctap_req ? ctap_req->cid : 0;
        }
        else {
            uint32_t channel = ctap_req ? ctap_req->cid : 0;
            if (cred_channel != channel || cred_counter > cred_total) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
            rpIdHash = rpIdHashx;
        }
        file_t *cred_ef = NULL;
        uint16_t skip = 0;
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            file_t *tef = file_search((uint16_t)(EF_CRED + i));
            if (file_has_data(tef) && credential_resident_matches_rp(tef, rpIdHash.data)) {
                if (++skip == cred_counter) {
                    if (cred_ef == NULL) {
                        cred_ef = tef;
                    }
                    if (subcommand == 0x05) {
                        break;
                    }
                }
                if (subcommand == 0x04) {
                    cred_total++;
                }
            }
        }
        if (!file_has_data(cred_ef)) {
            CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
        }

        Credential cred = { 0 };
        if (credential_load_resident(cred_ef, rpIdHash.data, &cred) != 0) {
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        const uint8_t *key_seed = cred.id.data;
        size_t key_seed_len = cred.id.len;
        if (cred.residentId.present == true &&
            credential_resident_id_uses_stable_keys(cred.residentId.data, cred.residentId.len)) {
            key_seed = cred.residentId.data;
            key_seed_len = cred.residentId.len;
        }

        uint8_t *cached_public_key = NULL;
        size_t cached_public_key_len = 0;
        int cached_public_key_status = credential_resident_public_key(cred_ef, &cached_public_key, &cached_public_key_len);
        bool use_cached_public_key = cached_public_key_status == PICOKEYS_OK;
        if (resident_container_is_marker(cred_ef) && !use_cached_public_key) {
            credential_free(&cred);
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        mbedtls_ecp_keypair key;
        mbedtls_ecp_keypair_init(&key);
        if (!use_cached_public_key && fido_load_key((int)cred.curve, key_seed, &key) != 0) {
            credential_free(&cred);
            mbedtls_ecp_keypair_free(&key);
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }

        cred_counter++;

        uint8_t l = 5;
        if (subcommand == 0x04) {
            l++;
        }
        if (cred.extensions.present == true) {
            if (cred.extensions.largeBlobKey == ptrue) {
                l++;
            }
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, l));

        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x06));
        l = 0;
        if (cred.userId.present == true) {
            l++;
        }
        if (cred.userName.present == true) {
            l++;
        }
        if (cred.userDisplayName.present == true) {
            l++;
        }
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, l));
        if (cred.userId.present == true) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, cred.userId.data, cred.userId.len));
        }
        if (cred.userName.present == true) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "name"));
            CBOR_CHECK(cbor_encode_text_string(&mapEncoder2, cred.userName.data, cred.userName.len));
        }
        if (cred.userDisplayName.present == true) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "displayName"));
            CBOR_CHECK(cbor_encode_text_string(&mapEncoder2, cred.userDisplayName.data, cred.userDisplayName.len));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));

        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, 2));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
        if (cred.residentId.present == true) {
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, cred.residentId.data, cred.residentId.len));
        }
        else {
            uint8_t cred_idr[CRED_RESIDENT_LEN] = {0};
            credential_derive_resident(cred.id.data, cred.id.len, cred_idr);
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, cred_idr, sizeof(cred_idr)));
        }
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "type"));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "public-key"));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));

        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
        if (use_cached_public_key) {
            CBOR_CHECK(COSE_cached_key(cached_public_key, cached_public_key_len, &mapEncoder, &mapEncoder2));
        }
        else {
            CBOR_CHECK(COSE_key(&key, (int)cred.alg, &mapEncoder, &mapEncoder2));
        }

        if (subcommand == 0x04) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x09));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, cred_total));
        }
        if (cred_counter <= cred_total) {
            asserted = true;
            rpIdHashx = rpIdHash;
            cred_timer = board_millis();
            cred_walk_active = true;
        }
        else {
            cred_walk_active = false;
        }
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0A));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, cred.extensions.credProtect > 0 ? cred.extensions.credProtect : CRED_PROT_UV_OPTIONAL));
        if (cred.extensions.present == true) {
            if (cred.extensions.largeBlobKey == ptrue) {
                uint8_t largeBlobKey[32];
                int ret = credential_derive_large_blob_key(key_seed, key_seed_len, largeBlobKey);
                if (ret != 0) {
                    CBOR_ERROR(CTAP2_ERR_PROCESSING);
                }
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0B));
                CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, largeBlobKey, sizeof(largeBlobKey)));
                mbedtls_platform_zeroize(largeBlobKey, sizeof(largeBlobKey));
            }
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0C));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, cred.extensions.thirdPartyPayment == ptrue));
        }
        else {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0C));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, false));
        }
        credential_free(&cred);
        free(cached_public_key);
        mbedtls_ecp_keypair_free(&key);
    }
    else if (subcommand == 0x06) {
        if (credentialId.id.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        *(raw_subpara - 1) = 0x06;
        if (verify((uint8_t)pinUvAuthProtocol, paut.data, raw_subpara - 1, (uint16_t)(raw_subpara_len + 1), pinUvAuthParam.data) != CborNoError) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (is_preview == false && (!(paut.permissions & CTAP_PERMISSION_CM) || (paut.has_rp_id == true && memcmp(paut.rp_id_hash, rpIdHash.data, RP_ID_HASH_LEN) != 0))) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            file_t *ef = file_search((uint16_t)(EF_CRED + i));
            if (file_has_data(ef) && credential_resident_matches_id(ef, credentialId.id.data, credentialId.id.len)) {
                bool legacy_rp = !resident_container_is_marker(ef);
                uint8_t rp_id_hash[RP_ID_HASH_LEN];
                if (credential_resident_rp_id_hash(ef, rp_id_hash) != PICOKEYS_OK) {
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                }
                if (is_preview == false && paut.has_rp_id == true && mbedtls_ct_memcmp(paut.rp_id_hash, rp_id_hash, RP_ID_HASH_LEN) != 0) {
                    CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
                }
                if (credential_resident_delete(ef) != PICOKEYS_OK) {
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                }
                if (legacy_rp) {
                    int rp_ret = credential_rp_legacy_decrement(rp_id_hash);
                    if (rp_ret != PICOKEYS_OK && rp_ret != PICOKEYS_ERR_FILE_NOT_FOUND) {
                        CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                    }
                }
                dev_state_update(DEV_STATE_CRED_STATE);
                flash_commit();
                goto err; //no error
            }
        }
        CBOR_ERROR(paut.has_rp_id && is_preview == false ? CTAP2_ERR_PIN_AUTH_INVALID : CTAP2_ERR_NO_CREDENTIALS);
    }
    else if (subcommand == 0x07) {
        if (credentialId.id.present == false || user.id.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        *(raw_subpara - 1) = 0x07;
        if (verify((uint8_t)pinUvAuthProtocol, paut.data, raw_subpara - 1, (uint16_t)(raw_subpara_len + 1), pinUvAuthParam.data) != CborNoError) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (is_preview == false && (!(paut.permissions & CTAP_PERMISSION_CM) || (paut.has_rp_id == true && memcmp(paut.rp_id_hash, rpIdHash.data, RP_ID_HASH_LEN) != 0))) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            file_t *ef = file_search((uint16_t)(EF_CRED + i));
            if (file_has_data(ef) && credential_resident_matches_id(ef, credentialId.id.data, credentialId.id.len)) {
                Credential cred = { 0 };
                uint8_t rp_id_hash[RP_ID_HASH_LEN];
                if (credential_resident_rp_id_hash(ef, rp_id_hash) != PICOKEYS_OK || credential_load_resident(ef, rp_id_hash, &cred) != 0) {
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                }
                if (is_preview == false && paut.has_rp_id == true && mbedtls_ct_memcmp(paut.rp_id_hash, rp_id_hash, RP_ID_HASH_LEN) != 0) {
                    credential_free(&cred);
                    CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
                }
                if (user.id.len != cred.userId.len || mbedtls_ct_memcmp(user.id.data, cred.userId.data, user.id.len) != 0) {
                    credential_free(&cred);
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }
                uint8_t newcred[MAX_CRED_ID_LENGTH];
                uint16_t newcred_len = 0;
                if (credential_create(&cred.rpId, &cred.userId, &user.parent.name,
                                    &user.displayName, &cred.opts, &cred.extensions,
                                    cred.use_sign_count, (int)cred.alg,
                                    (int)cred.curve, newcred, &newcred_len) != 0) {
                    credential_free(&cred);
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                }
                credential_free(&cred);
                if (credential_resident_update(ef, newcred, newcred_len) != PICOKEYS_OK) {
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                }
                dev_state_update(DEV_STATE_CRED_STATE);
                flash_commit();
                goto err; //no error
            }
        }
        CBOR_ERROR(paut.has_rp_id && is_preview == false ? CTAP2_ERR_PIN_AUTH_INVALID : CTAP2_ERR_NO_CREDENTIALS);
    }
    else {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
err:
    credential_rp_free(&rp_record);
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);

    if (asserted == false) {
        CBOR_FREE_BYTE_STRING(rpIdHash);
    }
    CBOR_FREE_BYTE_STRING(user.id);
    CBOR_FREE_BYTE_STRING(user.displayName);
    CBOR_FREE_BYTE_STRING(user.parent.name);
    CBOR_FREE_BYTE_STRING(credentialId.type);
    CBOR_FREE_BYTE_STRING(credentialId.id);
    for (size_t n = 0; n < credentialId.transports_len; n++) {
        CBOR_FREE_BYTE_STRING(credentialId.transports[n]);
    }
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}
