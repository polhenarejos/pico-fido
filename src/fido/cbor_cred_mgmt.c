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

#include "pico_keys.h"
#include "fido.h"
#include "ctap.h"
#include "hid/ctap_hid.h"
#include "cbor_make_credential.h"
#include "files.h"
#include "apdu.h"
#include "credential.h"

uint8_t rp_counter = 1;
uint8_t rp_total = 0;
uint8_t cred_counter = 1;
uint8_t cred_total = 0;
CborByteString rpIdHashx = { 0 };

int cbor_cred_mgmt(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    uint64_t subcommand = 0, pinUvAuthProtocol = 0;
    CborByteString pinUvAuthParam = { 0 }, rpIdHash = { 0 };
    PublicKeyCredentialDescriptor credentialId = { 0 };
    PublicKeyCredentialUserEntity user = { 0 };
    size_t resp_size = 0;
    CborEncoder encoder, mapEncoder, mapEncoder2;
    uint8_t *raw_subpara = NULL;
    size_t raw_subpara_len = 0;
    bool asserted = false, is_preview = *(data - 1) == 0x41; // Backwards compatibility

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
                                CBOR_FIELD_GET_TEXT(credentialId.transports[credentialId.transports_len], 4);
                                credentialId.transports_len++;
                            }
                            CBOR_PARSE_ARRAY_END(_f3, 4);
                        }
                    }
                    CBOR_PARSE_MAP_END(_f2, 3);
                }
                else if (subpara == 0x03) {
                    CBOR_PARSE_MAP_START(_f1, 3)
                    {
                        CBOR_FIELD_GET_KEY_TEXT(3);
                        CBOR_FIELD_KEY_TEXT_VAL_BYTES(3, "id", user.id);
                        CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "name", user.parent.name);
                        CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "displayName", user.displayName);
                    }
                    CBOR_PARSE_MAP_END(_f1, 3);
                }
            }
            CBOR_PARSE_MAP_END(_f1, 2);
            raw_subpara_len = cbor_value_get_next_byte(&_f1) - raw_subpara;
        }
        else if (val_u == 0x03) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x04) { // pubKeyCredParams
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    if (subcommand != 0x03 && subcommand != 0x05) {
        if (pinUvAuthParam.present == false) {
            CBOR_ERROR(CTAP2_ERR_PUAT_REQUIRED);
        }
        if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
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
            if (file_has_data(search_dynamic_file((uint16_t)(EF_CRED + i)))) {
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
        file_t *rp_ef = NULL;
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
            rp_counter = 1;
            rp_total = 0;
        }
        else {
            if (rp_counter > rp_total) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
        }
        uint8_t skip = 0;
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            file_t *tef = search_dynamic_file((uint16_t)(EF_RP + i));
            if (file_has_data(tef) && *file_get_data(tef) > 0) {
                if (++skip == rp_counter) {
                    if (rp_ef == NULL) {
                        rp_ef = tef;
                    }
                    if (subcommand == 0x03) {
                        break;
                    }
                }
                if (subcommand == 0x02) {
                    rp_total++;
                }
            }
        }
        if (rp_ef == NULL) {
            CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
        }
        rp_counter++;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, subcommand == 0x02 ? 3 : 2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, 1));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder2, (char *) file_get_data(rp_ef) + 33,
                                           file_get_size(rp_ef) - 33));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, file_get_data(rp_ef) + 1, 32));
        if (subcommand == 0x02) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, rp_total));
        }
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
                    (paut.has_rp_id == true && memcmp(paut.rp_id_hash, rpIdHash.data, 32) != 0))) {
                    CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
                }
            }
            cred_counter = 1;
            cred_total = 0;
        }
        else {
            if (cred_counter > cred_total) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
            rpIdHash = rpIdHashx;
        }
        file_t *cred_ef = NULL;
        uint8_t skip = 0;
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            file_t *tef = search_dynamic_file((uint16_t)(EF_CRED + i));
            if (file_has_data(tef) && memcmp(file_get_data(tef), rpIdHash.data, 32) == 0) {
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

        mbedtls_ecp_keypair key;
        mbedtls_ecp_keypair_init(&key);
        if (fido_load_key((int)cred.curve, cred.id.data, &key) != 0) {
            credential_free(&cred);
            mbedtls_ecp_keypair_free(&key);
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }

        cred_counter++;

        uint8_t l = 4;
        if (subcommand == 0x04) {
            l++;
        }
        if (cred.extensions.present == true) {
            if (cred.extensions.credProtect > 0) {
                l++;
            }
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
        uint8_t cred_idr[CRED_RESIDENT_LEN] = {0};
        credential_derive_resident(cred.id.data, cred.id.len, cred_idr);
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, cred_idr, sizeof(cred_idr)));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "type"));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "public-key"));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));

        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
        CBOR_CHECK(COSE_key(&key, &mapEncoder, &mapEncoder2));

        if (subcommand == 0x04) {
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x09));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, cred_total));
        }
        if (cred_counter <= cred_total) {
            asserted = true;
            rpIdHashx = rpIdHash;
        }
        if (cred.extensions.present == true) {
            if (cred.extensions.credProtect > 0) {
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0A));
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, cred.extensions.credProtect));
            }
            if (cred.extensions.largeBlobKey == ptrue) {
                uint8_t largeBlobKey[32];
                int ret = credential_derive_large_blob_key(cred.id.data, cred.id.len, largeBlobKey);
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
        if (is_preview == false &&
            (!(paut.permissions & CTAP_PERMISSION_CM) ||
             (paut.has_rp_id == true && memcmp(paut.rp_id_hash, rpIdHash.data, 32) != 0))) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            file_t *ef = search_dynamic_file((uint16_t)(EF_CRED + i));
            if (file_has_data(ef) && memcmp(file_get_data(ef) + 32, credentialId.id.data, CRED_RESIDENT_LEN) == 0) {
                uint8_t *rp_id_hash = file_get_data(ef);
                if (delete_file(ef) != 0) {
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                }
                for (int j = 0; j < MAX_RESIDENT_CREDENTIALS; j++) {
                    file_t *rp_ef = search_dynamic_file((uint16_t)(EF_RP + j));
                    if (file_has_data(rp_ef) && memcmp(file_get_data(rp_ef) + 1, rp_id_hash, 32) == 0) {
                        uint8_t *rp_data = (uint8_t *) calloc(1, file_get_size(rp_ef));
                        memcpy(rp_data, file_get_data(rp_ef), file_get_size(rp_ef));
                        rp_data[0] -= 1;
                        if (rp_data[0] == 0) {
                            delete_file(rp_ef);
                        }
                        else {
                            file_put_data(rp_ef, rp_data, file_get_size(rp_ef));
                        }
                        free(rp_data);
                        break;
                    }
                }
                low_flash_available();
                goto err; //no error
            }
        }
        CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
    }
    else if (subcommand == 0x07) {
        if (credentialId.id.present == false || user.id.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        *(raw_subpara - 1) = 0x07;
        if (verify((uint8_t)pinUvAuthProtocol, paut.data, raw_subpara - 1, (uint16_t)(raw_subpara_len + 1), pinUvAuthParam.data) != CborNoError) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if (is_preview == false &&
            (!(paut.permissions & CTAP_PERMISSION_CM) ||
             (paut.has_rp_id == true && memcmp(paut.rp_id_hash, rpIdHash.data, 32) != 0))) {
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            file_t *ef = search_dynamic_file((uint16_t)(EF_CRED + i));
            if (file_has_data(ef) && memcmp(file_get_data(ef) + 32, credentialId.id.data, CRED_RESIDENT_LEN) == 0) {
                Credential cred = { 0 };
                uint8_t *rp_id_hash = file_get_data(ef);
                if (credential_load_resident(ef, rp_id_hash, &cred) != 0) {
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                }
                if (memcmp(user.id.data, cred.userId.data, MIN(user.id.len, cred.userId.len)) != 0) {
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
                if (credential_store(newcred, newcred_len, rp_id_hash) != 0) {
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                }
                low_flash_available();
                goto err; //no error
            }
        }
        CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
err:
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
