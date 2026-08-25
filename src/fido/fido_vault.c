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
#include "serial.h"
#include "ctap2_cbor.h"
#include "fido.h"
#include "ctap.h"
#include "hid/ctap_hid.h"
#include "files.h"
#include "credential.h"
#include "apdu.h"
#include "random.h"
#if defined(ESP_PLATFORM)
#include "compat/esp_compat.h"
#else
#include "compat/board.h"
#endif
#include "crypto_utils.h"
#include "mbedtls/md.h"
#include "mbedtls/constant_time.h"

#include "fido_vault.h"
#include "object_container_store.h"
#include "object_provider.h"
#include "mbedtls/sha256.h"

extern uint8_t keydev_dec[32];
extern bool has_keydev_dec;

static int vault_sdk_init(void) {
    static file_object_container_crypto_t primary;
    primary.auth = fido_object_manifest_authenticator();
    primary.protector = fido_object_record_protector();
    if (!primary.auth || !primary.protector) {
        return PICOKEYS_EXEC_ERROR;
    }
    return picokeys_vault_init(&primary, NULL, ef_vault_key, file_search_by_fid(EF_VAULT_LABEL, NULL, SPECIFY_EF));
}

static const uint8_t vault_blob_magic[] = { 'P', 'K', 'V', 1 };

static int vault_pin_auth(uint8_t protocol, const CborByteString *auth, const uint8_t *raw_params, size_t raw_params_len, uint64_t subcommand) {
    if (!auth->present) {
        return CTAP2_ERR_PUAT_REQUIRED;
    }
    if ((protocol != 1 && protocol != 2) || auth->len != (protocol == 1 ? 16u : 32u)) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (raw_params_len > CTAP_MAX_CBOR_PAYLOAD - 34u) {
        return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    uint8_t *payload = calloc(1, 34u + raw_params_len);
    if (!payload) {
        return CTAP2_ERR_PROCESSING;
    }
    memset(payload, 0xff, 32);
    payload[32] = 0x0d;
    payload[33] = (uint8_t)subcommand;
    if (raw_params_len) {
        memcpy(payload + 34, raw_params, raw_params_len);
    }
    int ret = verify(protocol, paut.data, payload, (uint16_t)(34u + raw_params_len), auth->data);
    free(payload);
    if (ret != 0 || !(paut.permissions & CTAP_PERMISSION_ACFG)) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    return 0;
}

int vault_load_key(uint8_t key[VAULT_KEY_BYTES]) {
    if (!key || !ef_vault_key) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    int ret = vault_sdk_init();
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    uint8_t keydev[VAULT_KEY_BYTES] = { 0 };
    ret = load_keydev(keydev);
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(keydev, sizeof(keydev));
        return ret;
    }
    ret = picokeys_vault_get_kvault(VAULT_APP_ID, keydev, key);
    mbedtls_platform_zeroize(keydev, sizeof(keydev));
    return ret;
}

int vault_enrollment_finish(const uint8_t *packet, size_t packet_len) {
    if (!ef_vault_key) {
        picokeys_vault_enrollment_reset();
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }

    uint8_t kvault[VAULT_KEY_BYTES] = { 0 };
    uint8_t label[VAULT_LABEL_MAX] = { 0 };
    size_t label_len = 0;
    int ret = picokeys_vault_enrollment_decode(packet, packet_len, kvault, label, sizeof(label), &label_len);
    if (ret == PICOKEYS_OK) {
        ret = vault_sdk_init();
    }
    uint8_t keydev[VAULT_KEY_BYTES] = { 0 };
    if (ret == PICOKEYS_OK) {
        ret = load_keydev(keydev);
    }
    if (ret == PICOKEYS_OK) {
        ret = picokeys_vault_set_kvault(kvault, keydev, VAULT_APP_ID);
    }
    if (ret == PICOKEYS_OK) {
        ret = picokeys_vault_set_label(CONST_BYTE_ARRAY(label, label_len));
    }
    mbedtls_platform_zeroize(keydev, sizeof(keydev));
    mbedtls_platform_zeroize(kvault, sizeof(kvault));
    mbedtls_platform_zeroize(label, sizeof(label));
    if (ret != PICOKEYS_OK) {
        picokeys_vault_enrollment_reset();
    }
    return ret;
}

int vault_export_blob(const uint8_t *requested_id, size_t requested_id_len, uint8_t algorithm, uint8_t *blob, size_t blob_capacity, size_t *blob_len, uint8_t *metadata, size_t metadata_capacity, size_t *metadata_len) {
    if (!requested_id || requested_id_len == 0 || requested_id_len > MAX_CRED_ID_LENGTH || !blob || !blob_len || !metadata || !metadata_len) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!picokeys_vault_algorithm_valid(algorithm)) {
        return PICOKEYS_WRONG_DATA;
    }
    Credential credential = {0};
    file_t *found = NULL;
    uint8_t rp_id_hash[RP_ID_HASH_LEN] = {0};
    int ret = PICOKEYS_ERR_FILE_NOT_FOUND;
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS && !found; i++) {
        file_t *ef = file_search((uint16_t)(EF_CRED + i));
        if (!file_has_data(ef) || credential_resident_rp_id_hash(ef, rp_id_hash) != PICOKEYS_OK) {
            continue;
        }
        Credential current = {0};
        if (credential_load_resident(ef, rp_id_hash, &current) == 0) {
            if ((current.id.len == requested_id_len && mbedtls_ct_memcmp(current.id.data, requested_id, requested_id_len) == 0) || credential_resident_matches_id(ef, requested_id, requested_id_len)) {
                credential = current;
                found = ef;
            }
            else {
                credential_free(&current);
            }
        }
    }
    if (!found) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    const uint8_t *key_seed = credential.id.data;
    if (credential.residentId.present && credential_resident_id_uses_stable_keys(credential.residentId.data, credential.residentId.len)) {
        key_seed = credential.residentId.data;
    }
    mbedtls_ecp_keypair credential_key;
    mbedtls_ecp_keypair_init(&credential_key);
    uint8_t private_key[80] = {0};
    size_t private_len = 0;
    ret = PICOKEYS_OK;
    if (credential.privateKey.present) {
        private_len = credential.privateKey.len;
        if (private_len <= sizeof(private_key)) {
            memcpy(private_key, credential.privateKey.data, private_len);
        }
        else {
            ret = PICOKEYS_WRONG_LENGTH;
        }
    }
    else {
        ret = fido_load_key((int)credential.curve, key_seed, &credential_key);
        if (ret == 0) {
            ret = mbedtls_ecp_write_key_ext(&credential_key, &private_len, private_key, sizeof(private_key));
        }
    }
    mbedtls_ecp_keypair_free(&credential_key);
    if (ret != 0 || private_len == 0) {
        credential_free(&credential);
        mbedtls_platform_zeroize(private_key, sizeof(private_key));
        return PICOKEYS_EXEC_ERROR;
    }
    uint8_t embedded_metadata[VAULT_CREDENTIAL_METADATA_MAX] = {0};
    if (vault_encode_credential_metadata(&credential, rp_id_hash, embedded_metadata, sizeof(embedded_metadata), metadata_len) != PICOKEYS_OK || *metadata_len > metadata_capacity) {
        credential_free(&credential);
        mbedtls_platform_zeroize(private_key, sizeof(private_key));
        return PICOKEYS_ERR_NO_MEMORY;
    }
    memcpy(metadata, embedded_metadata, *metadata_len);
    uint8_t plain[VAULT_PLAIN_MAX] = {0};
    CborEncoder plain_encoder, plain_map;
    CborError error = CborNoError;
    cbor_encoder_init(&plain_encoder, plain, sizeof(plain), 0);
    if ((error = cbor_encoder_create_map(&plain_encoder, &plain_map, 6)) == CborNoError) {
        error = cbor_encode_uint(&plain_map, 1);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 1);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 2);
    }
    if (error == CborNoError) {
        error = cbor_encode_byte_string(&plain_map, credential.id.data, credential.id.len);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 3);
    }
    if (error == CborNoError) {
        error = cbor_encode_byte_string(&plain_map, private_key, private_len);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 4);
    }
    if (error == CborNoError) {
        error = cbor_encode_text_string(&plain_map, credential.rpId.data, credential.rpId.len);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 5);
    }
    if (error == CborNoError) {
        error = cbor_encode_byte_string(&plain_map, embedded_metadata, *metadata_len);
    }
    if (error == CborNoError) {
        error = cbor_encode_uint(&plain_map, 6);
    }
    if (error == CborNoError) {
        error = cbor_encode_byte_string(&plain_map, requested_id, requested_id_len);
    }
    if (error == CborNoError) {
        error = cbor_encoder_close_container(&plain_encoder, &plain_map);
    }
    size_t plain_len = cbor_encoder_get_buffer_size(&plain_encoder, plain);
    uint8_t kvault[VAULT_KEY_BYTES] = {0};
    uint8_t vault_id[VAULT_ID_BYTES] = {0};
    uint8_t credential_hash[VAULT_ID_BYTES] = {0};
    uint8_t blob_keys[2][VAULT_KEY_BYTES] = {0};
    size_t layer_count = picokeys_vault_algorithm_layers(algorithm);
    size_t nonce_len = layer_count * VAULT_BLOB_NONCE_BYTES;
    size_t total_len = VAULT_BLOB_HEADER_LEN + nonce_len + plain_len + layer_count * 16;
    if (error == CborNoError && vault_load_key(kvault) != PICOKEYS_OK) {
        error = CborErrorImproperValue;
    }
    if (error == CborNoError && (picokeys_vault_hash_kvault(kvault, vault_id) != PICOKEYS_OK || mbedtls_sha256(requested_id, requested_id_len, credential_hash, 0) != PICOKEYS_OK)) {
        error = CborErrorImproperValue;
    }
    if (error == CborNoError) {
        for (size_t layer = 0; layer < layer_count; layer++) {
            if (picokeys_vault_layer_key(kvault, vault_id, credential_hash, algorithm, (uint8_t)layer, blob_keys[layer]) != PICOKEYS_OK) {
                error = CborErrorImproperValue;
                break;
            }
        }
    }
    if (error == CborNoError && (total_len > blob_capacity || plain_len == 0)) {
        error = CborErrorOutOfMemory;
    }
    if (error == CborNoError) {
        memcpy(blob, vault_blob_magic, sizeof(vault_blob_magic));
        memcpy(blob + 4, vault_id, VAULT_ID_BYTES);
        memcpy(blob + 4 + VAULT_ID_BYTES, credential_hash, VAULT_ID_BYTES);
        blob[VAULT_BLOB_SERIAL_LEN_OFFSET] = sizeof(pico_serial.id);
        memcpy(blob + VAULT_BLOB_SERIAL_OFFSET, pico_serial.id, sizeof(pico_serial.id));
        blob[VAULT_BLOB_ALGORITHM_OFFSET] = algorithm;
        random_fill_buffer(BYTE_ARRAY(blob + VAULT_BLOB_HEADER_LEN, nonce_len));
        if (layer_count == 1) {
            uint8_t algorithm_layer = picokeys_vault_algorithm_layer(algorithm, 0);
            error = picokeys_vault_encrypt_layer(algorithm_layer, blob_keys[0], blob + VAULT_BLOB_HEADER_LEN, blob, VAULT_BLOB_HEADER_LEN, plain, plain_len, blob + VAULT_BLOB_HEADER_LEN + nonce_len, blob + VAULT_BLOB_HEADER_LEN + nonce_len + plain_len) == PICOKEYS_OK ? CborNoError : CborErrorImproperValue;
        }
        else {
            uint8_t intermediate[VAULT_PLAIN_MAX + 16] = {0};
            uint8_t first_algorithm = picokeys_vault_algorithm_layer(algorithm, 0);
            uint8_t second_algorithm = picokeys_vault_algorithm_layer(algorithm, 1);
            if (picokeys_vault_encrypt_layer(first_algorithm, blob_keys[0], blob + VAULT_BLOB_HEADER_LEN, blob, VAULT_BLOB_HEADER_LEN, plain, plain_len, intermediate, intermediate + plain_len) != PICOKEYS_OK
                || picokeys_vault_encrypt_layer(second_algorithm, blob_keys[1], blob + VAULT_BLOB_HEADER_LEN + VAULT_BLOB_NONCE_BYTES, blob, VAULT_BLOB_HEADER_LEN, intermediate, plain_len + 16, blob + VAULT_BLOB_HEADER_LEN + nonce_len, blob + VAULT_BLOB_HEADER_LEN + nonce_len + plain_len + 16) != PICOKEYS_OK) {
                error = CborErrorImproperValue;
            }
            mbedtls_platform_zeroize(intermediate, sizeof(intermediate));
        }
        *blob_len = total_len;
    }
    mbedtls_platform_zeroize(kvault, sizeof(kvault));
    mbedtls_platform_zeroize(blob_keys, sizeof(blob_keys));
    mbedtls_platform_zeroize(private_key, sizeof(private_key));
    mbedtls_platform_zeroize(plain, sizeof(plain));
    mbedtls_platform_zeroize(embedded_metadata, sizeof(embedded_metadata));
    credential_free(&credential);
    return error == CborNoError ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

int vault_import_blob(const uint8_t *blob, size_t blob_len) {
    if (!blob || blob_len < VAULT_BLOB_HEADER_LEN + VAULT_BLOB_NONCE_BYTES + 16) {
        return PICOKEYS_WRONG_DATA;
    }
    if (memcmp(blob, vault_blob_magic, sizeof(vault_blob_magic)) != 0) {
        return PICOKEYS_WRONG_DATA;
    }
    size_t header_len = VAULT_BLOB_HEADER_LEN;
    uint8_t algorithm = blob[VAULT_BLOB_ALGORITHM_OFFSET];
    if (!picokeys_vault_algorithm_valid(algorithm) || blob[VAULT_BLOB_SERIAL_LEN_OFFSET] > VAULT_BLOB_SERIAL_MAX) {
        return PICOKEYS_WRONG_DATA;
    }
    size_t layer_count = picokeys_vault_algorithm_layers(algorithm);
    size_t nonce_len = layer_count * VAULT_BLOB_NONCE_BYTES;
    if (blob_len < header_len + nonce_len + layer_count * 16) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t kvault[VAULT_KEY_BYTES] = {0};
    uint8_t vault_id[VAULT_ID_BYTES] = {0};
    uint8_t blob_keys[2][VAULT_KEY_BYTES] = {0};
    uint8_t plain[VAULT_PLAIN_MAX] = {0};
    uint8_t intermediate[VAULT_PLAIN_MAX + 16] = {0};
    int ret = vault_load_key(kvault);
    if (ret == PICOKEYS_OK) {
        ret = picokeys_vault_hash_kvault(kvault, vault_id);
    }
    if (ret == PICOKEYS_OK && mbedtls_ct_memcmp(vault_id, blob + 4, VAULT_ID_BYTES) != 0) {
        ret = PICOKEYS_VERIFICATION_FAILED;
    }
    if (ret == PICOKEYS_OK) {
        for (size_t layer = 0; layer < layer_count; layer++) {
            ret = picokeys_vault_layer_key(kvault, vault_id, blob + 4 + VAULT_ID_BYTES, algorithm, (uint8_t)layer, blob_keys[layer]);
            if (ret != PICOKEYS_OK) {
                break;
            }
        }
    }
    size_t encrypted_len = blob_len - header_len - nonce_len;
    size_t plain_len = encrypted_len - layer_count * 16;
    if (ret == PICOKEYS_OK && plain_len > sizeof(plain)) {
        ret = PICOKEYS_WRONG_LENGTH;
    }
    if (ret == PICOKEYS_OK) {
        if (layer_count == 1) {
            uint8_t algorithm_layer = picokeys_vault_algorithm_layer(algorithm, 0);
            ret = picokeys_vault_decrypt_layer(algorithm_layer, blob_keys[0], blob + header_len, blob, header_len, blob + header_len + nonce_len, plain_len, blob + blob_len - 16, plain);
        }
        else {
            uint8_t first_algorithm = picokeys_vault_algorithm_layer(algorithm, 0);
            uint8_t second_algorithm = picokeys_vault_algorithm_layer(algorithm, 1);
            ret = picokeys_vault_decrypt_layer(second_algorithm, blob_keys[1], blob + header_len + VAULT_BLOB_NONCE_BYTES, blob, header_len, blob + header_len + nonce_len, plain_len + 16, blob + blob_len - 16, intermediate);
            if (ret == PICOKEYS_OK) {
                ret = picokeys_vault_decrypt_layer(first_algorithm, blob_keys[0], blob + header_len, blob, header_len, intermediate, plain_len, intermediate + plain_len, plain);
            }
        }
    }
    CborByteString credential_id = {0}, private_key = {0}, metadata = {0}, requested_id = {0};
    CborCharString rp_id = {0};
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    uint64_t version = 0;
    bool version_present = false;
    if (ret == PICOKEYS_OK) {
        CBOR_CHECK(cbor_parser_init(plain, plain_len, 0, &parser, &map));
        uint8_t seen = 0;
        CBOR_PARSE_MAP_START(map, 1)
        {
            uint64_t key = 0;
            CBOR_FIELD_GET_UINT(key, 1);
            if (key >= 1 && key <= 6) {
                uint8_t field = (uint8_t)(1u << (key - 1u));
                if ((seen & field) != 0) {
                    error = CborErrorImproperValue;
                    goto err;
                }
                seen |= field;
            }
            if (key == 0x01) {
                CBOR_FIELD_GET_UINT(version, 1);
                version_present = true;
            }
            else if (key == 0x02) { CBOR_FIELD_GET_BYTES(credential_id, 1); }
            else if (key == 0x03) { CBOR_FIELD_GET_BYTES(private_key, 1); }
            else if (key == 0x04) { CBOR_FIELD_GET_TEXT(rp_id, 1); }
            else if (key == 0x05) { CBOR_FIELD_GET_BYTES(metadata, 1); }
            else if (key == 0x06) { CBOR_FIELD_GET_BYTES(requested_id, 1); }
            else { CBOR_ADVANCE(1); }
        }
        CBOR_PARSE_MAP_END(map, 1);
        if (!cbor_value_at_end(&map) || !version_present || version != 1 || !credential_id.present || credential_id.len == 0 || credential_id.len > MAX_CRED_ID_LENGTH || !private_key.present || private_key.len == 0 || private_key.len > CREDENTIAL_PRIVATE_KEY_MAX || !rp_id.present || rp_id.len == 0 || !metadata.present || metadata.len == 0 || metadata.len > VAULT_CREDENTIAL_METADATA_MAX || !requested_id.present || requested_id.len == 0 || requested_id.len > MAX_CRED_ID_LENGTH) {
            error = CborErrorImproperValue;
        }
    }
    if (ret == PICOKEYS_OK && error == CborNoError) {
        credential_import_record_t record = {
            .credential_id = credential_id.data,
            .credential_id_len = credential_id.len,
            .private_key = private_key.data,
            .private_key_len = private_key.len,
            .rp_id = (const uint8_t *)rp_id.data,
            .rp_id_len = rp_id.len,
            .metadata = metadata.data,
            .metadata_len = metadata.len,
            .requested_id = requested_id.data,
            .requested_id_len = requested_id.len,
            .credential_hash = blob + 4 + VAULT_ID_BYTES
        };
        ret = credential_import(&record);
    }
err:
    CBOR_FREE_BYTE_STRING(credential_id);
    CBOR_FREE_BYTE_STRING(private_key);
    CBOR_FREE_BYTE_STRING(rp_id);
    CBOR_FREE_BYTE_STRING(metadata);
    CBOR_FREE_BYTE_STRING(requested_id);
    mbedtls_platform_zeroize(kvault, sizeof(kvault));
    mbedtls_platform_zeroize(blob_keys, sizeof(blob_keys));
    mbedtls_platform_zeroize(plain, sizeof(plain));
    mbedtls_platform_zeroize(intermediate, sizeof(intermediate));
    if (error != CborNoError) {
        return PICOKEYS_WRONG_DATA;
    }
    return ret == 0 ? PICOKEYS_OK : ret;
}

int vault_encode_credential_metadata(const Credential *credential, const uint8_t rp_id_hash[RP_ID_HASH_LEN], uint8_t *buffer, size_t buffer_len, size_t *metadata_len) {
    if (!credential || !rp_id_hash || !buffer || !metadata_len) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    CborEncoder encoder, mapEncoder, mapEncoder2;
    CborError error = CborNoError;
    cbor_encoder_init(&encoder, buffer, buffer_len, 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, CborIndefiniteLength));
    if (credential->rpId.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, credential->rpId.data, credential->rpId.len));
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, rp_id_hash, RP_ID_HASH_LEN));
    if (credential->userId.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, credential->userId.data, credential->userId.len));
    }
    if (credential->userName.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, credential->userName.data, credential->userName.len));
    }
    if (credential->userDisplayName.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, credential->userDisplayName.data, credential->userDisplayName.len));
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x06));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, credential->board_creation));
    if (credential->extensions.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, CborIndefiniteLength));
        if (credential->extensions.credBlob.present) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credBlob"));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, credential->extensions.credBlob.data, credential->extensions.credBlob.len));
        }
        if (credential->extensions.credProtect != 0) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credProtect"));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder2, credential->extensions.credProtect));
        }
        if (credential->extensions.hmac_secret != NULL) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "hmac-secret"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, *credential->extensions.hmac_secret));
        }
        if (credential->extensions.largeBlobKey == ptrue) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "largeBlobKey"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
        }
        if (credential->extensions.thirdPartyPayment == ptrue) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "thirdPartyPayment"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
    CBOR_CHECK(cbor_encode_boolean(&mapEncoder, credential->use_sign_count == ptrue));
    if (credential->alg != FIDO2_ALG_ES256 || credential->curve != FIDO2_CURVE_P256) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x09));
        CBOR_CHECK(cbor_encode_int(&mapEncoder, credential->alg));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0A));
        CBOR_CHECK(cbor_encode_int(&mapEncoder, credential->curve));
    }
    if (credential->opts.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0B));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, CborIndefiniteLength));
        if (credential->opts.rk != NULL) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "rk"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, credential->opts.rk == ptrue));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    }
    if (credential->rtc_creation != 0) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0C));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, credential->rtc_creation));
    }
    if (credential->residentId.present) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0D));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, credential->residentId.data, credential->residentId.len));
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    *metadata_len = cbor_encoder_get_buffer_size(&encoder, buffer);
    return PICOKEYS_OK;
err:
    return PICOKEYS_ERR_NO_MEMORY;
}

CborError vault_vendor_command(uint64_t vendorCmd, CborByteString vendorParam, CborByteString pinUvAuthParam, uint64_t pinUvAuthProtocol, const uint8_t *raw_vendor_params, size_t raw_vendor_params_len, uint64_t vault_algorithm, bool vault_algorithm_present, CborEncoder encoder, size_t *resp_size, bool *response_handled, int *ctap_error) {
    CborError error = CborNoError;
    CborEncoder mapEncoder;
    bool response_started = false;
    *resp_size = 0;
    *response_handled = false;
    *ctap_error = 0;
#define VAULT_CBOR_ERROR(e) do { *ctap_error = (e); goto err; } while (0)
    if (vendorCmd == 0x01) {
        uint8_t kvault[VAULT_KEY_BYTES] = {0};
        uint8_t vault_id[VAULT_ID_BYTES] = {0};
        bool enrolled = vault_load_key(kvault) == PICOKEYS_OK;
        bool stored = vault_sdk_init() == PICOKEYS_OK && picokeys_vault_wrap_available(VAULT_APP_ID);
        if (enrolled && picokeys_vault_hash_kvault(kvault, vault_id) != PICOKEYS_OK) {
            mbedtls_platform_zeroize(kvault, sizeof(kvault));
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        uint8_t label[VAULT_LABEL_MAX] = { 0 };
        size_t label_len = 0;
        if (enrolled) {
            byte_buffer_t label_output = BYTE_BUFFER(label, sizeof(label));
            picokeys_vault_get_label(&label_output);
            label_len = label_output.len;
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 5));
        response_started = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, vault_id, enrolled ? sizeof(vault_id) : 0));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_boolean(&mapEncoder, picokeys_vault_enrollment_button_ready()));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, board_millis()));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_boolean(&mapEncoder, stored));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, (const char *)label, label_len));
        mbedtls_platform_zeroize(label, sizeof(label));
        mbedtls_platform_zeroize(kvault, sizeof(kvault));
    }
    else if (vendorCmd == 0x02) {
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        if (!picokeys_vault_enrollment_button_ready()) {
            VAULT_CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        picokeys_vault_enrollment_clear();
        uint8_t enrollment_public[VAULT_X448_BYTES] = { 0 };
        uint8_t enrollment_challenge[VAULT_ENROLL_CHALLENGE_BYTES] = { 0 };
        if (picokeys_vault_enrollment_start(enrollment_public, enrollment_challenge) != PICOKEYS_OK) {
            picokeys_vault_enrollment_reset();
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 2));
        response_started = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, enrollment_public, sizeof(enrollment_public)));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, enrollment_challenge, sizeof(enrollment_challenge)));
    }
    else if (vendorCmd == 0x03) {
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        if (!vendorParam.present || vault_enrollment_finish(vendorParam.data, vendorParam.len) != PICOKEYS_OK) {
            VAULT_CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);
        }
        uint8_t kvault[VAULT_KEY_BYTES] = {0};
        uint8_t vault_id[VAULT_ID_BYTES] = {0};
        if (vault_load_key(kvault) != PICOKEYS_OK || picokeys_vault_hash_kvault(kvault, vault_id) != PICOKEYS_OK) {
            mbedtls_platform_zeroize(kvault, sizeof(kvault));
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
        response_started = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, vault_id, sizeof(vault_id)));
        mbedtls_platform_zeroize(kvault, sizeof(kvault));
    }
    else if (vendorCmd == 0x04) {
        if (!vendorParam.present || vendorParam.len == 0) {
            VAULT_CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        uint8_t blob[VAULT_BLOB_MAX] = {0};
        uint8_t metadata[VAULT_CREDENTIAL_METADATA_MAX] = {0};
        size_t blob_len = 0;
        size_t metadata_len = 0;
        uint8_t algorithm = PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY;
        if (vault_algorithm_present) {
            if (vault_algorithm > UINT8_MAX || !picokeys_vault_algorithm_valid((uint8_t)vault_algorithm)) {
                VAULT_CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            algorithm = (uint8_t)vault_algorithm;
        }
        if (vault_export_blob(vendorParam.data, vendorParam.len, algorithm, blob, sizeof(blob), &blob_len, metadata, sizeof(metadata), &metadata_len) != PICOKEYS_OK) {
            VAULT_CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 2));
        response_started = true;
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, blob, blob_len));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, metadata, metadata_len));
        mbedtls_platform_zeroize(blob, sizeof(blob));
        mbedtls_platform_zeroize(metadata, sizeof(metadata));
    }
    else if (vendorCmd == 0x05) {
        if (!vendorParam.present || vendorParam.len == 0) {
            VAULT_CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        if (vault_import_blob(vendorParam.data, vendorParam.len) != PICOKEYS_OK) {
            VAULT_CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);
        }
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 0));
        response_started = true;
    }
    else if (vendorCmd == 0x06) {
        int auth_ret = vault_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
        if (auth_ret != 0) {
            VAULT_CBOR_ERROR(auth_ret);
        }
        int unenroll_ret = vault_sdk_init();
        if (unenroll_ret == PICOKEYS_OK) {
            unenroll_ret = picokeys_vault_delete_kvault(VAULT_APP_ID);
        }
        if (unenroll_ret != PICOKEYS_OK) {
            VAULT_CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        goto err;
    }
    else {
        VAULT_CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
    }
err:
#undef VAULT_CBOR_ERROR
    if (*ctap_error != 0) {
        return CborNoError;
    }
    if (error != CborNoError) {
        return error;
    }
    if (response_started) {
        error = cbor_encoder_close_container(&encoder, &mapEncoder);
        if (error != CborNoError) {
            return error;
        }
        *resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    }
    *response_handled = true;
    return CborNoError;
}
