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
#include "fido.h"
#include "apdu.h"
#include "files.h"
#include "random.h"
#include "version.h"
#include "tlv.h"
#include "crypto_utils.h"
#include "management.h"
#include "oath_container.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include <stdlib.h>

#define MAX_OATH_CRED   255
#define CHALLENGE_LEN   8
#define MAX_OTP_COUNTER 3
#define OTP_PIN_FORMAT_V1 1
#define OTP_PIN_LEGACY_SIZE 33
#define OTP_PIN_V1_SIZE 34
#define OTP_PIN_RETRY_COMMIT_TIMEOUT_MS 500
#define OATH_ACCESS_CODE_MAX_LEN 65
#define OATH_CRED_BITMAP_SIZE ((MAX_OATH_CRED + 7) / 8)
#define OATH_SECURE_KEY_VERSION 1
#define OATH_SECURE_KEY_OVERHEAD (sizeof(oath_secure_key_magic) + 1 + 12 + 16)

#define TAG_NAME            0x71
#define TAG_NAME_LIST       0x72
#define TAG_KEY             0x73
#define TAG_CHALLENGE       0x74
#define TAG_RESPONSE        0x75
#define TAG_T_RESPONSE      0x76
#define TAG_NO_RESPONSE     0x77
#define TAG_PROPERTY        0x78
#define TAG_T_VERSION       0x79
#define TAG_IMF             0x7a
#define TAG_ALGO            0x7b
#define TAG_TOUCH_RESPONSE  0x7c
#define TAG_PASSWORD        0x80
#define TAG_NEW_PASSWORD    0x81
#define TAG_PIN_COUNTER     0x82
#define TAG_PWS_LOGIN       0x83
#define TAG_PWS_PASSWORD    0x84
#define TAG_PWS_METADATA    0x85
#define TAG_SERIAL_NUMBER   0x8F

#define ALG_HMAC_SHA1       0x01
#define ALG_HMAC_SHA256     0x02
#define ALG_HMAC_SHA512     0x03
#define ALG_MASK            0x0f

#define OATH_TYPE_HOTP      0x10
#define OATH_TYPE_TOTP      0x20
#define OATH_TYPE_MASK      0xf0

#define PROP_INC            0x01
#define PROP_TOUCH          0x02
#define PROP_PIN            0x03

static int oath_process_apdu(void);
static int oath_unload(void);
static int oath_migrate_secrets(void);

static bool validated = true;
static bool otp_pin_verified = false;
static bool oath_migration_done = false;
static uint8_t challenge[CHALLENGE_LEN] = { 0 };
static const uint8_t oath_secure_key_magic[] = { 'O', 'A', 'T', 'H' };

static bool oath_response_has_room(size_t len) {
    return res_APDU_size <= USB_BUFFER_SIZE && len <= (size_t)(USB_BUFFER_SIZE - res_APDU_size);
}

static bool oath_response_append(uint8_t tag, const uint8_t *data, size_t len) {
    if (len > UINT8_MAX || !oath_response_has_room(len + 2)) {
        return false;
    }
    res_APDU[res_APDU_size++] = tag;
    res_APDU[res_APDU_size++] = (uint8_t)len;
    memcpy(res_APDU + res_APDU_size, data, len);
    res_APDU_size += (uint16_t)len;
    return true;
}

typedef struct {
    uint16_t *fids;
    size_t len;
    size_t cap;
} oath_cred_list_t;

typedef struct {
    const uint8_t *data;
    uint8_t *allocated;
    uint16_t size;
} oath_credential_data_t;

typedef struct {
    int ret;
    bool changed;
} oath_migration_ctx_t;

const uint8_t oath_aid[] = {
    7,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01
};

static int oath_select(app_t *a, uint8_t force) {
    (void) force;
    if (cap_supported(CAP_OATH)) {
        validated = !file_has_data(file_search(EF_OATH_CODE)) && !file_has_data(file_search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF));
        otp_pin_verified = false;
        int migration_ret = oath_migrate_secrets();
        if (migration_ret != PICOKEYS_OK) {
            return migration_ret;
        }
        a->process_apdu = oath_process_apdu;
        a->unload = oath_unload;
        res_APDU_size = 0;
        res_APDU[res_APDU_size++] = TAG_T_VERSION;
        res_APDU[res_APDU_size++] = 3;
        res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MAJOR;
        res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MINOR;
        res_APDU[res_APDU_size++] = 0;
        res_APDU[res_APDU_size++] = TAG_NAME;
        res_APDU[res_APDU_size++] = 8;
        memcpy(res_APDU + res_APDU_size, pico_serial_str, 8); res_APDU_size += 8;
        if (file_has_data(file_search(EF_OATH_CODE)) == true) {
            random_fill_buffer(BYTE_ARRAY(challenge, sizeof(challenge)));
            res_APDU[res_APDU_size++] = TAG_CHALLENGE;
            res_APDU[res_APDU_size++] = sizeof(challenge);
            memcpy(res_APDU + res_APDU_size, challenge, sizeof(challenge));
            res_APDU_size += sizeof(challenge);
            res_APDU[res_APDU_size++] = TAG_ALGO;
            res_APDU[res_APDU_size++] = 1;
            res_APDU[res_APDU_size++] = ALG_HMAC_SHA1;
        }
        if (is_nk) {
            res_APDU[res_APDU_size++] = TAG_SERIAL_NUMBER;
            res_APDU[res_APDU_size++] = 8;
            memcpy(res_APDU + res_APDU_size, pico_serial_str, 8);
            res_APDU_size += 8;
            file_t *ef_otp_pin = file_search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
            if (file_has_data(ef_otp_pin)) {
                const uint8_t *pin_data = file_get_data(ef_otp_pin);
                res_APDU[res_APDU_size++] = TAG_PIN_COUNTER;
                res_APDU[res_APDU_size++] = 1;
                res_APDU[res_APDU_size++] = *pin_data;
            }
        }
        apdu.ne = res_APDU_size;
        return PICOKEYS_OK;
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}

INITIALIZER ( oath_ctor ) {
    register_app(oath_select, oath_aid);
}

static int oath_unload(void) {
    validated = false;
    otp_pin_verified = false;
    return PICOKEYS_OK;
}

static int oath_require_otp_pin(void) {
    if (file_has_data(file_search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF)) && !otp_pin_verified) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    return SW_OK();
}

static bool oath_key_is_secure(const uint8_t *data, size_t len) {
    return data != NULL && len > OATH_SECURE_KEY_OVERHEAD && memcmp(data, oath_secure_key_magic, sizeof(oath_secure_key_magic)) == 0 && data[sizeof(oath_secure_key_magic)] == OATH_SECURE_KEY_VERSION;
}

static int oath_derive_key(uint8_t key[32]) {
    uint8_t kbase[32];
    derive_kbase(kbase);
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), pico_serial_hash, sizeof(pico_serial_hash), kbase, sizeof(kbase), (const uint8_t *)"OATH/KEYS", 9, key, 32);
    mbedtls_platform_zeroize(kbase, sizeof(kbase));
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static int oath_encrypt_key(const uint8_t *plain, size_t plain_len, uint8_t **encrypted, uint16_t *encrypted_len) {
    if (plain == NULL || encrypted == NULL || encrypted_len == NULL) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    size_t out_len = OATH_SECURE_KEY_OVERHEAD + plain_len;
    if (out_len > UINT16_MAX) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t *out = (uint8_t *)calloc(1, out_len);
    if (out == NULL) {
        return PICOKEYS_EXEC_ERROR;
    }
    memcpy(out, oath_secure_key_magic, sizeof(oath_secure_key_magic));
    out[sizeof(oath_secure_key_magic)] = OATH_SECURE_KEY_VERSION;

    uint8_t oath_key[32];
    int ret = oath_derive_key(oath_key);
    if (ret == PICOKEYS_OK) {
        ret = encrypt_with_aad(oath_key, CONST_BYTE_ARRAY(plain, plain_len), PIN_KDF_V2, out + sizeof(oath_secure_key_magic) + 1);
    }
    mbedtls_platform_zeroize(oath_key, sizeof(oath_key));
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(out, out_len);
        free(out);
        return ret;
    }
    *encrypted = out;
    *encrypted_len = (uint16_t)out_len;
    return PICOKEYS_OK;
}

static int oath_decrypt_key(const uint8_t *stored, size_t stored_len, uint8_t **decrypted, uint16_t *decrypted_len) {
    if (stored == NULL || decrypted == NULL || decrypted_len == NULL) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (stored_len > UINT16_MAX) {
        return PICOKEYS_WRONG_DATA;
    }
    if (!oath_key_is_secure(stored, stored_len)) {
        uint8_t *copy = (uint8_t *)calloc(1, stored_len);
        if (copy == NULL) {
            return PICOKEYS_EXEC_ERROR;
        }
        memcpy(copy, stored, stored_len);
        *decrypted = copy;
        *decrypted_len = (uint16_t)stored_len;
        return PICOKEYS_OK;
    }

    size_t out_len = stored_len - OATH_SECURE_KEY_OVERHEAD;
    if (out_len > UINT16_MAX) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t *out = (uint8_t *)calloc(1, out_len);
    if (out == NULL) {
        return PICOKEYS_EXEC_ERROR;
    }
    uint8_t oath_key[32];
    int ret = oath_derive_key(oath_key);
    if (ret == PICOKEYS_OK) {
        ret = decrypt_with_aad(oath_key, CONST_BYTE_ARRAY(stored + sizeof(oath_secure_key_magic) + 1, stored_len - sizeof(oath_secure_key_magic) - 1), PIN_KDF_V2, out);
    }
    mbedtls_platform_zeroize(oath_key, sizeof(oath_key));
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(out, out_len);
        free(out);
        return ret;
    }
    *decrypted = out;
    *decrypted_len = (uint16_t)out_len;
    return PICOKEYS_OK;
}

static uint8_t *tlv_append(uint8_t *out, uint16_t tag, const uint8_t *data, uint16_t len) {
    if (tag > 0xff) {
        *out++ = (uint8_t)(tag >> 8);
    }
    *out++ = (uint8_t)tag;
    out += tlv_format_len(len, out);
    if (len > 0) {
        memcpy(out, data, len);
    }
    return out + len;
}

static int oath_put_credential_data(file_t *ef, const uint8_t *data, size_t len) {
    tlv_ctx_t ctxi;
    tlv_ctx_init(BYTE_ARRAY((uint8_t *)data, len), &ctxi);
    tlv_ctx_t key = { 0 };
    if (tlv_find_tag(&ctxi, TAG_KEY, &key) == false || oath_key_is_secure(key.data, key.len)) {
        return file_put_data(ef, CONST_BYTE_ARRAY(data, len));
    }

    uint8_t *encrypted = NULL;
    uint16_t encrypted_len = 0;
    int ret = oath_encrypt_key(key.data, key.len, &encrypted, &encrypted_len);
    if (ret != PICOKEYS_OK) {
        return ret;
    }

    size_t out_len = 0;
    uint8_t *p = NULL;
    tlv_item_t item;
    while (tlv_walk(&ctxi, &p, &item)) {
        uint16_t value_len = item.tag == TAG_KEY ? encrypted_len : (uint16_t)item.value.len;
        out_len += tlv_len_tag(item.tag, value_len);
    }
    uint8_t *out = (uint8_t *)calloc(1, out_len);
    if (out == NULL) {
        mbedtls_platform_zeroize(encrypted, encrypted_len);
        free(encrypted);
        return PICOKEYS_EXEC_ERROR;
    }
    p = NULL;
    uint8_t *op = out;
    while (tlv_walk(&ctxi, &p, &item)) {
        if (item.tag == TAG_KEY) {
            op = tlv_append(op, item.tag, encrypted, encrypted_len);
        }
        else {
            op = tlv_append(op, item.tag, item.value.data, (uint16_t)item.value.len);
        }
    }

    ret = file_put_data(ef, CONST_BYTE_ARRAY(out, out_len));
    mbedtls_platform_zeroize(encrypted, encrypted_len);
    mbedtls_platform_zeroize(out, out_len);
    free(encrypted);
    free(out);
    return ret;
}

static int oath_put_code_key(file_t *ef, const uint8_t *key, size_t key_len) {
    if (oath_key_is_secure(key, key_len)) {
        return file_put_data(ef, CONST_BYTE_ARRAY(key, key_len));
    }
    uint8_t *encrypted = NULL;
    uint16_t encrypted_len = 0;
    int ret = oath_encrypt_key(key, key_len, &encrypted, &encrypted_len);
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    ret = file_put_data(ef, CONST_BYTE_ARRAY(encrypted, encrypted_len));
    mbedtls_platform_zeroize(encrypted, encrypted_len);
    free(encrypted);
    return ret;
}

static int oath_migrate_credential(file_t *ef, bool *changed) {
    if (!file_has_data(ef) || oath_container_is_marker(ef)) {
        return PICOKEYS_OK;
    }
    tlv_ctx_t ctxi, key = { 0 };
    tlv_ctx_init(BYTE_ARRAY(file_get_data(ef), file_get_size(ef)), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_KEY, &key) == false || oath_key_is_secure(key.data, key.len)) {
        return PICOKEYS_OK;
    }
    int ret = oath_put_credential_data(ef, file_get_data(ef), file_get_size(ef));
    if (ret == PICOKEYS_OK && changed != NULL) {
        *changed = true;
    }
    return ret;
}

static bool oath_migrate_cred_cb(file_t *file, void *ctx) {
    if (file->fid < EF_OATH_CRED || file->fid >= EF_OATH_CRED + MAX_OATH_CRED) {
        return true;
    }
    oath_migration_ctx_t *migration = (oath_migration_ctx_t *)ctx;
    bool changed = false;
    migration->ret = oath_migrate_credential(file, &changed);
    if (migration->ret == PICOKEYS_OK && changed) {
        migration->changed = true;
    }
    return migration->ret == PICOKEYS_OK;
}

static int oath_migrate_secrets(void) {
    if (oath_migration_done) {
        return PICOKEYS_OK;
    }

    oath_migration_ctx_t migration = { .ret = PICOKEYS_OK, .changed = false };
    file_for_each_dynamic(oath_migrate_cred_cb, &migration);
    bool changed = migration.changed;
    if (migration.ret != PICOKEYS_OK) {
        return migration.ret;
    }

    file_t *ef_code = file_search(EF_OATH_CODE);
    if (file_has_data(ef_code) && !oath_key_is_secure(file_get_data(ef_code), file_get_size(ef_code))) {
        int ret = oath_put_code_key(ef_code, file_get_data(ef_code), file_get_size(ef_code));
        if (ret != PICOKEYS_OK) {
            return ret;
        }
        changed = true;
    }

    if (changed) {
        flash_commit();
    }
    oath_migration_done = true;
    return PICOKEYS_OK;
}

static int cmp_u16(const void *a, const void *b) {
    const uint16_t fa = *(const uint16_t *)a;
    const uint16_t fb = *(const uint16_t *)b;
    return (fa > fb) - (fa < fb);
}

static bool collect_oath_cred(file_t *file, void *ctx) {
    oath_cred_list_t *list = (oath_cred_list_t *)ctx;
    if (file->fid < EF_OATH_CRED || file->fid >= EF_OATH_CRED + MAX_OATH_CRED || list->len >= list->cap) {
        return true;
    }
    list->fids[list->len] = file->fid;
    list->len++;
    return true;
}

static size_t present_oath_cred_fids(uint16_t *fids, size_t cap) {
    oath_cred_list_t list = {
        .fids = fids,
        .len = 0,
        .cap = cap
    };
    file_for_each_dynamic(collect_oath_cred, &list);
    qsort(fids, list.len, sizeof(fids[0]), cmp_u16);
    return list.len;
}

static uint8_t oath_credential_slot(uint16_t fid) {
    return (uint8_t)(fid - EF_OATH_CRED);
}

static int oath_credential_open(uint16_t fid, uint16_t object_type, oath_credential_data_t *credential) {
    if (!credential || fid < EF_OATH_CRED || fid >= EF_OATH_CRED + MAX_OATH_CRED) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    memset(credential, 0, sizeof(*credential));
    file_t *file = file_search(fid);
    if (!file_has_data(file)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (!oath_container_is_marker(file)) {
        uint32_t file_size = file_get_size(file);
        if (file_size > UINT16_MAX) {
            return PICOKEYS_WRONG_LENGTH;
        }
        credential->data = file_get_data(file);
        credential->size = (uint16_t)file_size;
        return PICOKEYS_OK;
    }

    uint32_t object_size = 0;
    uint8_t slot = oath_credential_slot(fid);
    int ret = oath_container_object_size(slot, object_type, &object_size);
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    if (object_size == 0 || object_size > UINT16_MAX) {
        return PICOKEYS_WRONG_LENGTH;
    }
    credential->allocated = (uint8_t *)calloc(1, object_size);
    if (!credential->allocated) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    byte_buffer_t output = BYTE_BUFFER(credential->allocated, object_size);
    ret = oath_container_read(slot, object_type, &output);
    if (ret != PICOKEYS_OK || output.len != object_size) {
        mbedtls_platform_zeroize(credential->allocated, object_size);
        free(credential->allocated);
        memset(credential, 0, sizeof(*credential));
        return ret == PICOKEYS_OK ? PICOKEYS_WRONG_LENGTH : ret;
    }
    credential->data = credential->allocated;
    credential->size = (uint16_t)object_size;
    return PICOKEYS_OK;
}

static void oath_credential_close(oath_credential_data_t *credential) {
    if (!credential) {
        return;
    }
    if (credential->allocated) {
        mbedtls_platform_zeroize(credential->allocated, credential->size);
        free(credential->allocated);
    }
    memset(credential, 0, sizeof(*credential));
}

static int oath_credential_metadata(const uint8_t *data, uint16_t data_size, uint8_t **metadata, uint16_t *metadata_size) {
    if (!data || !metadata || !metadata_size) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    tlv_ctx_t input;
    tlv_ctx_t name = { 0 };
    tlv_ctx_t key = { 0 };
    tlv_ctx_t property = { 0 };
    tlv_ctx_t password = { 0 };
    tlv_ctx_init(BYTE_ARRAY((uint8_t *)data, data_size), &input);
    if (!tlv_find_tag(&input, TAG_NAME, &name) || !tlv_find_tag(&input, TAG_KEY, &key) || key.len < 2) {
        return PICOKEYS_WRONG_DATA;
    }

    size_t size = tlv_len_tag(TAG_NAME, (uint16_t)name.len) + tlv_len_tag(TAG_KEY, 2);
    bool has_property = tlv_find_tag(&input, TAG_PROPERTY, &property);
    if (has_property) {
        size += tlv_len_tag(TAG_PROPERTY, (uint16_t)property.len);
    }
    bool has_password_safe = tlv_find_tag(&input, TAG_PWS_LOGIN, &password) || tlv_find_tag(&input, TAG_PWS_PASSWORD, &password) || tlv_find_tag(&input, TAG_PWS_METADATA, &password);
    if (has_password_safe) {
        size += tlv_len_tag(TAG_PWS_METADATA, 0);
    }
    if (size > UINT16_MAX) {
        return PICOKEYS_WRONG_LENGTH;
    }

    uint8_t *out = (uint8_t *)calloc(1, size);
    if (!out) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    uint8_t *position = out;
    position = tlv_append(position, TAG_NAME, name.data, (uint16_t)name.len);
    position = tlv_append(position, TAG_KEY, key.data, 2);
    if (has_property) {
        position = tlv_append(position, TAG_PROPERTY, property.data, (uint16_t)property.len);
    }
    if (has_password_safe) {
        position = tlv_append(position, TAG_PWS_METADATA, NULL, 0);
    }
    *metadata = out;
    *metadata_size = (uint16_t)(position - out);
    return PICOKEYS_OK;
}

static int oath_credential_write(uint16_t fid, const uint8_t *data, uint16_t data_size) {
    if (!data || fid < EF_OATH_CRED || fid >= EF_OATH_CRED + MAX_OATH_CRED) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_t *file = file_search(fid);
    if (file_has_data(file) && !oath_container_is_marker(file)) {
        int ret = oath_put_credential_data(file, data, data_size);
        if (ret == PICOKEYS_OK) {
            flash_commit();
        }
        return ret;
    }

    uint8_t *metadata = NULL;
    uint16_t metadata_size = 0;
    int ret = oath_credential_metadata(data, data_size, &metadata, &metadata_size);
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    if (oath_container_is_marker(file)) {
        ret = oath_container_update(oath_credential_slot(fid), data, data_size, metadata, metadata_size);
    }
    else if (oath_container_can_create(oath_credential_slot(fid))) {
        ret = oath_container_create(oath_credential_slot(fid), data, data_size, metadata, metadata_size);
    }
    else {
        ret = PICOKEYS_WRONG_DATA;
    }
    mbedtls_platform_zeroize(metadata, metadata_size);
    free(metadata);
    return ret;
}

static int oath_credential_delete(uint16_t fid) {
    file_t *file = file_search(fid);
    if (!file_has_data(file)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (oath_container_is_marker(file)) {
        return oath_container_delete(oath_credential_slot(fid));
    }
    return file_delete(file);
}

static bool find_oath_cred(const uint8_t *name, size_t name_len, uint16_t *fid) {
    if ((!name && name_len > 0) || !fid) {
        return false;
    }
    uint16_t fids[MAX_OATH_CRED];
    size_t num_creds = present_oath_cred_fids(fids, MAX_OATH_CRED);
    for (size_t i = 0; i < num_creds; i++) {
        oath_credential_data_t credential;
        if (oath_credential_open(fids[i], FIDO_OATH_OBJECT_METADATA, &credential) != PICOKEYS_OK) {
            continue;
        }
        tlv_ctx_t ctxi, ef_tag = { 0 };
        tlv_ctx_init(BYTE_ARRAY((uint8_t *)credential.data, credential.size), &ctxi);
        bool matches = tlv_find_tag(&ctxi, TAG_NAME, &ef_tag) && ef_tag.len == name_len && memcmp(ef_tag.data, name, name_len) == 0;
        oath_credential_close(&credential);
        if (matches) {
            *fid = fids[i];
            return true;
        }
    }
    return false;
}

static int cmd_put(void) {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    tlv_ctx_t ctxi, key = { 0 }, name = { 0 }, imf = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_KEY, &key) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (key.len < 2) {
        return SW_WRONG_DATA();
    }
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_INCORRECT_PARAMS();
    }
    uint8_t *put_data = apdu.data;
    size_t put_len = apdu.nc;
    uint8_t *put_copy = NULL;
    if ((key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
        if (apdu.nc > UINT16_MAX - 10) {
            return SW_WRONG_LENGTH();
        }
        put_copy = calloc(1, apdu.nc + 10);
        if (put_copy == NULL) {
            return SW_EXEC_ERROR();
        }
        memcpy(put_copy, apdu.data, apdu.nc);
        put_data = put_copy;
        tlv_ctx_init(BYTE_ARRAY(put_data, put_len), &ctxi);
        if (tlv_find_tag(&ctxi, TAG_IMF, &imf) == false) {
            memcpy(put_data + put_len, "\x7a\x08\x00\x00\x00\x00\x00\x00\x00\x00", 10);
            put_len += 10;
        }
        else { //prepend zero-valued bytes
            if (imf.len < 8) {
                size_t extra = 8 - imf.len;
                size_t value_offset = (size_t)(imf.data - put_data);
                memmove(put_data + value_offset + extra, put_data + value_offset, put_len - value_offset);
                memset(put_data + value_offset, 0, extra);
                *(imf.data - 1) = 8;
                put_len += extra;
            }
        }
    }
    uint16_t fid = 0;
    if (find_oath_cred(name.data, name.len, &fid)) {
        int ret = oath_credential_write(fid, put_data, (uint16_t)put_len);
        if (put_copy != NULL) {
            mbedtls_platform_zeroize(put_copy, put_len);
        }
        free(put_copy);
        if (ret != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else {
        uint16_t fids[MAX_OATH_CRED];
        uint8_t used[OATH_CRED_BITMAP_SIZE] = { 0 };
        size_t num_creds = present_oath_cred_fids(fids, MAX_OATH_CRED);
        for (size_t j = 0; j < num_creds; j++) {
            uint16_t slot = (uint16_t)(fids[j] - EF_OATH_CRED);
            used[slot / 8] |= (uint8_t)(1u << (slot % 8));
        }
        for (int i = 0; i < MAX_OATH_CRED; i++) {
            if ((used[i / 8] & (1u << (i % 8))) == 0) {
                int ret = oath_credential_write((uint16_t)(EF_OATH_CRED + i), put_data, (uint16_t)put_len);
                if (put_copy != NULL) {
                    mbedtls_platform_zeroize(put_copy, put_len);
                }
                free(put_copy);
                if (ret != PICOKEYS_OK) {
                    return SW_EXEC_ERROR();
                }
                return SW_OK();
            }
        }
        if (put_copy != NULL) {
            mbedtls_platform_zeroize(put_copy, put_len);
        }
        free(put_copy);
        return SW_FILE_FULL();
    }
    return SW_OK();
}


static int cmd_delete(void) {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    tlv_ctx_t ctxi, ctxo = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_NAME, &ctxo) == true) {
        uint16_t fid = 0;
        if (find_oath_cred(ctxo.data, ctxo.len, &fid)) {
            return oath_credential_delete(fid) == PICOKEYS_OK ? SW_OK() : SW_EXEC_ERROR();
        }
        return SW_DATA_INVALID();
    }
    return SW_INCORRECT_PARAMS();
}

static const mbedtls_md_info_t *get_oath_md_info(uint8_t alg) {
    if ((alg & ALG_MASK) == ALG_HMAC_SHA1) {
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    }
    else if ((alg & ALG_MASK) == ALG_HMAC_SHA256) {
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    }
    else if ((alg & ALG_MASK) == ALG_HMAC_SHA512) {
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    }
    return NULL;
}

static int cmd_set_code(void) {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.nc == 0) {
        file_delete(file_search(EF_OATH_CODE));
        validated = true;
        return SW_OK();
    }
    tlv_ctx_t ctxi, key = { 0 }, chal = { 0 }, resp = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_KEY, &key) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (key.len == 1 || key.len > OATH_ACCESS_CODE_MAX_LEN) {
        return SW_WRONG_DATA();
    }
    if (key.len == 0) {
        file_delete(file_search(EF_OATH_CODE));
        validated = true;
        return SW_OK();
    }
    if (tlv_find_tag(&ctxi, TAG_CHALLENGE, &chal) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (tlv_find_tag(&ctxi, TAG_RESPONSE, &resp) == false) {
        return SW_INCORRECT_PARAMS();
    }

    const mbedtls_md_info_t *md_info = get_oath_md_info(key.data[0]);
    if (md_info == NULL) {
        return SW_INCORRECT_PARAMS();
    }
    uint8_t hmac[64];
    int r = mbedtls_md_hmac(md_info, key.data + 1, key.len - 1, chal.data, chal.len, hmac);
    if (r != 0) {
        return SW_EXEC_ERROR();
    }
    if (resp.len != mbedtls_md_get_size(md_info)) {
        return SW_DATA_INVALID();
    }
    if (mbedtls_ct_memcmp(hmac, resp.data, resp.len) != 0) {
        return SW_DATA_INVALID();
    }
    random_fill_buffer(BYTE_ARRAY(challenge, sizeof(challenge)));
    file_t *ef = file_new(EF_OATH_CODE);
    if (oath_put_code_key(ef, key.data, key.len) != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    flash_commit();
    validated = false;
    return SW_OK();
}

static int cmd_reset(void) {
    if (P1(apdu) != 0xde || P2(apdu) != 0xad) {
        return SW_INCORRECT_P1P2();
    }
    uint16_t fids[MAX_OATH_CRED];
    size_t num_creds = present_oath_cred_fids(fids, MAX_OATH_CRED);
    for (size_t i = 0; i < num_creds; i++) {
        file_t *ef = file_search(fids[i]);
        if (oath_container_is_marker(ef)) {
            if (oath_container_purge(oath_credential_slot(fids[i])) != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }
        }
        else if (file_has_data(ef)) {
            file_delete_no_commit(ef);
        }
    }
    file_delete_no_commit(file_search(EF_OATH_CODE));
    flash_clear_file(file_search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF));
    flash_commit();
    validated = true;
    otp_pin_verified = false;
    return SW_OK();
}

static int cmd_list(void) {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    bool ext = (apdu.nc == 1 && apdu.data[0] == 0x01);
    uint16_t fids[MAX_OATH_CRED];
    size_t num_creds = present_oath_cred_fids(fids, MAX_OATH_CRED);
    for (size_t i = 0; i < num_creds; i++) {
        oath_credential_data_t credential;
        if (oath_credential_open(fids[i], FIDO_OATH_OBJECT_METADATA, &credential) == PICOKEYS_OK) {
            tlv_ctx_t ctxi, key = { 0 }, name = { 0 }, pws = { 0 };
            tlv_ctx_init(BYTE_ARRAY((uint8_t *)credential.data, credential.size), &ctxi);
            if (tlv_find_tag(&ctxi, TAG_NAME, &name) == true && tlv_find_tag(&ctxi, TAG_KEY, &key) == true) {
                uint8_t *plain_key = NULL;
                uint16_t plain_key_len = 0;
                if (oath_decrypt_key(key.data, key.len, &plain_key, &plain_key_len) != PICOKEYS_OK || plain_key_len < 2) {
                    if (plain_key != NULL) {
                        mbedtls_platform_zeroize(plain_key, plain_key_len);
                        free(plain_key);
                    }
                    oath_credential_close(&credential);
                    continue;
                }
                size_t name_overhead = 1u + (ext ? 1u : 0u);
                if (name.len > (size_t)UINT8_MAX - name_overhead ||
                    !oath_response_has_room(3 + name.len + (ext ? 1 : 0))) {
                    mbedtls_platform_zeroize(plain_key, plain_key_len);
                    free(plain_key);
                    oath_credential_close(&credential);
                    return SW_WRONG_LENGTH();
                }
                res_APDU[res_APDU_size++] = TAG_NAME_LIST;
                res_APDU[res_APDU_size++] = (uint8_t)(name.len + 1 + (ext ? 1 : 0));
                res_APDU[res_APDU_size++] = plain_key[0];
                memcpy(res_APDU + res_APDU_size, name.data, name.len);
                res_APDU_size += (uint16_t)name.len;
                if (ext) {
                    uint8_t props = 0x0;
                    if (tlv_find_tag(&ctxi, TAG_PWS_LOGIN, &pws) == true || tlv_find_tag(&ctxi, TAG_PWS_PASSWORD, &pws) == true || tlv_find_tag(&ctxi, TAG_PWS_METADATA, &pws) == true) {
                        props |= 0x4;
                    }
                    if (tlv_find_tag(&ctxi, TAG_PROPERTY, &pws) == true && pws.len > 0 && (pws.data[0] & PROP_TOUCH)) {
                        props |= 0x1;
                    }
                    res_APDU[res_APDU_size++] = props;
                }
                mbedtls_platform_zeroize(plain_key, plain_key_len);
                free(plain_key);
            }
            oath_credential_close(&credential);
        }
    }
    apdu.ne = res_APDU_size;
    return SW_OK();
}

static int cmd_validate(void) {
    tlv_ctx_t ctxi, key = { 0 }, chal = { 0 }, resp = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_CHALLENGE, &chal) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (tlv_find_tag(&ctxi, TAG_RESPONSE, &resp) == false) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *ef = file_search(EF_OATH_CODE);
    if (file_has_data(ef) == false) {
        validated = true;
        return SW_DATA_INVALID();
    }
    uint8_t *plain_key = NULL;
    uint16_t plain_key_len = 0;
    if (oath_decrypt_key(file_get_data(ef), file_get_size(ef), &plain_key, &plain_key_len) != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    key.data = plain_key;
    key.len = plain_key_len;
    if (plain_key_len < 2 || plain_key_len > OATH_ACCESS_CODE_MAX_LEN) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        return SW_WRONG_DATA();
    }
    const mbedtls_md_info_t *md_info = get_oath_md_info(key.data[0]);
    if (md_info == NULL) {
        mbedtls_platform_zeroize(key.data, key.len);
        free(key.data);
        return SW_INCORRECT_PARAMS();
    }
    uint8_t hmac[64];
    int ret = mbedtls_md_hmac(md_info, key.data + 1, key.len - 1, challenge, sizeof(challenge), hmac);
    if (ret != 0) {
        mbedtls_platform_zeroize(key.data, key.len);
        free(key.data);
        return SW_EXEC_ERROR();
    }
    if (resp.len != mbedtls_md_get_size(md_info)) {
        mbedtls_platform_zeroize(key.data, key.len);
        free(key.data);
        return SW_DATA_INVALID();
    }
    if (mbedtls_ct_memcmp(hmac, resp.data, resp.len) != 0) {
        mbedtls_platform_zeroize(key.data, key.len);
        free(key.data);
        return SW_DATA_INVALID();
    }
    ret = mbedtls_md_hmac(md_info, key.data + 1, key.len - 1, chal.data, chal.len, hmac);
    if (ret != 0) {
        mbedtls_platform_zeroize(key.data, key.len);
        free(key.data);
        return SW_EXEC_ERROR();
    }
    mbedtls_platform_zeroize(key.data, key.len);
    free(key.data);
    validated = true;
    res_APDU[res_APDU_size++] = TAG_RESPONSE;
    res_APDU[res_APDU_size++] = mbedtls_md_get_size(md_info);
    memcpy(res_APDU + res_APDU_size, hmac, mbedtls_md_get_size(md_info));
    res_APDU_size += mbedtls_md_get_size(md_info);
    apdu.ne = res_APDU_size;
    return SW_OK();
}

int calculate_oath(uint8_t truncate, const uint8_t *key, size_t key_len, const uint8_t *chal, size_t chal_len) {
    if (key == NULL || key_len < 2) {
        return PICOKEYS_WRONG_DATA;
    }
    const mbedtls_md_info_t *md_info = get_oath_md_info(key[0]);
    if (md_info == NULL) {
        return SW_INCORRECT_PARAMS();
    }
    uint8_t hmac[64];
    int r = mbedtls_md_hmac(md_info, key + 2, key_len - 2, chal, chal_len, hmac);
    size_t hmac_size = mbedtls_md_get_size(md_info);
    if (r != 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    if (truncate == 0x01) {
        if (!oath_response_has_room(7)) {
            return PICOKEYS_WRONG_LENGTH;
        }
        res_APDU[res_APDU_size++] = 4 + 1;
        res_APDU[res_APDU_size++] = key[1];
        uint8_t offset = hmac[hmac_size - 1] & 0x0f;
        res_APDU[res_APDU_size++] = hmac[offset] & 0x7f;
        res_APDU[res_APDU_size++] = hmac[offset + 1];
        res_APDU[res_APDU_size++] = hmac[offset + 2];
        res_APDU[res_APDU_size++] = hmac[offset + 3];
    }
    else {
        if (!oath_response_has_room(hmac_size + 2)) {
            return PICOKEYS_WRONG_LENGTH;
        }
        res_APDU[res_APDU_size++] = (uint8_t)(hmac_size + 1);
        res_APDU[res_APDU_size++] = key[1];
        memcpy(res_APDU + res_APDU_size, hmac, hmac_size); res_APDU_size += (uint16_t)hmac_size;
    }
    apdu.ne = res_APDU_size;
    return PICOKEYS_OK;
}

static int cmd_calculate(void) {
    if (P2(apdu) != 0x0 && P2(apdu) != 0x1) {
        return SW_INCORRECT_P1P2();
    }
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    tlv_ctx_t ctxi, key = { 0 }, chal = { 0 }, name = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_CHALLENGE, &chal) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_INCORRECT_PARAMS();
    }
    uint16_t fid = 0;
    if (!find_oath_cred(name.data, name.len, &fid)) {
        return SW_DATA_INVALID();
    }
    oath_credential_data_t credential;
    if (oath_credential_open(fid, FIDO_OATH_OBJECT_CREDENTIAL, &credential) != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    tlv_ctx_t ctxe;
    tlv_ctx_init(BYTE_ARRAY((uint8_t *)credential.data, credential.size), &ctxe);
    if (tlv_find_tag(&ctxe, TAG_KEY, &key) == false) {
        oath_credential_close(&credential);
        return SW_INCORRECT_PARAMS();
    }
    uint8_t *plain_key = NULL;
    uint16_t plain_key_len = 0;
    if (oath_decrypt_key(key.data, key.len, &plain_key, &plain_key_len) != PICOKEYS_OK || plain_key_len < 2) {
        if (plain_key != NULL) {
            mbedtls_platform_zeroize(plain_key, plain_key_len);
            free(plain_key);
        }
        oath_credential_close(&credential);
        return SW_EXEC_ERROR();
    }
    key.data = plain_key;
    key.len = plain_key_len;

    if ((key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
        if (tlv_find_tag(&ctxe, TAG_IMF, &chal) == false) {
            mbedtls_platform_zeroize(plain_key, plain_key_len);
            free(plain_key);
            oath_credential_close(&credential);
            return SW_INCORRECT_PARAMS();
        }
    }

    if (!oath_response_has_room(1)) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        oath_credential_close(&credential);
        return SW_WRONG_LENGTH();
    }
    res_APDU[res_APDU_size++] = TAG_RESPONSE + P2(apdu);

    bool is_hotp = (key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP;
    int ret = calculate_oath(P2(apdu), key.data, key.len, chal.data, chal.len);
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        oath_credential_close(&credential);
        return SW_EXEC_ERROR();
    }
    mbedtls_platform_zeroize(plain_key, plain_key_len);
    free(plain_key);
    if (is_hotp) {
        uint64_t v = get_uint64_be(chal.data);
        v++;
        uint8_t *tmp = (uint8_t *)calloc(1, credential.size);
        if (!tmp) {
            oath_credential_close(&credential);
            return SW_EXEC_ERROR();
        }
        memcpy(tmp, credential.data, credential.size);
        tlv_ctx_t ctxt;
        tlv_ctx_init(BYTE_ARRAY(tmp, credential.size), &ctxt);
        if (!tlv_find_tag(&ctxt, TAG_IMF, &chal)) {
            mbedtls_platform_zeroize(tmp, credential.size);
            free(tmp);
            oath_credential_close(&credential);
            return SW_EXEC_ERROR();
        }
        put_uint64_be(v, chal.data);
        int update_ret = oath_credential_write(fid, tmp, credential.size);
        mbedtls_platform_zeroize(tmp, credential.size);
        free(tmp);
        if (update_ret != PICOKEYS_OK) {
            oath_credential_close(&credential);
            return SW_EXEC_ERROR();
        }
    }
    oath_credential_close(&credential);
    apdu.ne = res_APDU_size;
    return SW_OK();
}

static int cmd_calculate_all(void) {
    tlv_ctx_t ctxi, key = { 0 }, chal = { 0 }, name = { 0 }, prop = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (P2(apdu) != 0x0 && P2(apdu) != 0x1) {
        return SW_INCORRECT_P1P2();
    }
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (tlv_find_tag(&ctxi, TAG_CHALLENGE, &chal) == false) {
        return SW_INCORRECT_PARAMS();
    }
    res_APDU_size = 0;
    uint16_t fids[MAX_OATH_CRED];
    size_t num_creds = present_oath_cred_fids(fids, MAX_OATH_CRED);
    for (size_t i = 0; i < num_creds; i++) {
        oath_credential_data_t credential;
        if (oath_credential_open(fids[i], FIDO_OATH_OBJECT_CREDENTIAL, &credential) == PICOKEYS_OK) {
            tlv_ctx_t ctxe;
            tlv_ctx_init(BYTE_ARRAY((uint8_t *)credential.data, credential.size), &ctxe);
            if (tlv_find_tag(&ctxe, TAG_NAME, &name) == false || tlv_find_tag(&ctxe, TAG_KEY, &key) == false) {
                oath_credential_close(&credential);
                continue;
            }
            if (name.len > UINT8_MAX) {
                oath_credential_close(&credential);
                return SW_WRONG_LENGTH();
            }
            uint8_t *plain_key = NULL;
            uint16_t plain_key_len = 0;
            if (oath_decrypt_key(key.data, key.len, &plain_key, &plain_key_len) != PICOKEYS_OK || plain_key_len < 2) {
                if (plain_key != NULL) {
                    mbedtls_platform_zeroize(plain_key, plain_key_len);
                    free(plain_key);
                }
                oath_credential_close(&credential);
                continue;
            }
            key.data = plain_key;
            key.len = plain_key_len;
            bool is_hotp = (key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP;
            bool touch_required = tlv_find_tag(&ctxe, TAG_PROPERTY, &prop) == true && prop.len > 0 && (prop.data[0] & PROP_TOUCH);
            size_t response_len = is_hotp || touch_required ? 3 : 8;
            if (!oath_response_has_room(2 + name.len + response_len)) {
                mbedtls_platform_zeroize(plain_key, plain_key_len);
                free(plain_key);
                oath_credential_close(&credential);
                return SW_WRONG_LENGTH();
            }
            res_APDU[res_APDU_size++] = TAG_NAME;
            res_APDU[res_APDU_size++] = (uint8_t)name.len;
            memcpy(res_APDU + res_APDU_size, name.data, name.len);
            res_APDU_size += (uint16_t)name.len;
            if (is_hotp) {
                res_APDU[res_APDU_size++] = TAG_NO_RESPONSE;
                res_APDU[res_APDU_size++] = 1;
                res_APDU[res_APDU_size++] = key.data[1];
            }
            else if (touch_required) {
                res_APDU[res_APDU_size++] = TAG_TOUCH_RESPONSE;
                res_APDU[res_APDU_size++] = 1;
                res_APDU[res_APDU_size++] = key.data[1];
            }
            else {
                res_APDU[res_APDU_size++] = TAG_RESPONSE + P2(apdu);
                int ret = calculate_oath(P2(apdu), key.data, key.len, chal.data, chal.len);
                if (ret != PICOKEYS_OK) {
                    res_APDU[res_APDU_size++] = 1;
                    res_APDU[res_APDU_size++] = key.data[1];
                }
            }
            mbedtls_platform_zeroize(plain_key, plain_key_len);
            free(plain_key);
            oath_credential_close(&credential);
        }
    }
    apdu.ne = res_APDU_size;
    return SW_OK();
}

static int cmd_send_remaining(void) {
    return SW_OK();
}

static bool otp_pin_matches(const uint8_t *record, size_t record_len, const uint8_t *pin, size_t pin_len) {
    uint8_t verifier[32] = { 0 };
    bool matches = false;

    if (record_len == OTP_PIN_V1_SIZE && record[1] == OTP_PIN_FORMAT_V1) {
        pin_derive_verifier(CONST_BYTE_ARRAY(pin, pin_len), verifier);
        matches = mbedtls_ct_memcmp(record + 2, verifier, sizeof(verifier)) == 0;
    }
    else if (record_len == OTP_PIN_LEGACY_SIZE && pin_len > 0) {
        double_hash_pin(CONST_BYTE_ARRAY(pin, pin_len), verifier);
        matches = mbedtls_ct_memcmp(record + 1, verifier, sizeof(verifier)) == 0;
    }

    mbedtls_platform_zeroize(verifier, sizeof(verifier));
    return matches;
}

static void otp_pin_record_v1(const uint8_t *pin, size_t pin_len, uint8_t record[OTP_PIN_V1_SIZE]) {
    memset(record, 0, OTP_PIN_V1_SIZE);
    record[0] = MAX_OTP_COUNTER;
    record[1] = OTP_PIN_FORMAT_V1;
    pin_derive_verifier(CONST_BYTE_ARRAY(pin, pin_len), record + 2);
}

typedef enum {
    OTP_PIN_MATCH,
    OTP_PIN_MISMATCH,
    OTP_PIN_BLOCKED,
    OTP_PIN_STORAGE_ERROR,
} otp_pin_match_result_t;

static otp_pin_match_result_t oath_check_pin(file_t *ef_otp_pin, size_t record_len, const uint8_t *pin, size_t pin_len) {
    uint8_t record[OTP_PIN_V1_SIZE] = { 0 };
    if (!file_has_data(ef_otp_pin) || file_get_data(ef_otp_pin) == NULL || (record_len != OTP_PIN_LEGACY_SIZE && record_len != OTP_PIN_V1_SIZE)) {
        return OTP_PIN_STORAGE_ERROR;
    }
    memcpy(record, file_get_data(ef_otp_pin), record_len);
    if (record[0] == 0) {
        mbedtls_platform_zeroize(record, sizeof(record));
        return OTP_PIN_BLOCKED;
    }

    record[0] -= 1;
    if (file_put_data(ef_otp_pin, CONST_BYTE_ARRAY(record, record_len)) != PICOKEYS_OK ||
        !flash_commit_sync(OTP_PIN_RETRY_COMMIT_TIMEOUT_MS) ||
        file_get_size(ef_otp_pin) != record_len || file_get_data(ef_otp_pin) == NULL ||
        file_get_data(ef_otp_pin)[0] != record[0]) {
        mbedtls_platform_zeroize(record, sizeof(record));
        return OTP_PIN_STORAGE_ERROR;
    }
    mbedtls_platform_zeroize(record, sizeof(record));
    return otp_pin_matches(file_get_data(ef_otp_pin), record_len, pin, pin_len) ? OTP_PIN_MATCH : OTP_PIN_MISMATCH;
}

static int cmd_set_otp_pin(void) {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t record[OTP_PIN_V1_SIZE] = { 0 };
    file_t *ef_otp_pin = file_search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
    if (file_has_data(ef_otp_pin)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    tlv_ctx_t ctxi, pw = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_PASSWORD, &pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    otp_pin_record_v1(pw.data, pw.len, record);
    int ret = file_put_data(ef_otp_pin, CONST_BYTE_ARRAY(record, sizeof(record)));
    mbedtls_platform_zeroize(record, sizeof(record));
    if (ret != PICOKEYS_OK) {
        return SW_MEMORY_FAILURE();
    }
    flash_commit();
    otp_pin_verified = false;
    return SW_OK();
}

static int cmd_change_otp_pin(void) {
    uint8_t record[OTP_PIN_V1_SIZE] = { 0 };
    file_t *ef_otp_pin = file_search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
    size_t record_len = file_get_size(ef_otp_pin);
    if (!file_has_data(ef_otp_pin) || (record_len != OTP_PIN_LEGACY_SIZE && record_len != OTP_PIN_V1_SIZE)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    tlv_ctx_t ctxi, pw = { 0 }, new_pw = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_PASSWORD,  &pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (tlv_find_tag(&ctxi, TAG_NEW_PASSWORD, &new_pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    otp_pin_match_result_t match = oath_check_pin(ef_otp_pin, record_len, pw.data, pw.len);
    if (match == OTP_PIN_STORAGE_ERROR) {
        otp_pin_verified = false;
        return SW_MEMORY_FAILURE();
    }
    if (match != OTP_PIN_MATCH) {
        otp_pin_verified = false;
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    otp_pin_record_v1(new_pw.data, new_pw.len, record);
    int ret = file_put_data(ef_otp_pin, CONST_BYTE_ARRAY(record, sizeof(record)));
    mbedtls_platform_zeroize(record, sizeof(record));
    if (ret != PICOKEYS_OK) {
        return SW_MEMORY_FAILURE();
    }
    flash_commit();
    otp_pin_verified = false;
    return SW_OK();
}

static int cmd_verify_otp_pin(void) {
    uint8_t record[OTP_PIN_V1_SIZE] = { 0 };
    file_t *ef_otp_pin = file_search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
    size_t record_len = file_get_size(ef_otp_pin);
    if (!file_has_data(ef_otp_pin) || (record_len != OTP_PIN_LEGACY_SIZE && record_len != OTP_PIN_V1_SIZE)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    otp_pin_verified = false;
    tlv_ctx_t ctxi, pw = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_PASSWORD, &pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    otp_pin_match_result_t match = oath_check_pin(ef_otp_pin, record_len, pw.data, pw.len);
    if (match == OTP_PIN_STORAGE_ERROR) {
        return SW_MEMORY_FAILURE();
    }
    if (match != OTP_PIN_MATCH) {
        validated = false;
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    otp_pin_record_v1(pw.data, pw.len, record);
    int ret = file_put_data(ef_otp_pin, CONST_BYTE_ARRAY(record, sizeof(record)));
    mbedtls_platform_zeroize(record, sizeof(record));
    if (ret != PICOKEYS_OK) {
        return SW_MEMORY_FAILURE();
    }
    flash_commit();
    validated = true;
    otp_pin_verified = true;
    return SW_OK();
}

static int cmd_verify_hotp(void) {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    int pin_status = oath_require_otp_pin();
    if (pin_status != SW_OK()) {
        return pin_status;
    }
    tlv_ctx_t ctxi, key = { 0 }, chal = { 0 }, name = { 0 }, code = { 0 }, prop = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    uint32_t code_int = 0;
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_INCORRECT_PARAMS();
    }
    uint16_t fid = 0;
    if (!find_oath_cred(name.data, name.len, &fid)) {
        return SW_DATA_INVALID();
    }
    oath_credential_data_t credential;
    if (oath_credential_open(fid, FIDO_OATH_OBJECT_CREDENTIAL, &credential) != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    tlv_ctx_t ctxe;
    tlv_ctx_init(BYTE_ARRAY((uint8_t *)credential.data, credential.size), &ctxe);
    if (tlv_find_tag(&ctxe, TAG_KEY, &key) == false) {
        oath_credential_close(&credential);
        return SW_INCORRECT_PARAMS();
    }
    uint8_t *plain_key = NULL;
    uint16_t plain_key_len = 0;
    if (oath_decrypt_key(key.data, key.len, &plain_key, &plain_key_len) != PICOKEYS_OK || plain_key_len < 2) {
        if (plain_key != NULL) {
            mbedtls_platform_zeroize(plain_key, plain_key_len);
            free(plain_key);
        }
        oath_credential_close(&credential);
        return SW_EXEC_ERROR();
    }
    key.data = plain_key;
    key.len = plain_key_len;

    if ((key.data[0] & OATH_TYPE_MASK) != OATH_TYPE_HOTP) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        oath_credential_close(&credential);
        return SW_DATA_INVALID();
    }
    if (tlv_find_tag(&ctxe, TAG_IMF, &chal) == false) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        oath_credential_close(&credential);
        return SW_INCORRECT_PARAMS();
    }
    if (tlv_find_tag(&ctxe, TAG_PROPERTY, &prop) == true && prop.len > 0 && (prop.data[0] & PROP_TOUCH) && !check_user_presence()) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        oath_credential_close(&credential);
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (tlv_find_tag(&ctxi, TAG_RESPONSE, &code) == false || code.len != sizeof(uint32_t)) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        oath_credential_close(&credential);
        return SW_INCORRECT_PARAMS();
    }
    code_int = get_uint32_be(code.data);

    int ret = calculate_oath(0x01, key.data, key.len, chal.data, chal.len);
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        oath_credential_close(&credential);
        return SW_EXEC_ERROR();
    }
    mbedtls_platform_zeroize(plain_key, plain_key_len);
    free(plain_key);
    oath_credential_close(&credential);
    uint32_t res_int = get_uint32_be(res_APDU + 2);
    if (res_APDU[1] == 6) {
        res_int %= (uint32_t) 1e6;
    }
    else {
        res_int %= (uint32_t) 1e8;
    }
    if (res_int != code_int) {
        return SW_WRONG_DATA();
    }
    res_APDU_size = 0;
    apdu.ne = 0;
    return SW_OK();
}

static int cmd_rename(void) {
    tlv_ctx_t ctxi, name = { 0 }, new_name = { 0 };

    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.data[0] != TAG_NAME) {
        return SW_WRONG_DATA();
    }
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_WRONG_DATA();
    }

    tlv_ctx_init(BYTE_ARRAY(name.data + name.len, apdu.nc - (name.data + name.len - apdu.data)), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_NAME, &new_name) == false) {
        return SW_WRONG_DATA();
    }
    if (name.len == new_name.len && memcmp(name.data, new_name.data, name.len) == 0) {
        return SW_WRONG_DATA();
    }
    if (new_name.len > UINT8_MAX) {
        return SW_WRONG_DATA();
    }
    uint16_t fid = 0;
    if (!find_oath_cred(name.data, name.len, &fid)) {
        return SW_DATA_INVALID();
    }
    oath_credential_data_t credential;
    if (oath_credential_open(fid, FIDO_OATH_OBJECT_CREDENTIAL, &credential) != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    const uint8_t *fdata = credential.data;
    uint16_t fsize = credential.size;
    tlv_ctx_init(BYTE_ARRAY((uint8_t *)fdata, fsize), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        oath_credential_close(&credential);
        return SW_WRONG_DATA();
    }
    uint8_t *new_data = (uint8_t *) calloc(fsize + new_name.len - name.len, sizeof(uint8_t));
    if (!new_data) {
        oath_credential_close(&credential);
        return SW_EXEC_ERROR();
    }
    memcpy(new_data, fdata, name.data - fdata);
    *(new_data + (name.data - fdata) - 1) = (uint8_t)new_name.len;
    memcpy(new_data + (name.data - fdata), new_name.data, new_name.len);
    memcpy(new_data + (name.data - fdata) + new_name.len, name.data + name.len, fsize - (name.data + name.len - fdata));
    int ret = oath_credential_write(fid, new_data, (uint16_t)(fsize + new_name.len - name.len));
    mbedtls_platform_zeroize(new_data, fsize + new_name.len - name.len);
    free(new_data);
    oath_credential_close(&credential);
    return ret == PICOKEYS_OK ? SW_OK() : SW_EXEC_ERROR();
}

static int cmd_get_credential(void) {
    tlv_ctx_t ctxi, name = { 0 };
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    int pin_status = oath_require_otp_pin();
    if (pin_status != SW_OK()) {
        return pin_status;
    }
    if (apdu.nc < 3) {
        return SW_INCORRECT_PARAMS();
    }
    if (apdu.data[0] != TAG_NAME) {
        return SW_WRONG_DATA();
    }
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_WRONG_DATA();
    }
    uint16_t fid = 0;
    if (!find_oath_cred(name.data, name.len, &fid)) {
        return SW_DATA_INVALID();
    }
    oath_credential_data_t credential;
    if (oath_credential_open(fid, FIDO_OATH_OBJECT_CREDENTIAL, &credential) != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    tlv_ctx_t login = { 0 }, pw = { 0 }, meta = { 0 }, prop = { 0 };
    tlv_ctx_init(BYTE_ARRAY((uint8_t *)credential.data, credential.size), &ctxi);
    if ((tlv_find_tag(&ctxi, TAG_NAME, &name) == true && !oath_response_append(TAG_NAME, name.data, name.len)) ||
        (tlv_find_tag(&ctxi, TAG_PWS_LOGIN, &login) == true && !oath_response_append(TAG_PWS_LOGIN, login.data, login.len)) ||
        (tlv_find_tag(&ctxi, TAG_PWS_PASSWORD, &pw) == true && !oath_response_append(TAG_PWS_PASSWORD, pw.data, pw.len)) ||
        (tlv_find_tag(&ctxi, TAG_PWS_METADATA, &meta) == true && !oath_response_append(TAG_PWS_METADATA, meta.data, meta.len)) ||
        (tlv_find_tag(&ctxi, TAG_PROPERTY, &prop) == true && !oath_response_append(TAG_PROPERTY, prop.data, prop.len))) {
        oath_credential_close(&credential);
        return SW_WRONG_LENGTH();
    }
    oath_credential_close(&credential);
    apdu.ne = res_APDU_size;
    return SW_OK();
}

#define INS_PUT             0x01
#define INS_DELETE          0x02
#define INS_SET_CODE        0x03
#define INS_RESET           0x04
#define INS_RENAME          0x05
#define INS_LIST            0xa1
#define INS_CALCULATE       0xa2
#define INS_VALIDATE        0xa3
#define INS_CALC_ALL        0xa4
#define INS_SEND_REMAINING  0xa5
#define INS_VERIFY_CODE     0xb1
#define INS_VERIFY_PIN      0xb2
#define INS_CHANGE_PIN      0xb3
#define INS_SET_PIN         0xb4
#define INS_GET_CREDENTIAL  0xb5

static const cmd_t cmds[] = {
    { INS_PUT, cmd_put },
    { INS_DELETE, cmd_delete },
    { INS_SET_CODE, cmd_set_code },
    { INS_RESET, cmd_reset },
    { INS_RENAME, cmd_rename },
    { INS_LIST, cmd_list },
    { INS_VALIDATE, cmd_validate },
    { INS_CALCULATE, cmd_calculate },
    { INS_CALC_ALL, cmd_calculate_all },
    { INS_SEND_REMAINING, cmd_send_remaining },
    { INS_SET_PIN, cmd_set_otp_pin },
    { INS_CHANGE_PIN, cmd_change_otp_pin },
    { INS_VERIFY_PIN, cmd_verify_otp_pin },
    { INS_VERIFY_CODE, cmd_verify_hotp },
    { INS_GET_CREDENTIAL, cmd_get_credential },
    { 0x00, 0x0 }
};

static int oath_process_apdu(void) {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    if (cap_supported(CAP_OATH)) {
        for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
            if (cmd->ins == INS(apdu)) {
                int r = cmd->cmd_handler();
                return r;
            }
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
