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
#include "mbedtls/constant_time.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include <stdlib.h>

#define MAX_OATH_CRED   255
#define CHALLENGE_LEN   8
#define MAX_OTP_COUNTER 3
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
static bool oath_migration_done = false;
static uint8_t challenge[CHALLENGE_LEN] = { 0 };
static const uint8_t oath_secure_key_magic[] = { 'O', 'A', 'T', 'H' };

typedef struct {
    file_t **files;
    uint16_t *fids;
    size_t len;
    size_t cap;
} oath_cred_list_t;

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
            random_fill_buffer(challenge, sizeof(challenge));
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
    return PICOKEYS_OK;
}

static bool oath_key_is_secure(const uint8_t *data, uint16_t len) {
    return data != NULL && len > OATH_SECURE_KEY_OVERHEAD && memcmp(data, oath_secure_key_magic, sizeof(oath_secure_key_magic)) == 0 && data[sizeof(oath_secure_key_magic)] == OATH_SECURE_KEY_VERSION;
}

static int oath_derive_key(uint8_t key[32]) {
    uint8_t kbase[32];
    derive_kbase(kbase);
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), pico_serial_hash, sizeof(pico_serial_hash), kbase, sizeof(kbase), (const uint8_t *)"OATH/KEYS", 9, key, 32);
    mbedtls_platform_zeroize(kbase, sizeof(kbase));
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static int oath_encrypt_key(const uint8_t *plain, uint16_t plain_len, uint8_t **encrypted, uint16_t *encrypted_len) {
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
        ret = encrypt_with_aad(oath_key, plain, plain_len, PIN_KDF_V2, out + sizeof(oath_secure_key_magic) + 1);
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

static int oath_decrypt_key(const uint8_t *stored, uint16_t stored_len, uint8_t **decrypted, uint16_t *decrypted_len) {
    if (stored == NULL || decrypted == NULL || decrypted_len == NULL) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!oath_key_is_secure(stored, stored_len)) {
        uint8_t *copy = (uint8_t *)calloc(1, stored_len);
        if (copy == NULL) {
            return PICOKEYS_EXEC_ERROR;
        }
        memcpy(copy, stored, stored_len);
        *decrypted = copy;
        *decrypted_len = stored_len;
        return PICOKEYS_OK;
    }

    uint16_t out_len = stored_len - OATH_SECURE_KEY_OVERHEAD;
    uint8_t *out = (uint8_t *)calloc(1, out_len);
    if (out == NULL) {
        return PICOKEYS_EXEC_ERROR;
    }
    uint8_t oath_key[32];
    int ret = oath_derive_key(oath_key);
    if (ret == PICOKEYS_OK) {
        ret = decrypt_with_aad(oath_key, stored + sizeof(oath_secure_key_magic) + 1, stored_len - sizeof(oath_secure_key_magic) - 1, PIN_KDF_V2, out);
    }
    mbedtls_platform_zeroize(oath_key, sizeof(oath_key));
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(out, out_len);
        free(out);
        return ret;
    }
    *decrypted = out;
    *decrypted_len = out_len;
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

static int oath_put_credential_data(file_t *ef, const uint8_t *data, uint16_t len) {
    tlv_ctx_t ctxi;
    tlv_ctx_init((uint8_t *)data, len, &ctxi);
    tlv_ctx_t key = { 0 };
    if (tlv_find_tag(&ctxi, TAG_KEY, &key) == false || oath_key_is_secure(key.data, key.len)) {
        return file_put_data(ef, data, len);
    }

    uint8_t *encrypted = NULL;
    uint16_t encrypted_len = 0;
    int ret = oath_encrypt_key(key.data, key.len, &encrypted, &encrypted_len);
    if (ret != PICOKEYS_OK) {
        return ret;
    }

    uint16_t out_len = 0;
    uint8_t *p = NULL, *tdata = NULL;
    uint16_t tag = 0, tag_len = 0;
    while (tlv_walk(&ctxi, &p, &tag, &tag_len, &tdata)) {
        out_len += tlv_len_tag(tag, tag == TAG_KEY ? encrypted_len : tag_len);
    }
    uint8_t *out = (uint8_t *)calloc(1, out_len);
    if (out == NULL) {
        mbedtls_platform_zeroize(encrypted, encrypted_len);
        free(encrypted);
        return PICOKEYS_EXEC_ERROR;
    }
    p = NULL;
    uint8_t *op = out;
    while (tlv_walk(&ctxi, &p, &tag, &tag_len, &tdata)) {
        if (tag == TAG_KEY) {
            op = tlv_append(op, tag, encrypted, encrypted_len);
        }
        else {
            op = tlv_append(op, tag, tdata, tag_len);
        }
    }

    ret = file_put_data(ef, out, out_len);
    mbedtls_platform_zeroize(encrypted, encrypted_len);
    mbedtls_platform_zeroize(out, out_len);
    free(encrypted);
    free(out);
    return ret;
}

static int oath_put_code_key(file_t *ef, const uint8_t *key, uint16_t key_len) {
    if (oath_key_is_secure(key, key_len)) {
        return file_put_data(ef, key, key_len);
    }
    uint8_t *encrypted = NULL;
    uint16_t encrypted_len = 0;
    int ret = oath_encrypt_key(key, key_len, &encrypted, &encrypted_len);
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    ret = file_put_data(ef, encrypted, encrypted_len);
    mbedtls_platform_zeroize(encrypted, encrypted_len);
    free(encrypted);
    return ret;
}

static int oath_migrate_credential(file_t *ef, bool *changed) {
    if (!file_has_data(ef)) {
        return PICOKEYS_OK;
    }
    tlv_ctx_t ctxi, key = { 0 };
    tlv_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
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

static int cmp_file_fid(const void *a, const void *b) {
    const file_t *fa = *(const file_t * const *)a;
    const file_t *fb = *(const file_t * const *)b;
    return (fa->fid > fb->fid) - (fa->fid < fb->fid);
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
    if (list->files) {
        list->files[list->len] = file;
    }
    if (list->fids) {
        list->fids[list->len] = file->fid;
    }
    list->len++;
    return true;
}

static size_t present_oath_cred_files(file_t **files, size_t cap) {
    oath_cred_list_t list = { .files = files, .fids = NULL, .len = 0, .cap = cap };
    file_for_each_dynamic(collect_oath_cred, &list);
    qsort(files, list.len, sizeof(files[0]), cmp_file_fid);
    return list.len;
}

static size_t present_oath_cred_fids(uint16_t *fids, size_t cap) {
    oath_cred_list_t list = { .files = NULL, .fids = fids, .len = 0, .cap = cap };
    file_for_each_dynamic(collect_oath_cred, &list);
    qsort(fids, list.len, sizeof(fids[0]), cmp_u16);
    return list.len;
}

static file_t *find_oath_cred(const uint8_t *name, size_t name_len) {
    file_t *creds[MAX_OATH_CRED];
    size_t num_creds = present_oath_cred_files(creds, MAX_OATH_CRED);
    for (size_t i = 0; i < num_creds; i++) {
        file_t *ef = creds[i];
        tlv_ctx_t ctxi, ef_tag = { 0 };
        tlv_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
        if (file_has_data(ef) && tlv_find_tag(&ctxi, TAG_NAME, &ef_tag) == true && ef_tag.len == name_len && memcmp(ef_tag.data, name, name_len) == 0) {
            return ef;
        }
    }
    return NULL;
}

static int cmd_put(void) {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    tlv_ctx_t ctxi, key = { 0 }, name = { 0 }, imf = { 0 };
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (tlv_find_tag(&ctxi, TAG_KEY, &key) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (key.len < 2) {
        return SW_WRONG_DATA();
    }
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if ((key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
        if (tlv_find_tag(&ctxi, TAG_IMF, &imf) == false) {
            memcpy(apdu.data + apdu.nc, "\x7a\x08\x00\x00\x00\x00\x00\x00\x00\x00", 10);
            apdu.nc += 10;
        }
        else { //prepend zero-valued bytes
            if (imf.len < 8) {
                memmove(imf.data + (8 - imf.len), imf.data, imf.len);
                memset(imf.data, 0, 8 - imf.len);
                *(imf.data - 1) = 8;
                apdu.nc += (8 - imf.len);
            }

        }
    }
    file_t *ef = find_oath_cred(name.data, name.len);
    if (file_has_data(ef)) {
        int ret = oath_put_credential_data(ef, apdu.data, (uint16_t)apdu.nc);
        if (ret != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        flash_commit();
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
                file_t *tef = file_new((uint16_t)(EF_OATH_CRED + i));
                if (!tef) {
                    return SW_FILE_FULL();
                }
                int ret = oath_put_credential_data(tef, apdu.data, (uint16_t)apdu.nc);
                if (ret != PICOKEYS_OK) {
                    return SW_EXEC_ERROR();
                }
                flash_commit();
                return SW_OK();
            }
        }
        return SW_FILE_FULL();
    }
    return SW_OK();
}


static int cmd_delete(void) {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    tlv_ctx_t ctxi, ctxo = { 0 };
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (tlv_find_tag(&ctxi, TAG_NAME, &ctxo) == true) {
        file_t *ef = find_oath_cred(ctxo.data, ctxo.len);
        if (ef) {
            file_delete(ef);
            return SW_OK();
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
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (tlv_find_tag(&ctxi, TAG_KEY, &key) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (key.len == 1) {
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
    if (mbedtls_ct_memcmp(hmac, resp.data, resp.len) != 0) {
        return SW_DATA_INVALID();
    }
    random_fill_buffer(challenge, sizeof(challenge));
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
        if (file_has_data(ef)) {
            file_delete_no_commit(ef);
        }
    }
    file_delete_no_commit(file_search(EF_OATH_CODE));
    flash_clear_file(file_search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF));
    flash_commit();
    validated = true;
    return SW_OK();
}

static int cmd_list(void) {
    if (validated == false) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    bool ext = (apdu.nc == 1 && apdu.data[0] == 0x01);
    file_t *creds[MAX_OATH_CRED];
    size_t num_creds = present_oath_cred_files(creds, MAX_OATH_CRED);
    for (size_t i = 0; i < num_creds; i++) {
        file_t *ef = creds[i];
        if (file_has_data(ef)) {
            tlv_ctx_t ctxi, key = { 0 }, name = { 0 }, pws = { 0 };
            tlv_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
            if (tlv_find_tag(&ctxi, TAG_NAME, &name) == true && tlv_find_tag(&ctxi, TAG_KEY, &key) == true) {
                uint8_t *plain_key = NULL;
                uint16_t plain_key_len = 0;
                if (oath_decrypt_key(key.data, key.len, &plain_key, &plain_key_len) != PICOKEYS_OK || plain_key_len < 2) {
                    if (plain_key != NULL) {
                        mbedtls_platform_zeroize(plain_key, plain_key_len);
                        free(plain_key);
                    }
                    continue;
                }
                res_APDU[res_APDU_size++] = TAG_NAME_LIST;
                res_APDU[res_APDU_size++] = (uint8_t)(name.len + 1 + (ext ? 1 : 0));
                res_APDU[res_APDU_size++] = plain_key[0];
                memcpy(res_APDU + res_APDU_size, name.data, name.len); res_APDU_size += name.len;
                if (ext) {
                    uint8_t props = 0x0;
                    if (tlv_find_tag(&ctxi, TAG_PWS_LOGIN, &pws) == true || tlv_find_tag(&ctxi, TAG_PWS_PASSWORD, &pws) == true || tlv_find_tag(&ctxi, TAG_PWS_METADATA, &pws) == true) {
                        props |= 0x4;
                    }
                    if (tlv_find_tag(&ctxi, TAG_PROPERTY, &pws) == true && (pws.data[0] & PROP_TOUCH)) {
                        props |= 0x1;
                    }
                    res_APDU[res_APDU_size++] = props;
                }
                mbedtls_platform_zeroize(plain_key, plain_key_len);
                free(plain_key);
            }
        }
    }
    apdu.ne = res_APDU_size;
    return SW_OK();
}

static int cmd_validate(void) {
    tlv_ctx_t ctxi, key = { 0 }, chal = { 0 }, resp = { 0 };
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
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
    if (plain_key_len < 2) {
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
        res_APDU[res_APDU_size++] = 4 + 1;
        res_APDU[res_APDU_size++] = key[1];
        uint8_t offset = hmac[hmac_size - 1] & 0x0f;
        res_APDU[res_APDU_size++] = hmac[offset] & 0x7f;
        res_APDU[res_APDU_size++] = hmac[offset + 1];
        res_APDU[res_APDU_size++] = hmac[offset + 2];
        res_APDU[res_APDU_size++] = hmac[offset + 3];
    }
    else {
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
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (tlv_find_tag(&ctxi, TAG_CHALLENGE, &chal) == false) {
        return SW_INCORRECT_PARAMS();
    }
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *ef = find_oath_cred(name.data, name.len);
    if (file_has_data(ef) == false) {
        return SW_DATA_INVALID();
    }
    tlv_ctx_t ctxe;
    tlv_ctx_init(file_get_data(ef), file_get_size(ef), &ctxe);
    if (tlv_find_tag(&ctxe, TAG_KEY, &key) == false) {
        return SW_INCORRECT_PARAMS();
    }
    uint8_t *plain_key = NULL;
    uint16_t plain_key_len = 0;
    if (oath_decrypt_key(key.data, key.len, &plain_key, &plain_key_len) != PICOKEYS_OK || plain_key_len < 2) {
        if (plain_key != NULL) {
            mbedtls_platform_zeroize(plain_key, plain_key_len);
            free(plain_key);
        }
        return SW_EXEC_ERROR();
    }
    key.data = plain_key;
    key.len = plain_key_len;

    if ((key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
        if (tlv_find_tag(&ctxe, TAG_IMF, &chal) == false) {
            mbedtls_platform_zeroize(plain_key, plain_key_len);
            free(plain_key);
            return SW_INCORRECT_PARAMS();
        }
    }

    res_APDU[res_APDU_size++] = TAG_RESPONSE + P2(apdu);

    bool is_hotp = (key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP;
    int ret = calculate_oath(P2(apdu), key.data, key.len, chal.data, chal.len);
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        return SW_EXEC_ERROR();
    }
    mbedtls_platform_zeroize(plain_key, plain_key_len);
    free(plain_key);
    if (is_hotp) {
        uint64_t v = get_uint64_be(chal.data);
        size_t ef_size = file_get_size(ef);
        v++;
        uint8_t *tmp = (uint8_t *) calloc(1, ef_size);
        memcpy(tmp, file_get_data(ef), ef_size);
        tlv_ctx_t ctxt;
        tlv_ctx_init(tmp, (uint16_t)ef_size, &ctxt);
        tlv_find_tag(&ctxt, TAG_IMF, &chal);
        put_uint64_be(v, chal.data);
        file_put_data(ef, tmp, (uint16_t)ef_size);
        flash_commit();
        free(tmp);
    }
    apdu.ne = res_APDU_size;
    return SW_OK();
}

static int cmd_calculate_all(void) {
    tlv_ctx_t ctxi, key = { 0 }, chal = { 0 }, name = { 0 }, prop = { 0 };
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
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
    file_t *creds[MAX_OATH_CRED];
    size_t num_creds = present_oath_cred_files(creds, MAX_OATH_CRED);
    for (size_t i = 0; i < num_creds; i++) {
        file_t *ef = creds[i];
        if (file_has_data(ef)) {
            const uint8_t *ef_data = file_get_data(ef);
            size_t ef_len = file_get_size(ef);
            tlv_ctx_t ctxe;
            tlv_ctx_init((uint8_t *)ef_data, (uint16_t)ef_len, &ctxe);
            if (tlv_find_tag(&ctxe, TAG_NAME, &name) == false || tlv_find_tag(&ctxe, TAG_KEY, &key) == false) {
                continue;
            }
            uint8_t *plain_key = NULL;
            uint16_t plain_key_len = 0;
            if (oath_decrypt_key(key.data, key.len, &plain_key, &plain_key_len) != PICOKEYS_OK || plain_key_len < 2) {
                if (plain_key != NULL) {
                    mbedtls_platform_zeroize(plain_key, plain_key_len);
                    free(plain_key);
                }
                continue;
            }
            key.data = plain_key;
            key.len = plain_key_len;
            res_APDU[res_APDU_size++] = TAG_NAME;
            res_APDU[res_APDU_size++] = (uint8_t)name.len;
            memcpy(res_APDU + res_APDU_size, name.data, name.len); res_APDU_size += name.len;
            if ((key.data[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP) {
                res_APDU[res_APDU_size++] = TAG_NO_RESPONSE;
                res_APDU[res_APDU_size++] = 1;
                res_APDU[res_APDU_size++] = key.data[1];
            }
            else if (tlv_find_tag(&ctxe, TAG_PROPERTY, &prop) == true && (prop.data[0] & PROP_TOUCH)) {
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
        }
    }
    apdu.ne = res_APDU_size;
    return SW_OK();
}

static int cmd_send_remaining(void) {
    return SW_OK();
}

static int cmd_set_otp_pin(void) {
    uint8_t hsh[33] = { 0 };
    file_t *ef_otp_pin = file_search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
    if (file_has_data(ef_otp_pin)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    tlv_ctx_t ctxi, pw = { 0 };
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (tlv_find_tag(&ctxi, TAG_PASSWORD, &pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    hsh[0] = MAX_OTP_COUNTER;
    double_hash_pin(pw.data, pw.len, hsh + 1);
    file_put_data(ef_otp_pin, hsh, sizeof(hsh));
    flash_commit();
    return SW_OK();
}

static int cmd_change_otp_pin(void) {
    uint8_t hsh[33] = { 0 };
    file_t *ef_otp_pin = file_search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
    if (!file_has_data(ef_otp_pin)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    tlv_ctx_t ctxi, pw = { 0 }, new_pw = { 0 };
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (tlv_find_tag(&ctxi, TAG_PASSWORD,  &pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    double_hash_pin(pw.data, pw.len, hsh + 1);
    if (mbedtls_ct_memcmp(file_get_data(ef_otp_pin) + 1, hsh + 1, 32) != 0) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (tlv_find_tag(&ctxi, TAG_NEW_PASSWORD, &new_pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    hsh[0] = MAX_OTP_COUNTER;
    double_hash_pin(new_pw.data, new_pw.len, hsh + 1);
    file_put_data(ef_otp_pin, hsh, sizeof(hsh));
    flash_commit();
    return SW_OK();
}

static int cmd_verify_otp_pin(void) {
    uint8_t hsh[33] = { 0 }, data_hsh[33];
    file_t *ef_otp_pin = file_search_by_fid(EF_OTP_PIN, NULL, SPECIFY_EF);
    if (!file_has_data(ef_otp_pin)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    tlv_ctx_t ctxi, pw = { 0 };
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (tlv_find_tag(&ctxi, TAG_PASSWORD, &pw) == false) {
        return SW_INCORRECT_PARAMS();
    }
    double_hash_pin(pw.data, pw.len, hsh + 1);
    memcpy(data_hsh, file_get_data(ef_otp_pin), sizeof(data_hsh));
    if (data_hsh[0] == 0 || mbedtls_ct_memcmp(data_hsh + 1, hsh + 1, 32) != 0) {
        if (data_hsh[0] > 0) {
            data_hsh[0] -= 1;
        }
        file_put_data(ef_otp_pin, data_hsh, sizeof(data_hsh));
        flash_commit();
        validated = false;
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    data_hsh[0] = MAX_OTP_COUNTER;
    file_put_data(ef_otp_pin, data_hsh, sizeof(data_hsh));
    flash_commit();
    validated = true;
    return SW_OK();
}

static int cmd_verify_hotp(void) {
    tlv_ctx_t ctxi, key = { 0 }, chal = { 0 }, name = { 0 }, code = { 0 };
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    uint32_t code_int = 0;
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *ef = file_search_by_fid(EF_OATH_CRED, NULL, SPECIFY_EF);
    if (file_has_data(ef) == false) {
        return SW_DATA_INVALID();
    }
    tlv_ctx_t ctxe;
    tlv_ctx_init(file_get_data(ef), file_get_size(ef), &ctxe);
    if (tlv_find_tag(&ctxe, TAG_KEY, &key) == false) {
        return SW_INCORRECT_PARAMS();
    }
    uint8_t *plain_key = NULL;
    uint16_t plain_key_len = 0;
    if (oath_decrypt_key(key.data, key.len, &plain_key, &plain_key_len) != PICOKEYS_OK || plain_key_len < 2) {
        if (plain_key != NULL) {
            mbedtls_platform_zeroize(plain_key, plain_key_len);
            free(plain_key);
        }
        return SW_EXEC_ERROR();
    }
    key.data = plain_key;
    key.len = plain_key_len;

    if ((key.data[0] & OATH_TYPE_MASK) != OATH_TYPE_HOTP) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        return SW_DATA_INVALID();
    }
    if (tlv_find_tag(&ctxe, TAG_IMF, &chal) == false) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        return SW_INCORRECT_PARAMS();
    }
    if (tlv_find_tag(&ctxi, TAG_RESPONSE, &code) == true) {
        code_int = get_uint32_be(code.data);
    }

    int ret = calculate_oath(0x01, key.data, key.len, chal.data, chal.len);
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(plain_key, plain_key_len);
        free(plain_key);
        return SW_EXEC_ERROR();
    }
    mbedtls_platform_zeroize(plain_key, plain_key_len);
    free(plain_key);
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
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_WRONG_DATA();
    }

    tlv_ctx_init(name.data + name.len, (uint16_t)(apdu.nc - (name.data + name.len - apdu.data)), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_NAME, &new_name) == false) {
        return SW_WRONG_DATA();
    }
    if (name.len == new_name.len && memcmp(name.data, new_name.data, name.len) == 0) {
        return SW_WRONG_DATA();
    }
    file_t *ef = find_oath_cred(name.data, name.len);
    if (file_has_data(ef) == false) {
        return SW_DATA_INVALID();
    }
    uint8_t *fdata = file_get_data(ef);
    uint16_t fsize = file_get_size(ef);
    tlv_ctx_init(fdata, fsize, &ctxi);
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_WRONG_DATA();
    }
    uint8_t *new_data = (uint8_t *) calloc(fsize + new_name.len - name.len, sizeof(uint8_t));
    memcpy(new_data, fdata, name.data - fdata);
    *(new_data + (name.data - fdata) - 1) = new_name.len;
    memcpy(new_data + (name.data - fdata), new_name.data, new_name.len);
    memcpy(new_data + (name.data - fdata) + new_name.len, name.data + name.len, fsize - (name.data + name.len - fdata));
    file_put_data(ef, new_data, fsize + new_name.len - name.len);
    flash_commit();
    free(new_data);
    return SW_OK();
}

static int cmd_get_credential(void) {
    tlv_ctx_t ctxi, name = { 0 };
    if (apdu.nc < 3) {
        return SW_INCORRECT_PARAMS();
    }
    if (apdu.data[0] != TAG_NAME) {
        return SW_WRONG_DATA();
    }
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == false) {
        return SW_WRONG_DATA();
    }
    file_t *ef = find_oath_cred(name.data, name.len);
    if (file_has_data(ef) == false) {
        return SW_DATA_INVALID();
    }
    tlv_ctx_t login = { 0 }, pw = { 0 }, meta = { 0 }, prop = { 0 };
    tlv_ctx_init(file_get_data(ef), file_get_size(ef), &ctxi);
    if (tlv_find_tag(&ctxi, TAG_NAME, &name) == true) {
        res_APDU[res_APDU_size++] = TAG_NAME;
        res_APDU[res_APDU_size++] = (uint8_t)(name.len);
        memcpy(res_APDU + res_APDU_size, name.data, name.len); res_APDU_size += name.len;
    }
    if (tlv_find_tag(&ctxi, TAG_PWS_LOGIN, &login) == true) {
        res_APDU[res_APDU_size++] = TAG_PWS_LOGIN;
        res_APDU[res_APDU_size++] = (uint8_t)(login.len);
        memcpy(res_APDU + res_APDU_size, login.data, login.len); res_APDU_size += login.len;
    }
    if (tlv_find_tag(&ctxi, TAG_PWS_PASSWORD, &pw) == true) {
        res_APDU[res_APDU_size++] = TAG_PWS_PASSWORD;
        res_APDU[res_APDU_size++] = (uint8_t)(pw.len);
        memcpy(res_APDU + res_APDU_size, pw.data, pw.len); res_APDU_size += pw.len;
    }
    if (tlv_find_tag(&ctxi, TAG_PWS_METADATA, &meta) == true) {
        res_APDU[res_APDU_size++] = TAG_PWS_METADATA;
        res_APDU[res_APDU_size++] = (uint8_t)(meta.len);
        memcpy(res_APDU + res_APDU_size, meta.data, meta.len); res_APDU_size += meta.len;
    }
    if (tlv_find_tag(&ctxi, TAG_PROPERTY, &prop) == true) {
        res_APDU[res_APDU_size++] = TAG_PROPERTY;
        res_APDU[res_APDU_size++] = (uint8_t)(prop.len);
        memcpy(res_APDU + res_APDU_size, prop.data, prop.len); res_APDU_size += prop.len;
    }
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
