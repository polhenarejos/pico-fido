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
#include "files.h"
#include "object_provider.h"
#include "otp_container.h"

#include "object_container_store.h"
#include "object_policy.h"

#include <mbedtls/platform_util.h>

#define FIDO_OTP_CONTAINER_KIND 0x0003u
#define FIDO_OTP_OBJECT_SECRET 0x0001u
#define FIDO_OTP_OBJECT_METADATA 0x0002u
#define FIDO_OTP_OBJECT_INDEX 0x0003u
#define FIDO_OTP_POLICY_ID 0x0400u
#define FIDO_OTP_CONTAINER_ID 0u
#define FIDO_OTP_TRANSACTION_GROUP 1u
#define FIDO_OTP_MANIFEST_PREFIX_0 0xB600u
#define FIDO_OTP_MANIFEST_PREFIX_1 0xB700u
#define FIDO_OTP_RECORD_PREFIX_0 0xB800u
#define FIDO_OTP_RECORD_PREFIX_1 0xB900u
#define FIDO_OTP_CONTAINER_COMMIT_TIMEOUT_MS 5000u
#define FIDO_OTP_CONTAINER_MARKER_SIZE 8u
#define FIDO_OTP_CONTAINER_MARKER_VERSION 1u
#define FIDO_OTP_CONTAINER_MARKER_VERSION_OFFSET 4u
#define FIDO_OTP_CONTAINER_MARKER_SLOT_OFFSET 5u
#define FIDO_OTP_CONTAINER_MARKER_RESERVED_0_OFFSET 6u
#define FIDO_OTP_CONTAINER_MARKER_RESERVED_1_OFFSET 7u
#define FIDO_OTP_CONTAINER_MARKER_RESERVED_VALUE 0u
#define FIDO_OTP_RECORD_INDEX_METADATA_BASE FIDO_OTP_SLOT_COUNT
#define FIDO_OTP_RECORD_INDEX_ACTIVE (FIDO_OTP_SLOT_COUNT * 2u)
#define FIDO_OTP_RECORD_COUNT (FIDO_OTP_RECORD_INDEX_ACTIVE + 1u)
#define FIDO_OTP_SECRET_MAX_SIZE 128u
#define FIDO_OTP_METADATA_MAX_SIZE 64u

static const uint8_t otp_container_marker_magic[] = { 'P', 'K', 'T', '1' };
static const uint8_t otp_internal_policy[] = {
    FILE_OBJECT_POLICY_FORMAT_VERSION, 1,
    0x1f, 0xff, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
};

typedef struct otp_container_slot {
    uint8_t secret[FIDO_OTP_SECRET_MAX_SIZE];
    uint8_t metadata[FIDO_OTP_METADATA_MAX_SIZE];
    size_t secret_size;
    size_t metadata_size;
    bool stored;
} otp_container_slot_t;

static bool otp_slot_valid(uint8_t slot) {
    return slot < FIDO_OTP_SLOT_COUNT;
}

static uint16_t otp_manifest_fid(uint8_t slot) {
    return slot == 0 ? FIDO_OTP_MANIFEST_PREFIX_0 : FIDO_OTP_MANIFEST_PREFIX_1;
}

static uint8_t otp_record_index(uint16_t object_type, uint16_t object_tag) {
    if (object_type == FIDO_OTP_OBJECT_SECRET) {
        return (uint8_t)object_tag;
    }
    if (object_type == FIDO_OTP_OBJECT_METADATA) {
        return (uint8_t)(FIDO_OTP_RECORD_INDEX_METADATA_BASE + object_tag);
    }
    return FIDO_OTP_RECORD_INDEX_ACTIVE;
}

static uint16_t otp_record_fid(uint8_t slot, uint16_t object_type, uint16_t object_tag) {
    uint16_t prefix = slot == 0 ? FIDO_OTP_RECORD_PREFIX_0 : FIDO_OTP_RECORD_PREFIX_1;
    return prefix | otp_record_index(object_type, object_tag);
}

static bool otp_object_identity_valid(uint16_t object_type, uint16_t object_tag) {
    if (object_type == FIDO_OTP_OBJECT_INDEX) {
        return object_tag == 0;
    }
    return (object_type == FIDO_OTP_OBJECT_SECRET || object_type == FIDO_OTP_OBJECT_METADATA) && object_tag < FIDO_OTP_SLOT_COUNT;
}

static bool otp_record_id_valid(const file_object_descriptor_t *object) {
    uint16_t expected0 = otp_record_fid(0, object->object_type, object->object_tag);
    uint16_t expected1 = otp_record_fid(1, object->object_type, object->object_tag);
    return object->record_id == expected0 || object->record_id == expected1;
}

static int otp_policy_hash(void *ctx, uint16_t policy_id, uint8_t hash[FILE_OBJECT_POLICY_HASH_SIZE]) {
    (void)ctx;
    if (policy_id != FIDO_OTP_POLICY_ID) {
        return PICOKEYS_WRONG_DATA;
    }
    return file_object_policy_hash(CONST_BYTE_ARRAY(otp_internal_policy, sizeof(otp_internal_policy)), hash);
}

static uint16_t otp_layout_manifest_fid(void *ctx, uint32_t container_id, uint8_t slot) {
    (void)ctx;
    (void)container_id;
    return otp_manifest_fid(slot);
}

static int otp_layout_record_fid(void *ctx, uint32_t container_id, const file_object_descriptor_t *object, uint16_t *fid) {
    (void)ctx;
    (void)container_id;
    if (!object || !fid || !otp_object_identity_valid(object->object_type, object->object_tag) || !otp_record_id_valid(object)) {
        return PICOKEYS_WRONG_DATA;
    }
    *fid = (uint16_t)object->record_id;
    return PICOKEYS_OK;
}

static int otp_layout_record_allocate(void *ctx, uint32_t container_id, uint8_t target_slot, const file_object_container_write_t *write, const file_object_authenticator_t *auth, uint64_t *record_id, uint16_t *fid) {
    (void)ctx;
    (void)container_id;
    (void)auth;
    if (!write || !record_id || !fid || !otp_object_identity_valid(write->object_type, write->object_tag)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *fid = otp_record_fid(target_slot, write->object_type, write->object_tag);
    *record_id = *fid;
    return PICOKEYS_OK;
}

static bool otp_layout_write_valid(void *ctx, const file_object_container_write_t *write) {
    (void)ctx;
    if (!otp_object_identity_valid(write->object_type, write->object_tag) || write->policy_id != FIDO_OTP_POLICY_ID || write->key_domain != 0 || write->transaction_group != FIDO_OTP_TRANSACTION_GROUP) {
        return false;
    }
    if (write->object_type == FIDO_OTP_OBJECT_SECRET) {
        return write->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET && write->flags == (FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP);
    }
    return write->protection == FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC && write->flags == (FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP);
}

static bool otp_layout_descriptor_valid(void *ctx, uint32_t container_id, const file_object_descriptor_t *object) {
    (void)ctx;
    (void)container_id;
    if (!otp_object_identity_valid(object->object_type, object->object_tag) || object->policy_id != FIDO_OTP_POLICY_ID || object->key_domain != 0 || object->transaction_group != FIDO_OTP_TRANSACTION_GROUP || !otp_record_id_valid(object)) {
        return false;
    }
    if (object->object_type == FIDO_OTP_OBJECT_SECRET) {
        return object->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET && object->flags == (FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP);
    }
    return object->protection == FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC && object->flags == (FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP);
}

static int otp_layout_activate(void *ctx, uint32_t container_id) {
    (void)ctx;
    (void)container_id;
    return PICOKEYS_OK;
}

static int otp_layout_retire(void *ctx, uint32_t container_id, const file_object_container_state_t *state, const file_object_manifest_t *next, uint8_t current_slot, uint8_t target_slot) {
    (void)ctx;
    (void)container_id;
    (void)state;
    (void)current_slot;
    for (uint8_t slot = 0; slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; slot++) {
        if (slot != target_slot) {
            file_t *manifest = file_search(otp_manifest_fid(slot));
            if (manifest) {
                file_delete_no_commit(manifest);
            }
        }
        for (uint8_t index = 0; index < FIDO_OTP_RECORD_COUNT; index++) {
            uint16_t fid = (slot == 0 ? FIDO_OTP_RECORD_PREFIX_0 : FIDO_OTP_RECORD_PREFIX_1) | index;
            if (!file_object_container_references(next, fid)) {
                file_t *record = file_search(fid);
                if (record) {
                    file_delete_no_commit(record);
                }
            }
        }
    }
    flash_commit();
    return PICOKEYS_OK;
}

static const file_object_container_layout_t otp_container_layout = {
    .namespace_id = FIDO_OTP_OBJECT_NAMESPACE,
    .container_kind = FIDO_OTP_CONTAINER_KIND,
    .commit_timeout_ms = FIDO_OTP_CONTAINER_COMMIT_TIMEOUT_MS,
    .manifest_fid = otp_layout_manifest_fid,
    .record_fid = otp_layout_record_fid,
    .record_allocate = otp_layout_record_allocate,
    .policy_hash = otp_policy_hash,
    .write_valid = otp_layout_write_valid,
    .descriptor_valid = otp_layout_descriptor_valid,
    .activate = otp_layout_activate,
    .retire = otp_layout_retire
};

static bool otp_crypto(file_object_container_crypto_t *primary) {
    primary->auth = fido_otp_object_manifest_authenticator();
    primary->protector = fido_otp_object_record_protector();
    return primary->auth && primary->protector;
}

static bool otp_container_storage_available(void) {
    bool manifest_present = false;
    for (uint8_t slot = 0; slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; slot++) {
        file_t *manifest = file_search(otp_manifest_fid(slot));
        if (manifest && !file_has_data(manifest)) {
            return false;
        }
        manifest_present |= manifest != NULL;
    }
    if (manifest_present) {
        return true;
    }
    static const uint8_t record_magic[] = { 'P', 'K', 'O', 'R' };
    for (uint8_t slot = 0; slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; slot++) {
        for (uint8_t index = 0; index < FIDO_OTP_RECORD_COUNT; index++) {
            uint16_t fid = (slot == 0 ? FIDO_OTP_RECORD_PREFIX_0 : FIDO_OTP_RECORD_PREFIX_1) | index;
            file_t *record = file_search(fid);
            if (record && (!file_has_data(record) || file_get_size(record) < sizeof(record_magic) || memcmp(file_get_data(record), record_magic, sizeof(record_magic)) != 0)) {
                return false;
            }
        }
    }
    return true;
}

static int otp_active_slots_read(uint8_t *active) {
    file_object_container_crypto_t primary;
    if (!active || !otp_crypto(&primary)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    byte_buffer_t output = BYTE_BUFFER(active, 1);
    int r = file_object_container_read(&otp_container_layout, FIDO_OTP_CONTAINER_ID, FIDO_OTP_OBJECT_INDEX, 0, &primary, NULL, NULL, NULL, &output);
    if (r == PICOKEYS_OK && output.len != 1) {
        return PICOKEYS_WRONG_LENGTH;
    }
    return r;
}

static int otp_marker_replace(uint8_t slot, bool present) {
    file_t *marker = file_search((uint16_t)(EF_OTP_SLOT1 + slot));
    if (!present) {
        if (marker && otp_container_is_marker(marker)) {
            file_delete_no_commit(marker);
            flash_commit();
        }
        return PICOKEYS_OK;
    }
    if (marker && !otp_container_is_marker(marker)) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t data[FIDO_OTP_CONTAINER_MARKER_SIZE] = { 0 };
    memcpy(data, otp_container_marker_magic, sizeof(otp_container_marker_magic));
    data[FIDO_OTP_CONTAINER_MARKER_VERSION_OFFSET] = FIDO_OTP_CONTAINER_MARKER_VERSION;
    data[FIDO_OTP_CONTAINER_MARKER_SLOT_OFFSET] = slot;
    if (marker) {
        file_delete_no_commit(marker);
    }
    marker = file_new((uint16_t)(EF_OTP_SLOT1 + slot));
    if (!marker) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    int r = file_put_data(marker, CONST_BYTE_ARRAY(data, sizeof(data)));
    if (r != PICOKEYS_OK) {
        return r;
    }
    return flash_commit_sync(FIDO_OTP_CONTAINER_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}

bool otp_container_is_marker(const file_t *file) {
    if (!file_has_data(file) || file->fid < EF_OTP_SLOT1 || file->fid >= EF_OTP_SLOT1 + FIDO_OTP_SLOT_COUNT || file_get_size(file) != FIDO_OTP_CONTAINER_MARKER_SIZE) {
        return false;
    }
    const uint8_t *data = file_get_data(file);
    return memcmp(data, otp_container_marker_magic, sizeof(otp_container_marker_magic)) == 0 &&
           data[FIDO_OTP_CONTAINER_MARKER_VERSION_OFFSET] == FIDO_OTP_CONTAINER_MARKER_VERSION &&
           data[FIDO_OTP_CONTAINER_MARKER_SLOT_OFFSET] == (uint8_t)(file->fid - EF_OTP_SLOT1) &&
           data[FIDO_OTP_CONTAINER_MARKER_RESERVED_0_OFFSET] == FIDO_OTP_CONTAINER_MARKER_RESERVED_VALUE &&
           data[FIDO_OTP_CONTAINER_MARKER_RESERVED_1_OFFSET] == FIDO_OTP_CONTAINER_MARKER_RESERVED_VALUE;
}

bool otp_container_has_slot(uint8_t slot) {
    uint8_t active = 0;
    return otp_slot_valid(slot) && otp_active_slots_read(&active) == PICOKEYS_OK && (active & (1u << slot)) != 0;
}

static file_object_container_write_t otp_write(uint16_t object_type, uint16_t object_tag, const uint8_t *data, size_t data_size) {
    file_object_container_write_t write = {
        .object_type = object_type,
        .object_tag = object_tag,
        .data = CONST_BYTE_ARRAY(data, data_size),
        .policy_id = FIDO_OTP_POLICY_ID,
        .protection = object_type == FIDO_OTP_OBJECT_SECRET ? FILE_OBJECT_PROTECTION_AEAD_SECRET : FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC,
        .flags = object_type == FIDO_OTP_OBJECT_SECRET ? FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP : FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP,
        .transaction_group = FIDO_OTP_TRANSACTION_GROUP
    };
    return write;
}

static int otp_container_update(const file_object_container_write_t *writes, size_t write_count) {
    if (!otp_container_storage_available()) {
        return PICOKEYS_WRONG_DATA;
    }
    file_object_container_crypto_t primary;
    if (!otp_crypto(&primary)) {
        return PICOKEYS_EXEC_ERROR;
    }
    return file_object_container_update(&otp_container_layout, FIDO_OTP_CONTAINER_ID, writes, write_count, &primary, NULL);
}

static int otp_container_read_object(uint8_t slot, uint16_t object_type, byte_buffer_t *data) {
    file_object_container_crypto_t primary;
    if (!otp_crypto(&primary)) {
        return PICOKEYS_EXEC_ERROR;
    }
    return file_object_container_read(&otp_container_layout, FIDO_OTP_CONTAINER_ID, object_type, slot, &primary, NULL, NULL, NULL, data);
}

static int otp_container_bank_load(uint8_t *active, otp_container_slot_t slots[FIDO_OTP_SLOT_COUNT]) {
    if (!active || !slots) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    memset(slots, 0, sizeof(otp_container_slot_t) * FIDO_OTP_SLOT_COUNT);
    int r = otp_active_slots_read(active);
    if (r == PICOKEYS_ERR_FILE_NOT_FOUND) {
        *active = 0;
        return PICOKEYS_OK;
    }
    if (r != PICOKEYS_OK) {
        return r;
    }
    for (uint8_t slot = 0; slot < FIDO_OTP_SLOT_COUNT; slot++) {
        byte_buffer_t secret = BYTE_BUFFER(slots[slot].secret, sizeof(slots[slot].secret));
        r = otp_container_read_object(slot, FIDO_OTP_OBJECT_SECRET, &secret);
        if (r == PICOKEYS_ERR_FILE_NOT_FOUND) {
            if ((*active & (1u << slot)) != 0) {
                return PICOKEYS_WRONG_DATA;
            }
            continue;
        }
        if (r != PICOKEYS_OK) {
            return r;
        }
        byte_buffer_t metadata = BYTE_BUFFER(slots[slot].metadata, sizeof(slots[slot].metadata));
        r = otp_container_read_object(slot, FIDO_OTP_OBJECT_METADATA, &metadata);
        if (r != PICOKEYS_OK) {
            return r;
        }
        slots[slot].secret_size = secret.len;
        slots[slot].metadata_size = metadata.len;
        slots[slot].stored = true;
    }
    return PICOKEYS_OK;
}

static int otp_container_bank_commit(uint8_t active, const otp_container_slot_t slots[FIDO_OTP_SLOT_COUNT]) {
    file_object_container_write_t writes[FIDO_OTP_RECORD_COUNT];
    size_t write_count = 0;
    for (uint8_t slot = 0; slot < FIDO_OTP_SLOT_COUNT; slot++) {
        if (!slots[slot].stored) {
            continue;
        }
        writes[write_count++] = otp_write(FIDO_OTP_OBJECT_SECRET, slot, slots[slot].secret, slots[slot].secret_size);
        writes[write_count++] = otp_write(FIDO_OTP_OBJECT_METADATA, slot, slots[slot].metadata, slots[slot].metadata_size);
    }
    writes[write_count++] = otp_write(FIDO_OTP_OBJECT_INDEX, 0, &active, sizeof(active));
    return otp_container_update(writes, write_count);
}

int otp_container_read_slot(uint8_t slot, byte_buffer_t *data) {
    if (!otp_slot_valid(slot) || !data || !otp_container_has_slot(slot)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    return otp_container_read_object(slot, FIDO_OTP_OBJECT_SECRET, data);
}

int otp_container_write_slot(uint8_t slot, const uint8_t *data, size_t data_size, const uint8_t *metadata, size_t metadata_size) {
    if (!otp_slot_valid(slot) || !data || !metadata || data_size > FIDO_OTP_SECRET_MAX_SIZE || metadata_size > FIDO_OTP_METADATA_MAX_SIZE) {
        return PICOKEYS_WRONG_DATA;
    }
    file_t *logical = file_search((uint16_t)(EF_OTP_SLOT1 + slot));
    if (file_has_data(logical) && !otp_container_is_marker(logical)) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t active = 0;
    otp_container_slot_t slots[FIDO_OTP_SLOT_COUNT];
    int r = otp_container_bank_load(&active, slots);
    if (r != PICOKEYS_OK) {
        mbedtls_platform_zeroize(slots, sizeof(slots));
        return r;
    }
    memcpy(slots[slot].secret, data, data_size);
    memcpy(slots[slot].metadata, metadata, metadata_size);
    slots[slot].secret_size = data_size;
    slots[slot].metadata_size = metadata_size;
    slots[slot].stored = true;
    active |= (uint8_t)(1u << slot);
    r = otp_container_bank_commit(active, slots);
    mbedtls_platform_zeroize(slots, sizeof(slots));
    return r == PICOKEYS_OK ? otp_marker_replace(slot, true) : r;
}

int otp_container_delete_slot(uint8_t slot) {
    if (!otp_slot_valid(slot) || !otp_container_has_slot(slot)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint8_t active = 0;
    otp_container_slot_t slots[FIDO_OTP_SLOT_COUNT];
    int r = otp_container_bank_load(&active, slots);
    if (r != PICOKEYS_OK) {
        mbedtls_platform_zeroize(slots, sizeof(slots));
        return r;
    }
    active &= (uint8_t)~(1u << slot);
    r = otp_container_bank_commit(active, slots);
    mbedtls_platform_zeroize(slots, sizeof(slots));
    return r == PICOKEYS_OK ? otp_marker_replace(slot, false) : r;
}

int otp_container_swap_slots(uint8_t slot1, bool present1, const uint8_t *data1, size_t data1_size, const uint8_t *metadata1, size_t metadata1_size, uint8_t slot2, bool present2, const uint8_t *data2, size_t data2_size, const uint8_t *metadata2, size_t metadata2_size) {
    if (!otp_slot_valid(slot1) || !otp_slot_valid(slot2) || slot1 == slot2 || present1 != otp_container_has_slot(slot1) || present2 != otp_container_has_slot(slot2) || (present1 && (!data1 || !metadata1 || data1_size > FIDO_OTP_SECRET_MAX_SIZE || metadata1_size > FIDO_OTP_METADATA_MAX_SIZE)) || (present2 && (!data2 || !metadata2 || data2_size > FIDO_OTP_SECRET_MAX_SIZE || metadata2_size > FIDO_OTP_METADATA_MAX_SIZE))) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t active = 0;
    otp_container_slot_t slots[FIDO_OTP_SLOT_COUNT];
    int r = otp_container_bank_load(&active, slots);
    if (r != PICOKEYS_OK) {
        mbedtls_platform_zeroize(slots, sizeof(slots));
        return r;
    }
    if (present2) {
        memcpy(slots[slot1].secret, data2, data2_size);
        memcpy(slots[slot1].metadata, metadata2, metadata2_size);
        slots[slot1].secret_size = data2_size;
        slots[slot1].metadata_size = metadata2_size;
        slots[slot1].stored = true;
    }
    if (present1) {
        memcpy(slots[slot2].secret, data1, data1_size);
        memcpy(slots[slot2].metadata, metadata1, metadata1_size);
        slots[slot2].secret_size = data1_size;
        slots[slot2].metadata_size = metadata1_size;
        slots[slot2].stored = true;
    }
    active &= (uint8_t)~((1u << slot1) | (1u << slot2));
    if (present2) {
        active |= (uint8_t)(1u << slot1);
    }
    if (present1) {
        active |= (uint8_t)(1u << slot2);
    }
    r = otp_container_bank_commit(active, slots);
    mbedtls_platform_zeroize(slots, sizeof(slots));
    if (r != PICOKEYS_OK) {
        return r;
    }
    r = otp_marker_replace(slot1, present2);
    if (r == PICOKEYS_OK) {
        r = otp_marker_replace(slot2, present1);
    }
    return r;
}
