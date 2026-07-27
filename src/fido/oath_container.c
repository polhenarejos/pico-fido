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
#include "oath_container.h"
#include "object_container_store.h"
#include "object_policy.h"
#include "object_provider.h"

#define FIDO_OATH_MANIFEST_SLOT_0_PREFIX 0xb0u
#define FIDO_OATH_MANIFEST_SLOT_1_PREFIX 0xb1u
#define FIDO_OATH_CREDENTIAL_SLOT_0_PREFIX 0xb2u
#define FIDO_OATH_METADATA_SLOT_0_PREFIX 0xb3u
#define FIDO_OATH_CREDENTIAL_SLOT_1_PREFIX 0xb4u
#define FIDO_OATH_METADATA_SLOT_1_PREFIX 0xb5u
#define FIDO_OATH_CONTAINER_MARKER_SIZE 8u
#define FIDO_OATH_CONTAINER_MARKER_VERSION_OFFSET 4u
#define FIDO_OATH_CONTAINER_MARKER_SLOT_OFFSET 5u
#define FIDO_OATH_CONTAINER_MARKER_RESERVED_0_OFFSET 6u
#define FIDO_OATH_CONTAINER_MARKER_RESERVED_1_OFFSET 7u
#define FIDO_OATH_CONTAINER_MARKER_VERSION 1u
#define FIDO_OATH_CONTAINER_MARKER_RESERVED_VALUE 0u
#define FIDO_OATH_CONTAINER_COMMIT_TIMEOUT_MS 5000u
#define FIDO_OATH_POLICY_ID 0x0201u

static const uint8_t oath_container_marker_magic[4] = { 'P', 'K', 'O', '1' };
static const uint8_t oath_internal_policy[] = {
    FILE_OBJECT_POLICY_FORMAT_VERSION, 1,
    0x1f, 0xff, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
};

static uint16_t oath_manifest_fid(uint8_t slot, uint8_t manifest_slot) {
    uint8_t prefix = manifest_slot == 0 ? FIDO_OATH_MANIFEST_SLOT_0_PREFIX : FIDO_OATH_MANIFEST_SLOT_1_PREFIX;
    return (uint16_t)((prefix << 8) | slot);
}

static uint8_t oath_record_prefix(uint8_t manifest_slot, uint16_t object_type) {
    if (manifest_slot == 0) {
        return object_type == FIDO_OATH_OBJECT_CREDENTIAL ? FIDO_OATH_CREDENTIAL_SLOT_0_PREFIX : FIDO_OATH_METADATA_SLOT_0_PREFIX;
    }
    return object_type == FIDO_OATH_OBJECT_CREDENTIAL ? FIDO_OATH_CREDENTIAL_SLOT_1_PREFIX : FIDO_OATH_METADATA_SLOT_1_PREFIX;
}

static uint16_t oath_record_fid(uint8_t slot, uint8_t manifest_slot, uint16_t object_type) {
    return (uint16_t)((oath_record_prefix(manifest_slot, object_type) << 8) | slot);
}

static bool oath_object_type_valid(uint16_t object_type) {
    return object_type == FIDO_OATH_OBJECT_CREDENTIAL || object_type == FIDO_OATH_OBJECT_METADATA;
}

static bool oath_record_id_valid(uint8_t slot, const file_object_descriptor_t *object) {
    if (!oath_object_type_valid(object->object_type) || object->record_id > UINT16_MAX) {
        return false;
    }
    uint16_t record_fid = (uint16_t)object->record_id;
    return record_fid == oath_record_fid(slot, 0, object->object_type) || record_fid == oath_record_fid(slot, 1, object->object_type);
}

static int oath_replace_file(uint16_t fid, const uint8_t *data, uint32_t data_size) {
    file_t *file = file_search(fid);
    if (file && file_delete_no_commit(file) != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    file = file_new(fid);
    if (!file) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    return file_put_data(file, CONST_BYTE_ARRAY(data, data_size));
}

bool oath_container_is_marker(const file_t *file) {
    if (!file_has_data(file) || file_get_size(file) != FIDO_OATH_CONTAINER_MARKER_SIZE) {
        return false;
    }
    const uint8_t *data = file_get_data(file);
    return memcmp(data, oath_container_marker_magic, sizeof(oath_container_marker_magic)) == 0 &&
           data[FIDO_OATH_CONTAINER_MARKER_VERSION_OFFSET] == FIDO_OATH_CONTAINER_MARKER_VERSION &&
           data[FIDO_OATH_CONTAINER_MARKER_SLOT_OFFSET] == (uint8_t)file->fid &&
           data[FIDO_OATH_CONTAINER_MARKER_RESERVED_0_OFFSET] == FIDO_OATH_CONTAINER_MARKER_RESERVED_VALUE &&
           data[FIDO_OATH_CONTAINER_MARKER_RESERVED_1_OFFSET] == FIDO_OATH_CONTAINER_MARKER_RESERVED_VALUE;
}

static int oath_policy_hash(void *ctx, uint16_t policy_id, uint8_t hash[FILE_OBJECT_POLICY_HASH_SIZE]) {
    (void)ctx;
    if (policy_id != FIDO_OATH_POLICY_ID) {
        return PICOKEYS_WRONG_DATA;
    }
    return file_object_policy_hash(CONST_BYTE_ARRAY(oath_internal_policy, sizeof(oath_internal_policy)), hash);
}

static uint16_t oath_layout_manifest_fid(void *ctx, uint32_t container_id, uint8_t slot) {
    (void)ctx;
    return oath_manifest_fid((uint8_t)container_id, slot);
}

static int oath_layout_record_fid(void *ctx, uint32_t container_id, const file_object_descriptor_t *object, uint16_t *fid) {
    (void)ctx;
    if (!object || !fid || container_id > UINT8_MAX || !oath_record_id_valid((uint8_t)container_id, object)) {
        return PICOKEYS_WRONG_DATA;
    }
    *fid = (uint16_t)object->record_id;
    return PICOKEYS_OK;
}

static int oath_layout_record_allocate(void *ctx, uint32_t container_id, uint8_t target_slot, const file_object_container_write_t *write, const file_object_authenticator_t *auth, uint64_t *record_id, uint16_t *fid) {
    (void)ctx;
    (void)auth;
    if (!write || !record_id || !fid || container_id > UINT8_MAX || !oath_object_type_valid(write->object_type)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *fid = oath_record_fid((uint8_t)container_id, target_slot, write->object_type);
    *record_id = *fid;
    return PICOKEYS_OK;
}

static bool oath_layout_write_valid(void *ctx, const file_object_container_write_t *write) {
    (void)ctx;
    if (!oath_object_type_valid(write->object_type) || write->object_tag != 0 || write->policy_id != FIDO_OATH_POLICY_ID || write->key_domain != 0) {
        return false;
    }
    if (write->object_type == FIDO_OATH_OBJECT_CREDENTIAL) {
        return write->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET && write->flags == (FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP) && write->transaction_group == 1;
    }
    return write->protection == FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC && write->flags == (FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP) && write->transaction_group == 1;
}

static bool oath_layout_descriptor_valid(void *ctx, uint32_t container_id, const file_object_descriptor_t *object) {
    (void)ctx;
    if (container_id > UINT8_MAX || object->object_tag != 0 || object->policy_id != FIDO_OATH_POLICY_ID || object->key_domain != 0 || !oath_record_id_valid((uint8_t)container_id, object)) {
        return false;
    }
    if (object->object_type == FIDO_OATH_OBJECT_CREDENTIAL) {
        return object->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET && object->flags == (FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP) && object->transaction_group == 1;
    }
    return object->protection == FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC && object->flags == (FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP) && object->transaction_group == 1;
}

static int oath_marker_write(uint8_t slot) {
    uint8_t marker[FIDO_OATH_CONTAINER_MARKER_SIZE] = { 0 };
    memcpy(marker, oath_container_marker_magic, sizeof(oath_container_marker_magic));
    marker[FIDO_OATH_CONTAINER_MARKER_VERSION_OFFSET] = FIDO_OATH_CONTAINER_MARKER_VERSION;
    marker[FIDO_OATH_CONTAINER_MARKER_SLOT_OFFSET] = slot;
    int r = oath_replace_file((uint16_t)(EF_OATH_CRED + slot), marker, sizeof(marker));
    if (r != PICOKEYS_OK) {
        return r;
    }
    return flash_commit_sync(FIDO_OATH_CONTAINER_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}

static int oath_layout_activate(void *ctx, uint32_t container_id) {
    (void)ctx;
    uint8_t slot = (uint8_t)container_id;
    if (oath_container_is_marker(file_search((uint16_t)(EF_OATH_CRED + slot)))) {
        return PICOKEYS_OK;
    }
    return oath_marker_write(slot);
}

static int oath_layout_retire(void *ctx, uint32_t container_id, const file_object_container_state_t *state, const file_object_manifest_t *next, uint8_t current_slot, uint8_t target_slot) {
    (void)ctx;
    (void)state;
    (void)current_slot;
    uint8_t slot = (uint8_t)container_id;
    for (uint8_t manifest_slot = 0; manifest_slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; manifest_slot++) {
        if (manifest_slot != target_slot) {
            file_t *manifest = file_search(oath_manifest_fid(slot, manifest_slot));
            if (manifest) {
                file_delete_no_commit(manifest);
            }
        }
        for (uint16_t object_type = FIDO_OATH_OBJECT_CREDENTIAL; object_type <= FIDO_OATH_OBJECT_METADATA; object_type++) {
            uint16_t record_fid = oath_record_fid(slot, manifest_slot, object_type);
            if (!file_object_container_references(next, record_fid)) {
                file_t *record = file_search(record_fid);
                if (record) {
                    file_delete_no_commit(record);
                }
            }
        }
    }
    flash_commit();
    return PICOKEYS_OK;
}

static int oath_layout_deactivate(void *ctx, uint32_t container_id) {
    (void)ctx;
    uint8_t slot = (uint8_t)container_id;
    for (uint8_t manifest_slot = 0; manifest_slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; manifest_slot++) {
        for (uint16_t object_type = FIDO_OATH_OBJECT_CREDENTIAL; object_type <= FIDO_OATH_OBJECT_METADATA; object_type++) {
            file_t *record = file_search(oath_record_fid(slot, manifest_slot, object_type));
            if (record) {
                file_delete_no_commit(record);
            }
        }
    }
    file_t *marker = file_search((uint16_t)(EF_OATH_CRED + slot));
    if (marker) {
        return file_delete_no_commit(marker);
    }
    return PICOKEYS_OK;
}

static const file_object_container_layout_t oath_container_layout = {
    .namespace_id = FIDO_OATH_OBJECT_NAMESPACE,
    .container_kind = FIDO_OATH_CONTAINER_KIND,
    .commit_timeout_ms = FIDO_OATH_CONTAINER_COMMIT_TIMEOUT_MS,
    .manifest_fid = oath_layout_manifest_fid,
    .record_fid = oath_layout_record_fid,
    .record_allocate = oath_layout_record_allocate,
    .policy_hash = oath_policy_hash,
    .write_valid = oath_layout_write_valid,
    .descriptor_valid = oath_layout_descriptor_valid,
    .activate = oath_layout_activate,
    .deactivate = oath_layout_deactivate,
    .retire = oath_layout_retire
};

static bool oath_crypto(file_object_container_crypto_t *primary) {
    primary->auth = fido_oath_object_manifest_authenticator();
    primary->protector = fido_oath_object_record_protector();
    return primary->auth && primary->protector;
}

bool oath_container_can_create(uint8_t slot) {
    bool manifest_present = false;
    for (uint8_t manifest_slot = 0; manifest_slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; manifest_slot++) {
        manifest_present |= file_search(oath_manifest_fid(slot, manifest_slot)) != NULL;
    }
    if (manifest_present) {
        file_object_container_crypto_t primary;
        file_object_container_state_t state;
        if (!oath_crypto(&primary) || file_object_container_load(&oath_container_layout, slot, &primary, NULL, &state) != PICOKEYS_OK) {
            return false;
        }
        return file_object_container_validate(&oath_container_layout, slot, &state.candidates[state.current_slot], state.crypto.protector) == PICOKEYS_OK;
    }

    static const uint8_t record_magic[4] = { 'P', 'K', 'O', 'R' };
    for (uint8_t manifest_slot = 0; manifest_slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; manifest_slot++) {
        for (uint16_t object_type = FIDO_OATH_OBJECT_CREDENTIAL; object_type <= FIDO_OATH_OBJECT_METADATA; object_type++) {
            file_t *record = file_search(oath_record_fid(slot, manifest_slot, object_type));
            if (record && (!file_has_data(record) || file_get_size(record) < sizeof(record_magic) || memcmp(file_get_data(record), record_magic, sizeof(record_magic)) != 0)) {
                return false;
            }
        }
    }
    return true;
}

static int oath_container_write(uint8_t slot, const uint8_t *credential, size_t credential_size, const uint8_t *metadata, size_t metadata_size) {
    if ((!credential && credential_size > 0) || (!metadata && metadata_size > 0) || credential_size > UINT32_MAX || metadata_size > UINT32_MAX) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_crypto_t primary;
    if (!oath_crypto(&primary)) {
        return PICOKEYS_EXEC_ERROR;
    }
    if (!file_has_data(file_search(oath_manifest_fid(slot, 0))) && !file_has_data(file_search(oath_manifest_fid(slot, 1))) && !oath_container_can_create(slot)) {
        return PICOKEYS_WRONG_DATA;
    }
    const file_object_container_write_t writes[] = {
        {
            .object_type = FIDO_OATH_OBJECT_CREDENTIAL,
            .data = CONST_BYTE_ARRAY(credential, credential_size),
            .policy_id = FIDO_OATH_POLICY_ID,
            .protection = FILE_OBJECT_PROTECTION_AEAD_SECRET,
            .flags = FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP,
            .transaction_group = 1
        },
        {
            .object_type = FIDO_OATH_OBJECT_METADATA,
            .data = CONST_BYTE_ARRAY(metadata, metadata_size),
            .policy_id = FIDO_OATH_POLICY_ID,
            .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC,
            .flags = FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_TRANSACTION_GROUP,
            .transaction_group = 1
        }
    };
    return file_object_container_update(&oath_container_layout, slot, writes, sizeof(writes) / sizeof(writes[0]), &primary, NULL);
}

int oath_container_create(uint8_t slot, const uint8_t *credential, size_t credential_size, const uint8_t *metadata, size_t metadata_size) {
    if (file_has_data(file_search((uint16_t)(EF_OATH_CRED + slot)))) {
        return PICOKEYS_WRONG_DATA;
    }
    return oath_container_write(slot, credential, credential_size, metadata, metadata_size);
}

int oath_container_object_size(uint8_t slot, uint16_t object_type, uint32_t *object_size) {
    if (!object_size || !oath_object_type_valid(object_type)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_crypto_t primary;
    if (!oath_crypto(&primary)) {
        return PICOKEYS_EXEC_ERROR;
    }
    return file_object_container_object_size(&oath_container_layout, slot, object_type, 0, &primary, NULL, NULL, NULL, object_size);
}

int oath_container_read(uint8_t slot, uint16_t object_type, byte_buffer_t *data) {
    if (!data || !oath_object_type_valid(object_type)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_crypto_t primary;
    if (!oath_crypto(&primary)) {
        return PICOKEYS_EXEC_ERROR;
    }
    return file_object_container_read(&oath_container_layout, slot, object_type, 0, &primary, NULL, NULL, NULL, data);
}

int oath_container_update(uint8_t slot, const uint8_t *credential, size_t credential_size, const uint8_t *metadata, size_t metadata_size) {
    if (!oath_container_is_marker(file_search((uint16_t)(EF_OATH_CRED + slot)))) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    return oath_container_write(slot, credential, credential_size, metadata, metadata_size);
}

int oath_container_delete(uint8_t slot) {
    if (!oath_container_is_marker(file_search((uint16_t)(EF_OATH_CRED + slot)))) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    file_object_container_crypto_t primary;
    if (!oath_crypto(&primary)) {
        return PICOKEYS_EXEC_ERROR;
    }
    return file_object_container_delete(&oath_container_layout, slot, &primary, NULL);
}

int oath_container_purge(uint8_t slot) {
    if (!oath_container_is_marker(file_search((uint16_t)(EF_OATH_CRED + slot)))) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    for (uint8_t manifest_slot = 0; manifest_slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; manifest_slot++) {
        file_t *manifest = file_search(oath_manifest_fid(slot, manifest_slot));
        if (manifest) {
            file_delete_no_commit(manifest);
        }
    }
    int r = oath_layout_deactivate(NULL, slot);
    if (r != PICOKEYS_OK) {
        return r;
    }
    return flash_commit_sync(FIDO_OATH_CONTAINER_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}
