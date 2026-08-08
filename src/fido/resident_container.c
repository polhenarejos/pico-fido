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
#include "object_container_store.h"
#include "object_policy.h"
#include "object_provider.h"
#include "resident_container.h"

#define FIDO_RESIDENT_MANIFEST_SLOT_0_PREFIX 0xd1u
#define FIDO_RESIDENT_MANIFEST_SLOT_1_PREFIX 0xd2u
#define FIDO_RESIDENT_RECORD_SLOT_0_PREFIX 0xd3u
#define FIDO_RESIDENT_RECORD_SLOT_1_PREFIX 0xd7u
#define FIDO_RESIDENT_CONTAINER_MARKER_SIZE 8u
#define FIDO_RESIDENT_CONTAINER_MARKER_VERSION_OFFSET 4u
#define FIDO_RESIDENT_CONTAINER_MARKER_SLOT_OFFSET 5u
#define FIDO_RESIDENT_CONTAINER_MARKER_RESERVED_0_OFFSET 6u
#define FIDO_RESIDENT_CONTAINER_MARKER_RESERVED_1_OFFSET 7u
#define FIDO_RESIDENT_CONTAINER_MARKER_VERSION 1u
#define FIDO_RESIDENT_CONTAINER_MARKER_RESERVED_VALUE 0u
#define FIDO_RESIDENT_CONTAINER_COMMIT_TIMEOUT_MS 5000u
#define FIDO_RESIDENT_POLICY_ID 0x0200u

static const uint8_t resident_container_marker_magic[4] = { 'P', 'K', 'F', '1' };
static const uint8_t resident_internal_policy[] = {
    FILE_OBJECT_POLICY_FORMAT_VERSION, 1,
    0x1f, 0xff, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
};

static uint16_t resident_manifest_fid(uint8_t slot, uint8_t manifest_slot) {
    uint8_t prefix = manifest_slot == 0 ? FIDO_RESIDENT_MANIFEST_SLOT_0_PREFIX : FIDO_RESIDENT_MANIFEST_SLOT_1_PREFIX;
    return (uint16_t)((prefix << 8) | slot);
}

static uint16_t resident_record_fid(uint8_t slot, uint8_t manifest_slot, uint16_t object_type) {
    uint8_t prefix;
    if (object_type == FIDO_RESIDENT_OBJECT_METADATA) {
        prefix = manifest_slot == 0 ? 0xdbu : 0xdcu;
        return (uint16_t)((prefix << 8) | slot);
    }
    else {
        prefix = manifest_slot == 0 ? FIDO_RESIDENT_RECORD_SLOT_0_PREFIX : FIDO_RESIDENT_RECORD_SLOT_1_PREFIX;
    }
    return (uint16_t)(((prefix + object_type - 1u) << 8) | slot);
}

static bool resident_object_type_valid(uint16_t object_type) {
    return object_type >= FIDO_RESIDENT_OBJECT_RP_ID_HASH && object_type <= FIDO_RESIDENT_OBJECT_STATE;
}

static bool resident_record_id_valid(uint8_t slot, const file_object_descriptor_t *object) {
    if (!resident_object_type_valid(object->object_type) || object->record_id > UINT16_MAX) {
        return false;
    }
    uint16_t record_fid = (uint16_t)object->record_id;
    return record_fid == resident_record_fid(slot, 0, object->object_type) || record_fid == resident_record_fid(slot, 1, object->object_type);
}

static int resident_replace_file(uint16_t fid, const uint8_t *data, uint32_t data_size) {
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

bool resident_container_is_marker(const file_t *file) {
    if (!file_has_data(file) || file_get_size(file) != FIDO_RESIDENT_CONTAINER_MARKER_SIZE) {
        return false;
    }
    const uint8_t *data = file_get_data(file);
    return memcmp(data, resident_container_marker_magic, sizeof(resident_container_marker_magic)) == 0 &&
           data[FIDO_RESIDENT_CONTAINER_MARKER_VERSION_OFFSET] == FIDO_RESIDENT_CONTAINER_MARKER_VERSION &&
           data[FIDO_RESIDENT_CONTAINER_MARKER_SLOT_OFFSET] == (uint8_t) file->fid &&
           data[FIDO_RESIDENT_CONTAINER_MARKER_RESERVED_0_OFFSET] == FIDO_RESIDENT_CONTAINER_MARKER_RESERVED_VALUE &&
           data[FIDO_RESIDENT_CONTAINER_MARKER_RESERVED_1_OFFSET] == FIDO_RESIDENT_CONTAINER_MARKER_RESERVED_VALUE;
}

static int resident_policy_hash(void *ctx, uint16_t policy_id, uint8_t hash[FILE_OBJECT_POLICY_HASH_SIZE]) {
    (void)ctx;
    if (policy_id != FIDO_RESIDENT_POLICY_ID) {
        return PICOKEYS_WRONG_DATA;
    }
    return file_object_policy_hash(CONST_BYTE_ARRAY(resident_internal_policy, sizeof(resident_internal_policy)), hash);
}

static uint16_t resident_layout_manifest_fid(void *ctx, uint32_t container_id, uint8_t slot) {
    (void)ctx;
    return resident_manifest_fid((uint8_t)container_id, slot);
}

static int resident_layout_record_fid(void *ctx, uint32_t container_id, const file_object_descriptor_t *object, uint16_t *fid) {
    (void)ctx;
    if (!object || !fid || container_id > UINT8_MAX || !resident_record_id_valid((uint8_t)container_id, object)) {
        return PICOKEYS_WRONG_DATA;
    }
    *fid = (uint16_t)object->record_id;
    return PICOKEYS_OK;
}

static int resident_layout_record_allocate(void *ctx, uint32_t container_id, uint8_t target_slot, const file_object_container_write_t *write, const file_object_authenticator_t *auth, uint64_t *record_id, uint16_t *fid) {
    (void)ctx;
    (void)auth;
    if (!write || !record_id || !fid || container_id > UINT8_MAX || !resident_object_type_valid(write->object_type)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *fid = resident_record_fid((uint8_t)container_id, target_slot, write->object_type);
    *record_id = *fid;
    return PICOKEYS_OK;
}

static bool resident_layout_write_valid(void *ctx, const file_object_container_write_t *write) {
    (void)ctx;
    return resident_object_type_valid(write->object_type) && write->object_tag == 0 && write->policy_id == FIDO_RESIDENT_POLICY_ID && write->key_domain == 0;
}

static bool resident_layout_descriptor_valid(void *ctx, uint32_t container_id, const file_object_descriptor_t *object) {
    (void)ctx;
    return container_id <= UINT8_MAX && object->object_tag == 0 && resident_record_id_valid((uint8_t)container_id, object);
}

static int resident_marker_write(uint8_t slot);

static int resident_marker_write(uint8_t slot) {
    uint8_t marker[FIDO_RESIDENT_CONTAINER_MARKER_SIZE] = { 0 };
    memcpy(marker, resident_container_marker_magic, sizeof(resident_container_marker_magic));
    marker[FIDO_RESIDENT_CONTAINER_MARKER_VERSION_OFFSET] = FIDO_RESIDENT_CONTAINER_MARKER_VERSION;
    marker[FIDO_RESIDENT_CONTAINER_MARKER_SLOT_OFFSET] = slot;
    int r = resident_replace_file((uint16_t)(EF_CRED + slot), marker, sizeof(marker));
    if (r != PICOKEYS_OK) {
        return r;
    }
    return flash_commit_sync(FIDO_RESIDENT_CONTAINER_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}

static int resident_layout_activate(void *ctx, uint32_t container_id) {
    (void)ctx;
    uint8_t slot = (uint8_t)container_id;
    if (resident_container_is_marker(file_search((uint16_t)(EF_CRED + slot)))) {
        return PICOKEYS_OK;
    }
    return resident_marker_write(slot);
}

static int resident_layout_retire(void *ctx, uint32_t container_id, const file_object_container_state_t *state, const file_object_manifest_t *next, uint8_t current_slot, uint8_t target_slot) {
    (void)ctx;
    (void)state;
    (void)current_slot;
    uint8_t slot = (uint8_t)container_id;
    for (uint8_t manifest_slot = 0; manifest_slot < 2; manifest_slot++) {
        if (manifest_slot != target_slot) {
            file_t *manifest = file_search(resident_manifest_fid(slot, manifest_slot));
            if (manifest) {
                file_delete_no_commit(manifest);
            }
        }
        for (uint16_t object_type = FIDO_RESIDENT_OBJECT_RP_ID_HASH; object_type <= FIDO_RESIDENT_OBJECT_STATE; object_type++) {
            uint16_t record_fid = resident_record_fid(slot, manifest_slot, object_type);
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

static int resident_layout_deactivate(void *ctx, uint32_t container_id) {
    (void)ctx;
    uint8_t slot = (uint8_t)container_id;
    for (uint8_t manifest_slot = 0; manifest_slot < 2; manifest_slot++) {
        for (uint16_t object_type = FIDO_RESIDENT_OBJECT_RP_ID_HASH; object_type <= FIDO_RESIDENT_OBJECT_STATE; object_type++) {
            file_t *record = file_search(resident_record_fid(slot, manifest_slot, object_type));
            if (record) {
                file_delete_no_commit(record);
            }
        }
    }
    file_t *marker = file_search((uint16_t)(EF_CRED + slot));
    if (marker) {
        return file_delete_no_commit(marker);
    }
    return PICOKEYS_OK;
}

static const file_object_container_layout_t resident_container_layout = {
    .namespace_id = FIDO_OBJECT_NAMESPACE,
    .container_kind = FIDO_RESIDENT_CONTAINER_KIND,
    .commit_timeout_ms = FIDO_RESIDENT_CONTAINER_COMMIT_TIMEOUT_MS,
    .manifest_fid = resident_layout_manifest_fid,
    .record_fid = resident_layout_record_fid,
    .record_allocate = resident_layout_record_allocate,
    .policy_hash = resident_policy_hash,
    .write_valid = resident_layout_write_valid,
    .descriptor_valid = resident_layout_descriptor_valid,
    .activate = resident_layout_activate,
    .deactivate = resident_layout_deactivate,
    .retire = resident_layout_retire
};

static bool resident_crypto(file_object_container_crypto_t *primary, file_object_container_crypto_t *legacy) {
    primary->auth = fido_object_manifest_authenticator();
    primary->protector = fido_object_record_protector();
    legacy->auth = fido_object_legacy_manifest_authenticator();
    legacy->protector = fido_object_legacy_record_protector();
    return primary->auth && primary->protector;
}

static bool resident_metadata_valid(const fido_resident_metadata_t *metadata) {
    return metadata && metadata->status <= FIDO_RESIDENT_STATUS_REVOKED;
}

static void resident_metadata_encode(const fido_resident_metadata_t *metadata, uint8_t data[FIDO_RESIDENT_METADATA_SIZE]) {
    data[0] = metadata->status;
    data[1] = metadata->properties;
    put_uint32_be(metadata->expiration, data + 2);
}

static void resident_metadata_decode(const uint8_t data[FIDO_RESIDENT_METADATA_SIZE], fido_resident_metadata_t *metadata) {
    metadata->status = data[0];
    metadata->properties = data[1];
    metadata->expiration = get_uint32_be(data + 2);
}

static const file_object_container_crypto_t *resident_legacy_crypto(const file_object_container_crypto_t *legacy) {
    return legacy->auth && legacy->protector ? legacy : NULL;
}

bool resident_container_can_create(uint8_t slot) {
    bool manifest_present = false;
    for (uint8_t manifest_slot = 0; manifest_slot < 2; manifest_slot++) {
        manifest_present |= file_search(resident_manifest_fid(slot, manifest_slot)) != NULL;
    }
    if (manifest_present) {
        file_object_container_crypto_t primary;
        file_object_container_crypto_t legacy;
        file_object_container_state_t state;
        if (!resident_crypto(&primary, &legacy) || file_object_container_load(&resident_container_layout, slot, &primary, resident_legacy_crypto(&legacy), &state) != PICOKEYS_OK) {
            return false;
        }
        return file_object_container_validate(&resident_container_layout, slot, &state.candidates[state.current_slot], state.crypto.protector) == PICOKEYS_OK;
    }
    static const uint8_t record_magic[4] = { 'P', 'K', 'O', 'R' };
    for (uint8_t manifest_slot = 0; manifest_slot < 2; manifest_slot++) {
        for (uint16_t object_type = FIDO_RESIDENT_OBJECT_RP_ID_HASH; object_type <= FIDO_RESIDENT_OBJECT_STATE; object_type++) {
            file_t *record = file_search(resident_record_fid(slot, manifest_slot, object_type));
            if (record && (!file_has_data(record) || file_get_size(record) < sizeof(record_magic) || memcmp(file_get_data(record), record_magic, sizeof(record_magic)) != 0)) {
                return false;
            }
        }
    }
    return true;
}

static int resident_container_update(uint8_t slot, const file_object_container_write_t *writes, size_t write_count) {
    file_object_container_crypto_t primary;
    file_object_container_crypto_t legacy;
    if (!resident_crypto(&primary, &legacy)) {
        return PICOKEYS_EXEC_ERROR;
    }
    if (!file_has_data(file_search(resident_manifest_fid(slot, 0))) && !file_has_data(file_search(resident_manifest_fid(slot, 1))) && !resident_container_can_create(slot)) {
        return PICOKEYS_WRONG_DATA;
    }
    return file_object_container_update(&resident_container_layout, slot, writes, write_count, &primary, resident_legacy_crypto(&legacy));
}

int resident_container_create(uint8_t slot, const uint8_t rp_id_hash[RP_ID_HASH_LEN], const uint8_t *client_id, size_t client_id_size, const uint8_t *credential, size_t credential_size, const uint8_t *public_key, size_t public_key_size) {
    if (!rp_id_hash || !client_id || !credential || !public_key || client_id_size > UINT32_MAX || credential_size > UINT32_MAX || public_key_size > UINT32_MAX) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    const uint8_t metadata[] = { FIDO_RESIDENT_STATUS_ACTIVE, FIDO_RESIDENT_PROPERTY_NATIVE, 0, 0, 0, 0 };
    file_object_container_write_t writes[] = {
        {
            .object_type = FIDO_RESIDENT_OBJECT_RP_ID_HASH,
            .data = CONST_BYTE_ARRAY(rp_id_hash, RP_ID_HASH_LEN),
            .policy_id = FIDO_RESIDENT_POLICY_ID,
            .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC
        },
        {
            .object_type = FIDO_RESIDENT_OBJECT_CLIENT_ID,
            .data = CONST_BYTE_ARRAY(client_id, client_id_size),
            .policy_id = FIDO_RESIDENT_POLICY_ID,
            .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC
        },
        {
            .object_type = FIDO_RESIDENT_OBJECT_CREDENTIAL,
            .data = CONST_BYTE_ARRAY(credential, credential_size),
            .policy_id = FIDO_RESIDENT_POLICY_ID,
            .protection = FILE_OBJECT_PROTECTION_AEAD_SECRET,
            .flags = FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE
        },
        {
            .object_type = FIDO_RESIDENT_OBJECT_PUBLIC_KEY,
            .data = CONST_BYTE_ARRAY(public_key, public_key_size),
            .policy_id = FIDO_RESIDENT_POLICY_ID,
            .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC
        },
        {
            .object_type = FIDO_RESIDENT_OBJECT_METADATA,
            .data = CONST_BYTE_ARRAY(metadata, sizeof(metadata)),
            .policy_id = FIDO_RESIDENT_POLICY_ID,
            .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC,
            .flags = FILE_OBJECT_FLAG_MUTABLE
        },
        {
            .object_type = FIDO_RESIDENT_OBJECT_STATE,
            .data = CONST_BYTE_ARRAY(metadata, sizeof(metadata)),
            .policy_id = FIDO_RESIDENT_POLICY_ID,
            .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC,
            .flags = FILE_OBJECT_FLAG_MUTABLE
        }
    };
    return resident_container_update(slot, writes, sizeof(writes) / sizeof(writes[0]));
}

int resident_container_object_size(uint8_t slot, uint16_t object_type, uint32_t *object_size) {
    if (!object_size || !resident_object_type_valid(object_type)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_crypto_t primary;
    file_object_container_crypto_t legacy;
    if (!resident_crypto(&primary, &legacy)) {
        return PICOKEYS_EXEC_ERROR;
    }
    return file_object_container_object_size(&resident_container_layout, slot, object_type, 0, &primary, resident_legacy_crypto(&legacy), NULL, NULL, object_size);
}

int resident_container_read(uint8_t slot, uint16_t object_type, byte_buffer_t *data) {
    if (!data || !resident_object_type_valid(object_type)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_crypto_t primary;
    file_object_container_crypto_t legacy;
    if (!resident_crypto(&primary, &legacy)) {
        return PICOKEYS_EXEC_ERROR;
    }
    return file_object_container_read(&resident_container_layout, slot, object_type, 0, &primary, resident_legacy_crypto(&legacy), NULL, NULL, data);
}

int resident_container_read_metadata(uint8_t slot, fido_resident_metadata_t *metadata) {
    if (!metadata) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    uint8_t data[FIDO_RESIDENT_METADATA_SIZE];
    byte_buffer_t output = BYTE_BUFFER(data, sizeof(data));
    int r = resident_container_read(slot, FIDO_RESIDENT_OBJECT_STATE, &output);
    if (r == PICOKEYS_ERR_FILE_NOT_FOUND) {
        *metadata = (fido_resident_metadata_t) {
            .status = FIDO_RESIDENT_STATUS_ACTIVE,
            .properties = FIDO_RESIDENT_PROPERTY_NATIVE,
            .expiration = 0
        };
        return PICOKEYS_OK;
    }
    if (r != PICOKEYS_OK || output.len != sizeof(data)) {
        return r == PICOKEYS_OK ? PICOKEYS_WRONG_LENGTH : r;
    }
    resident_metadata_decode(data, metadata);
    return resident_metadata_valid(metadata) ? PICOKEYS_OK : PICOKEYS_WRONG_DATA;
}

int resident_container_update_metadata(uint8_t slot, const fido_resident_metadata_t *metadata) {
    if (!resident_metadata_valid(metadata)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    fido_resident_metadata_t current;
    int r = resident_container_read_metadata(slot, &current);
    if (r == PICOKEYS_OK) {
        if (current.status != FIDO_RESIDENT_STATUS_ACTIVE && metadata->status != current.status) {
            return PICOKEYS_WRONG_DATA;
        }
    }
    else if (r != PICOKEYS_ERR_FILE_NOT_FOUND) {
        return r;
    }
    uint8_t data[FIDO_RESIDENT_METADATA_SIZE];
    resident_metadata_encode(metadata, data);
    file_object_container_write_t write = {
        .object_type = FIDO_RESIDENT_OBJECT_STATE,
        .data = CONST_BYTE_ARRAY(data, sizeof(data)),
        .policy_id = FIDO_RESIDENT_POLICY_ID,
        .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC,
        .flags = FILE_OBJECT_FLAG_MUTABLE
    };
    return resident_container_update(slot, &write, 1);
}

int resident_container_update_metadata_blob(uint8_t slot, const uint8_t *metadata, size_t metadata_size) {
    if ((!metadata && metadata_size > 0) || metadata_size == 0 || metadata_size > UINT32_MAX) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_write_t write = {
        .object_type = FIDO_RESIDENT_OBJECT_METADATA,
        .data = CONST_BYTE_ARRAY(metadata, metadata_size),
        .policy_id = FIDO_RESIDENT_POLICY_ID,
        .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC,
        .flags = FILE_OBJECT_FLAG_MUTABLE
    };
    return resident_container_update(slot, &write, 1);
}

int resident_container_update_credential(uint8_t slot, const uint8_t *credential, size_t credential_size) {
    if ((!credential && credential_size > 0) || credential_size > UINT32_MAX) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_write_t write = {
        .object_type = FIDO_RESIDENT_OBJECT_CREDENTIAL,
        .data = CONST_BYTE_ARRAY(credential, credential_size),
        .policy_id = FIDO_RESIDENT_POLICY_ID,
        .protection = FILE_OBJECT_PROTECTION_AEAD_SECRET,
        .flags = FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE
    };
    return resident_container_update(slot, &write, 1);
}

int resident_container_update_private_key(uint8_t slot, const uint8_t *private_key, size_t private_key_size) {
    if ((!private_key && private_key_size > 0) || private_key_size > UINT32_MAX) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_object_container_write_t write = {
        .object_type = FIDO_RESIDENT_OBJECT_PRIVATE_KEY,
        .data = CONST_BYTE_ARRAY(private_key, private_key_size),
        .policy_id = FIDO_RESIDENT_POLICY_ID,
        .protection = FILE_OBJECT_PROTECTION_AEAD_SECRET,
        .flags = FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE
    };
    return resident_container_update(slot, &write, 1);
}

int resident_container_delete(uint8_t slot) {
    file_t *marker = file_search((uint16_t)(EF_CRED + slot));
    if (!resident_container_is_marker(marker)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    file_object_container_crypto_t primary;
    file_object_container_crypto_t legacy;
    if (!resident_crypto(&primary, &legacy)) {
        return PICOKEYS_EXEC_ERROR;
    }
    return file_object_container_delete(&resident_container_layout, slot, &primary, resident_legacy_crypto(&legacy));
}
