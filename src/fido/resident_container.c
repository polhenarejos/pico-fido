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
#include "object_policy.h"
#include "object_provider.h"
#include "resident_container.h"

#include <mbedtls/platform_util.h>

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
#define FIDO_RESIDENT_CONTAINER_MAX_MANIFEST_SIZE (FILE_OBJECT_MANIFEST_HEADER_SIZE + FILE_OBJECT_MANIFEST_MAX_OBJECTS * FILE_OBJECT_DESCRIPTOR_SIZE + FILE_OBJECT_AUTH_TAG_SIZE)
#define FIDO_RESIDENT_POLICY_ID 0x0200u

typedef struct resident_manifest_candidate {
    file_object_manifest_t manifest;
    uint8_t slot;
    bool valid;
} resident_manifest_candidate_t;

typedef struct resident_container_write {
    uint16_t object_type;
    const uint8_t *data;
    uint32_t data_size;
    uint8_t protection;
    uint16_t flags;
} resident_container_write_t;

typedef struct resident_crypto_context {
    const file_object_authenticator_t *auth;
    const file_object_record_protector_t *protector;
} resident_crypto_context_t;

static const uint8_t resident_container_marker_magic[4] = { 'P', 'K', 'F', '1' };
static const uint8_t resident_internal_policy[] = {
    FILE_OBJECT_POLICY_FORMAT_VERSION, 1,
    0x1f, 0xff, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
};

static int resident_manifest_validate(const resident_manifest_candidate_t *candidate, const file_object_record_protector_t *protector);

static uint16_t resident_manifest_fid(uint8_t slot, uint8_t manifest_slot) {
    uint8_t prefix = manifest_slot == 0 ? FIDO_RESIDENT_MANIFEST_SLOT_0_PREFIX : FIDO_RESIDENT_MANIFEST_SLOT_1_PREFIX;
    return (uint16_t)((prefix << 8) | slot);
}

static uint16_t resident_record_fid(uint8_t slot, uint8_t manifest_slot, uint16_t object_type) {
    uint8_t prefix = manifest_slot == 0 ? FIDO_RESIDENT_RECORD_SLOT_0_PREFIX : FIDO_RESIDENT_RECORD_SLOT_1_PREFIX;
    return (uint16_t)(((prefix + object_type - 1u) << 8) | slot);
}

static bool resident_object_type_valid(uint16_t object_type) {
    return object_type >= FIDO_RESIDENT_OBJECT_RP_ID_HASH && object_type <= FIDO_RESIDENT_OBJECT_PUBLIC_KEY;
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
    return file_put_data(file, data, data_size);
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

static file_object_descriptor_t *resident_manifest_find(file_object_manifest_t *manifest, uint16_t object_type) {
    for (uint16_t i = 0; i < manifest->object_count; i++) {
        if (manifest->objects[i].object_type == object_type && manifest->objects[i].object_tag == 0) {
            return &manifest->objects[i];
        }
    }
    return NULL;
}

static bool resident_manifest_references_fid(const file_object_manifest_t *manifest, uint16_t fid) {
    for (uint16_t i = 0; i < manifest->object_count; i++) {
        if (manifest->objects[i].record_id == fid) {
            return true;
        }
    }
    return false;
}

static int resident_policy_hash(uint8_t hash[FILE_OBJECT_POLICY_HASH_SIZE]) {
    return file_object_policy_hash(resident_internal_policy, sizeof(resident_internal_policy), hash);
}

static int resident_manifest_parse_slot(uint8_t slot, uint8_t manifest_slot, const file_object_authenticator_t *auth, resident_manifest_candidate_t *candidate) {
    memset(candidate, 0, sizeof(*candidate));
    file_t *file = file_search(resident_manifest_fid(slot, manifest_slot));
    if (!file_has_data(file)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    int r = file_object_manifest_parse(file_get_data(file), file_get_size(file), auth, NULL, NULL, &candidate->manifest);
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (candidate->manifest.namespace_id != FIDO_OBJECT_NAMESPACE || candidate->manifest.container_kind != FIDO_RESIDENT_CONTAINER_KIND || candidate->manifest.container_id != slot || candidate->manifest.object_count == 0) {
        return PICOKEYS_WRONG_DATA;
    }
    for (uint16_t i = 0; i < candidate->manifest.object_count; i++) {
        const file_object_descriptor_t *object = &candidate->manifest.objects[i];
        if (!resident_record_id_valid(slot, object)) {
            return PICOKEYS_WRONG_DATA;
        }
        for (uint16_t j = 0; j < i; j++) {
            if (candidate->manifest.objects[j].object_type == object->object_type) {
                return PICOKEYS_WRONG_DATA;
            }
        }
        file_t *record = file_search((uint16_t)object->record_id);
        file_object_record_info_t info;
        if (!file_has_data(record) || file_object_record_header_parse(file_get_data(record), file_get_size(record), object, &info) != PICOKEYS_OK) {
            return PICOKEYS_WRONG_DATA;
        }
    }
    candidate->slot = manifest_slot;
    candidate->valid = true;
    return PICOKEYS_OK;
}

static int resident_manifest_load(uint8_t slot, const file_object_authenticator_t *auth, resident_manifest_candidate_t candidates[2], resident_manifest_candidate_t **current) {
    bool found = false;
    bool storage_present = false;
    *current = NULL;
    for (uint8_t manifest_slot = 0; manifest_slot < 2; manifest_slot++) {
        storage_present |= file_has_data(file_search(resident_manifest_fid(slot, manifest_slot)));
        int r = resident_manifest_parse_slot(slot, manifest_slot, auth, &candidates[manifest_slot]);
        if (r == PICOKEYS_OK) {
            if (*current && (*current)->manifest.generation == candidates[manifest_slot].manifest.generation) {
                return PICOKEYS_WRONG_DATA;
            }
            if (!*current || candidates[manifest_slot].manifest.generation > (*current)->manifest.generation) {
                *current = &candidates[manifest_slot];
            }
            found = true;
        }
        else if (r != PICOKEYS_ERR_FILE_NOT_FOUND && r != PICOKEYS_WRONG_DATA && r != PICOKEYS_WRONG_SIGNATURE) {
            return r;
        }
    }
    if (!found) {
        return storage_present ? PICOKEYS_WRONG_DATA : PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    return PICOKEYS_OK;
}

static int resident_manifest_load_compatible(uint8_t slot, resident_manifest_candidate_t candidates[2], resident_manifest_candidate_t **current, resident_crypto_context_t *crypto) {
    if (!crypto) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    crypto->auth = fido_object_manifest_authenticator();
    crypto->protector = fido_object_record_protector();
    if (!crypto->auth || !crypto->protector) {
        return PICOKEYS_EXEC_ERROR;
    }
    int r = resident_manifest_load(slot, crypto->auth, candidates, current);
    if (r == PICOKEYS_OK || r == PICOKEYS_ERR_FILE_NOT_FOUND) {
        return r;
    }

    const file_object_authenticator_t *legacy_auth = fido_object_legacy_manifest_authenticator();
    const file_object_record_protector_t *legacy_protector = fido_object_legacy_record_protector();
    if (!legacy_auth || !legacy_protector) {
        return r;
    }
    resident_manifest_candidate_t legacy_candidates[2];
    resident_manifest_candidate_t *legacy_current = NULL;
    int legacy_result = resident_manifest_load(slot, legacy_auth, legacy_candidates, &legacy_current);
    if (legacy_result != PICOKEYS_OK) {
        return r;
    }
    memcpy(candidates, legacy_candidates, sizeof(legacy_candidates));
    *current = &candidates[legacy_current->slot];
    crypto->auth = legacy_auth;
    crypto->protector = legacy_protector;
    return PICOKEYS_OK;
}

bool resident_container_can_create(uint8_t slot) {
    bool manifest_present = false;
    for (uint8_t manifest_slot = 0; manifest_slot < 2; manifest_slot++) {
        manifest_present |= file_search(resident_manifest_fid(slot, manifest_slot)) != NULL;
    }
    if (manifest_present) {
        resident_manifest_candidate_t candidates[2];
        resident_manifest_candidate_t *current = NULL;
        resident_crypto_context_t crypto;
        return resident_manifest_load_compatible(slot, candidates, &current, &crypto) == PICOKEYS_OK && resident_manifest_validate(current, crypto.protector) == PICOKEYS_OK;
    }
    static const uint8_t record_magic[4] = { 'P', 'K', 'O', 'R' };
    for (uint8_t manifest_slot = 0; manifest_slot < 2; manifest_slot++) {
        for (uint16_t object_type = FIDO_RESIDENT_OBJECT_RP_ID_HASH; object_type <= FIDO_RESIDENT_OBJECT_PUBLIC_KEY; object_type++) {
            file_t *record = file_search(resident_record_fid(slot, manifest_slot, object_type));
            if (record && (!file_has_data(record) || file_get_size(record) < sizeof(record_magic) || memcmp(file_get_data(record), record_magic, sizeof(record_magic)) != 0)) {
                return false;
            }
        }
    }
    return true;
}

static int resident_unseal(const file_object_manifest_t *manifest, const file_object_descriptor_t *object, const file_object_record_protector_t *protector, uint8_t *data, size_t capacity, size_t *written) {
    file_object_manifest_t record_manifest = *manifest;
    record_manifest.object_count = 1;
    record_manifest.has_object = true;
    record_manifest.object = *object;
    uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE];
    int r = resident_policy_hash(policy_hash);
    if (r != PICOKEYS_OK) {
        return r;
    }
    file_t *record = file_search((uint16_t)object->record_id);
    if (!file_has_data(record)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    return file_object_record_unseal(&record_manifest, policy_hash, protector, file_get_data(record), file_get_size(record), data, capacity, written);
}

static int resident_manifest_validate(const resident_manifest_candidate_t *candidate, const file_object_record_protector_t *protector) {
    for (uint16_t i = 0; i < candidate->manifest.object_count; i++) {
        const file_object_descriptor_t *object = &candidate->manifest.objects[i];
        uint8_t *data = NULL;
        if (object->logical_size > 0) {
            data = (uint8_t *)calloc(1, object->logical_size);
            if (!data) {
                return PICOKEYS_ERR_MEMORY_FATAL;
            }
        }
        size_t written = 0;
        int r = resident_unseal(&candidate->manifest, object, protector, data, object->logical_size, &written);
        if (data) {
            mbedtls_platform_zeroize(data, object->logical_size);
            free(data);
        }
        if (r != PICOKEYS_OK || written != object->logical_size) {
            return r == PICOKEYS_OK ? PICOKEYS_WRONG_LENGTH : r;
        }
    }
    return PICOKEYS_OK;
}

static int resident_record_write(uint8_t slot, uint8_t manifest_slot, const resident_container_write_t *write, uint32_t object_generation, uint32_t container_generation, const file_object_record_protector_t *protector, file_object_descriptor_t *descriptor) {
    uint16_t record_fid = resident_record_fid(slot, manifest_slot, write->object_type);
    *descriptor = (file_object_descriptor_t) {
        .object_type = write->object_type,
        .object_tag = 0,
        .generation = object_generation,
        .logical_size = write->data_size,
        .record_id = record_fid,
        .stored_size = write->data_size,
        .policy_id = FIDO_RESIDENT_POLICY_ID,
        .key_domain = 0,
        .protection = write->protection,
        .flags = write->flags
    };
    file_object_manifest_t record_manifest = {
        .namespace_id = FIDO_OBJECT_NAMESPACE,
        .container_kind = FIDO_RESIDENT_CONTAINER_KIND,
        .container_id = slot,
        .generation = container_generation,
        .previous_generation = container_generation > 1 ? container_generation - 1 : 0,
        .has_object = true,
        .object = *descriptor
    };
    uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE];
    int r = resident_policy_hash(policy_hash);
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (write->data_size > UINT32_MAX - FILE_OBJECT_RECORD_HEADER_SIZE - FILE_OBJECT_AUTH_TAG_SIZE) {
        return PICOKEYS_WRONG_LENGTH;
    }
    size_t record_size = FILE_OBJECT_RECORD_HEADER_SIZE + (size_t)write->data_size + FILE_OBJECT_AUTH_TAG_SIZE;
    uint8_t *record = (uint8_t *)calloc(1, record_size);
    if (!record) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    size_t written = 0;
    r = file_object_record_seal(&record_manifest, policy_hash, protector, write->data, write->data_size, record, record_size, &written);
    if (r == PICOKEYS_OK && written != record_size) {
        r = PICOKEYS_WRONG_LENGTH;
    }
    if (r == PICOKEYS_OK) {
        r = resident_replace_file(record_fid, record, (uint32_t)record_size);
    }
    mbedtls_platform_zeroize(record, record_size);
    free(record);
    return r;
}

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

static int resident_container_update(uint8_t slot, const resident_container_write_t *writes, size_t write_count) {
    if (!writes || write_count == 0 || write_count > FILE_OBJECT_MANIFEST_MAX_OBJECTS) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    resident_manifest_candidate_t candidates[2];
    resident_manifest_candidate_t *current = NULL;
    resident_crypto_context_t crypto;
    int r = resident_manifest_load_compatible(slot, candidates, &current, &crypto);
    if (r != PICOKEYS_OK && r != PICOKEYS_ERR_FILE_NOT_FOUND) {
        return r;
    }
    bool creating = r == PICOKEYS_ERR_FILE_NOT_FOUND;
    if (creating && !resident_container_can_create(slot)) {
        return PICOKEYS_WRONG_DATA;
    }
    if (current) {
        int current_status = resident_manifest_validate(current, crypto.protector);
        resident_manifest_candidate_t *previous = &candidates[current->slot ^ 1u];
        if (current_status != PICOKEYS_OK && previous->valid && resident_manifest_validate(previous, crypto.protector) == PICOKEYS_OK) {
            current = previous;
        }
        else if (current_status != PICOKEYS_OK) {
            return current_status;
        }
    }

    file_object_manifest_t next = { 0 };
    if (current) {
        next = current->manifest;
        if (next.generation == UINT32_MAX || next.extension_size != 0) {
            return PICOKEYS_WRONG_DATA;
        }
        next.previous_generation = next.generation;
        next.generation++;
    }
    else {
        next.namespace_id = FIDO_OBJECT_NAMESPACE;
        next.container_kind = FIDO_RESIDENT_CONTAINER_KIND;
        next.container_id = slot;
        next.generation = 1;
    }
    uint8_t target_slot = current ? current->slot ^ 1u : 0;
    for (size_t i = 0; i < write_count; i++) {
        const resident_container_write_t *write = &writes[i];
        if ((!write->data && write->data_size > 0) || !resident_object_type_valid(write->object_type) || (write->flags & FILE_OBJECT_FLAG_INLINE) != 0) {
            return PICOKEYS_WRONG_DATA;
        }
        for (size_t j = 0; j < i; j++) {
            if (writes[j].object_type == write->object_type) {
                return PICOKEYS_WRONG_DATA;
            }
        }
        file_object_descriptor_t *object = resident_manifest_find(&next, write->object_type);
        uint32_t object_generation = object ? object->generation + 1 : 1;
        if (object && object->generation == UINT32_MAX) {
            return PICOKEYS_WRONG_DATA;
        }
        file_object_descriptor_t replacement;
        r = resident_record_write(slot, target_slot, write, object_generation, next.generation, crypto.protector, &replacement);
        if (r != PICOKEYS_OK) {
            return r;
        }
        if (object) {
            *object = replacement;
        }
        else if (next.object_count < FILE_OBJECT_MANIFEST_MAX_OBJECTS) {
            next.objects[next.object_count++] = replacement;
            next.has_object = true;
        }
        else {
            return PICOKEYS_ERR_NO_MEMORY;
        }
    }
    if (!flash_commit_sync(FIDO_RESIDENT_CONTAINER_COMMIT_TIMEOUT_MS)) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }

    uint8_t manifest_data[FIDO_RESIDENT_CONTAINER_MAX_MANIFEST_SIZE];
    size_t manifest_size = 0;
    r = file_object_manifest_build(&next, NULL, 0, crypto.auth, manifest_data, sizeof(manifest_data), &manifest_size);
    if (r == PICOKEYS_OK) {
        r = resident_replace_file(resident_manifest_fid(slot, target_slot), manifest_data, (uint32_t)manifest_size);
    }
    memset(manifest_data, 0, sizeof(manifest_data));
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (!flash_commit_sync(FIDO_RESIDENT_CONTAINER_COMMIT_TIMEOUT_MS)) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    file_t *marker = file_search((uint16_t)(EF_CRED + slot));
    if (!resident_container_is_marker(marker)) {
        r = resident_marker_write(slot);
        if (r != PICOKEYS_OK) {
            return r;
        }
    }
    for (uint8_t manifest_slot = 0; manifest_slot < 2; manifest_slot++) {
        if (manifest_slot != target_slot) {
            file_t *manifest = file_search(resident_manifest_fid(slot, manifest_slot));
            if (manifest) {
                file_delete_no_commit(manifest);
            }
        }
        for (uint16_t object_type = FIDO_RESIDENT_OBJECT_RP_ID_HASH; object_type <= FIDO_RESIDENT_OBJECT_PUBLIC_KEY; object_type++) {
            uint16_t record_fid = resident_record_fid(slot, manifest_slot, object_type);
            if (!resident_manifest_references_fid(&next, record_fid)) {
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

int resident_container_create(uint8_t slot, const uint8_t rp_id_hash[RP_ID_HASH_LEN], const uint8_t *client_id, size_t client_id_size, const uint8_t *credential, size_t credential_size, const uint8_t *public_key, size_t public_key_size) {
    if (!rp_id_hash || !client_id || !credential || !public_key || client_id_size > UINT32_MAX || credential_size > UINT32_MAX || public_key_size > UINT32_MAX) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    resident_container_write_t writes[] = {
        { FIDO_RESIDENT_OBJECT_RP_ID_HASH, rp_id_hash, RP_ID_HASH_LEN, FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC, 0 },
        { FIDO_RESIDENT_OBJECT_CLIENT_ID, client_id, (uint32_t)client_id_size, FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC, 0 },
        { FIDO_RESIDENT_OBJECT_CREDENTIAL, credential, (uint32_t)credential_size, FILE_OBJECT_PROTECTION_AEAD_SECRET, FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE },
        { FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, (uint32_t)public_key_size, FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC, 0 }
    };
    return resident_container_update(slot, writes, sizeof(writes) / sizeof(writes[0]));
}

int resident_container_object_size(uint8_t slot, uint16_t object_type, uint32_t *object_size) {
    if (!object_size || !resident_object_type_valid(object_type)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *object_size = 0;
    resident_manifest_candidate_t candidates[2];
    resident_manifest_candidate_t *current = NULL;
    resident_crypto_context_t crypto;
    int r = resident_manifest_load_compatible(slot, candidates, &current, &crypto);
    if (r != PICOKEYS_OK) {
        return r;
    }
    file_object_descriptor_t *object = resident_manifest_find(&current->manifest, object_type);
    if (!object) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    *object_size = object->logical_size;
    return PICOKEYS_OK;
}

int resident_container_read(uint8_t slot, uint16_t object_type, uint8_t *data, size_t capacity, size_t *written) {
    if ((!data && capacity > 0) || !written || !resident_object_type_valid(object_type)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *written = 0;
    resident_manifest_candidate_t candidates[2];
    resident_manifest_candidate_t *current = NULL;
    resident_crypto_context_t crypto;
    int r = resident_manifest_load_compatible(slot, candidates, &current, &crypto);
    if (r != PICOKEYS_OK) {
        return r;
    }
    for (uint8_t attempt = 0; attempt < 2; attempt++) {
        resident_manifest_candidate_t *candidate = attempt == 0 ? current : &candidates[current->slot ^ 1u];
        if (!candidate || !candidate->valid) {
            continue;
        }
        file_object_descriptor_t *object = resident_manifest_find(&candidate->manifest, object_type);
        if (!object) {
            continue;
        }
        r = resident_unseal(&candidate->manifest, object, crypto.protector, data, capacity, written);
        if (r == PICOKEYS_OK) {
            return PICOKEYS_OK;
        }
    }
    if (data && capacity > 0) {
        memset(data, 0, capacity);
    }
    return r;
}

int resident_container_update_credential(uint8_t slot, const uint8_t *credential, size_t credential_size) {
    if ((!credential && credential_size > 0) || credential_size > UINT32_MAX) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    resident_container_write_t write = {
        .object_type = FIDO_RESIDENT_OBJECT_CREDENTIAL,
        .data = credential,
        .data_size = (uint32_t)credential_size,
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
    resident_manifest_candidate_t candidates[2];
    resident_manifest_candidate_t *current = NULL;
    resident_crypto_context_t crypto;
    int r = resident_manifest_load_compatible(slot, candidates, &current, &crypto);
    if (r != PICOKEYS_OK) {
        return r;
    }
    (void)current;
    for (uint8_t manifest_slot = 0; manifest_slot < 2; manifest_slot++) {
        for (uint16_t object_type = FIDO_RESIDENT_OBJECT_RP_ID_HASH; object_type <= FIDO_RESIDENT_OBJECT_PUBLIC_KEY; object_type++) {
            file_t *record = file_search(resident_record_fid(slot, manifest_slot, object_type));
            if (record) {
                file_delete_no_commit(record);
            }
        }
        file_t *manifest = file_search(resident_manifest_fid(slot, manifest_slot));
        if (manifest) {
            file_delete_no_commit(manifest);
        }
    }
    file_delete_no_commit(marker);
    return flash_commit_sync(FIDO_RESIDENT_CONTAINER_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}
