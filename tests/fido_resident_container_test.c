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

#include "picokeys.h"
#include "files.h"
#include "object_container.h"
#include "object_policy.h"
#include "object_provider.h"
#include "resident_container.h"

#include <assert.h>
#include <setjmp.h>
#include <stdio.h>

#define TEST_FILE_COUNT 32u
#define TEST_FILE_CAPACITY 1024u
#define TEST_SLOT 7u
#define TEST_MANIFEST_CAPACITY (FILE_OBJECT_MANIFEST_HEADER_SIZE + FILE_OBJECT_MANIFEST_MAX_OBJECTS * FILE_OBJECT_DESCRIPTOR_SIZE + FILE_OBJECT_AUTH_TAG_SIZE)
#define TEST_RESIDENT_POLICY_ID 0x0200u

typedef struct test_file {
    file_t file;
    uint8_t storage[TEST_FILE_CAPACITY];
    uint32_t size;
    bool allocated;
} test_file_t;

typedef struct test_file_image {
    uint8_t storage[TEST_FILE_CAPACITY];
    uint32_t size;
    uint16_t fid;
    bool allocated;
} test_file_image_t;

static test_file_t test_files[TEST_FILE_COUNT];
static test_file_image_t durable_files[TEST_FILE_COUNT];
static uint8_t device_key[32];
static uint8_t public_root[32];
static bool device_key_available;
static size_t sync_commit_count;
static size_t fail_sync_commit_at;
static jmp_buf power_loss_env;
static size_t power_loss_event;
static size_t power_loss_at = SIZE_MAX;
static bool power_loss_armed;

static test_file_t *test_file_from_handle(const file_t *file) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (&test_files[i].file == file) {
            return &test_files[i];
        }
    }
    return NULL;
}

static void test_persist(void) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        memcpy(durable_files[i].storage, test_files[i].storage, sizeof(durable_files[i].storage));
        durable_files[i].size = test_files[i].size;
        durable_files[i].fid = test_files[i].file.fid;
        durable_files[i].allocated = test_files[i].allocated;
    }
}

static void test_reset(void) {
    memset(test_files, 0, sizeof(test_files));
    memset(durable_files, 0, sizeof(durable_files));
    sync_commit_count = 0;
    fail_sync_commit_at = 0;
    power_loss_event = 0;
    power_loss_at = SIZE_MAX;
    power_loss_armed = false;
    for (size_t i = 0; i < sizeof(device_key); i++) {
        device_key[i] = (uint8_t)(i + 1u);
        public_root[i] = (uint8_t)(0x80u + i);
    }
    device_key_available = true;
}

static void test_reboot(void) {
    memset(test_files, 0, sizeof(test_files));
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        memcpy(test_files[i].storage, durable_files[i].storage, sizeof(test_files[i].storage));
        test_files[i].size = durable_files[i].size;
        test_files[i].file.fid = durable_files[i].fid;
        test_files[i].allocated = durable_files[i].allocated;
        test_files[i].file.data = test_files[i].size > 0 ? test_files[i].storage : NULL;
    }
    power_loss_armed = false;
}

static size_t test_allocated_files(void) {
    size_t count = 0;
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (test_files[i].allocated) {
            count++;
        }
    }
    return count;
}

static bool test_contains(const uint8_t *data, size_t data_size, const uint8_t *needle, size_t needle_size) {
    if (needle_size == 0 || needle_size > data_size) {
        return false;
    }
    for (size_t i = 0; i <= data_size - needle_size; i++) {
        if (memcmp(data + i, needle, needle_size) == 0) {
            return true;
        }
    }
    return false;
}

void derive_kbase(uint8_t kbase[32]) {
    memcpy(kbase, public_root, sizeof(public_root));
}

int load_keydev(uint8_t key[32]) {
    if (!device_key_available) {
        return PICOKEYS_NO_LOGIN;
    }
    memcpy(key, device_key, sizeof(device_key));
    return PICOKEYS_OK;
}

file_t *file_search(uint16_t fid) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (test_files[i].allocated && test_files[i].file.fid == fid) {
            return &test_files[i].file;
        }
    }
    return NULL;
}

file_t *file_new(uint16_t fid) {
    file_t *existing = file_search(fid);
    if (existing) {
        return existing;
    }
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (!test_files[i].allocated) {
            test_files[i].allocated = true;
            test_files[i].file.fid = fid;
            return &test_files[i].file;
        }
    }
    return NULL;
}

file_t *file_search_by_fid(const uint16_t fid, const file_t *parent, const uint8_t sp) {
    (void)parent;
    (void)sp;
    return file_search(fid);
}

bool file_has_data(const file_t *file) {
    const test_file_t *test_file = test_file_from_handle(file);
    return test_file && test_file->allocated && test_file->file.data && test_file->size > 0;
}

uint8_t *file_get_data(const file_t *file) {
    test_file_t *test_file = test_file_from_handle(file);
    return file_has_data(file) ? test_file->storage : NULL;
}

uint32_t file_get_size(const file_t *file) {
    const test_file_t *test_file = test_file_from_handle(file);
    return test_file ? test_file->size : 0;
}

int file_read_at(const file_t *file, uint32_t offset, byte_array_t data) {
    const test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data.data && data.len > 0) || offset > test_file->size || data.len > test_file->size - offset) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    memcpy(data.data, test_file->storage + offset, data.len);
    return PICOKEYS_OK;
}

int file_put_data(file_t *file, const_byte_array_t data) {
    test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data.data && data.len > 0) || data.len > sizeof(test_file->storage)) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (data.len > 0) {
        memcpy(test_file->storage, data.data, data.len);
    }
    test_file->size = (uint32_t)data.len;
    test_file->file.data = data.len > 0 ? test_file->storage : NULL;
    return PICOKEYS_OK;
}

int file_delete_no_commit(file_t *file) {
    test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || !test_file->allocated) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    memset(test_file, 0, sizeof(*test_file));
    return PICOKEYS_OK;
}

void flash_commit(void) {
    power_loss_event++;
    if (power_loss_armed && power_loss_event == power_loss_at) {
        power_loss_armed = false;
        longjmp(power_loss_env, 1);
    }
    test_persist();
}

bool flash_commit_sync(uint32_t timeout_ms) {
    (void)timeout_ms;
    power_loss_event++;
    if (power_loss_armed && power_loss_event == power_loss_at) {
        power_loss_armed = false;
        longjmp(power_loss_env, 1);
    }
    sync_commit_count++;
    if (fail_sync_commit_at > 0 && sync_commit_count == fail_sync_commit_at) {
        return false;
    }
    test_persist();
    return true;
}

static void test_read_object(uint16_t object_type, const uint8_t *expected, size_t expected_size) {
    uint8_t output[256];
    byte_buffer_t data = BYTE_BUFFER(output, sizeof(output));
    assert(expected_size <= sizeof(output));
    assert(resident_container_read(TEST_SLOT, object_type, &data) == PICOKEYS_OK);
    assert(data.len == expected_size);
    assert(memcmp(output, expected, expected_size) == 0);
}

static void test_create_update_reboot_delete(void) {
    uint8_t rp_id_hash[RP_ID_HASH_LEN];
    uint8_t client_id[42];
    static const uint8_t credential[] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
    static const uint8_t updated_credential[] = { 0xa0, 0xb0, 0xc0, 0xd0 };
    static const uint8_t public_key[] = { 0xa4, 0x01, 0x02, 0x03, 0x26 };
    for (size_t i = 0; i < sizeof(rp_id_hash); i++) {
        rp_id_hash[i] = (uint8_t)(0x80u + i);
    }
    for (size_t i = 0; i < sizeof(client_id); i++) {
        client_id[i] = (uint8_t)(0x20u + i);
    }

    assert(resident_container_can_create(TEST_SLOT));
    assert(resident_container_create(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key)) == PICOKEYS_OK);
    assert(resident_container_is_marker(file_search((uint16_t)(EF_CRED + TEST_SLOT))));
    assert(test_allocated_files() == 8);
    test_read_object(FIDO_RESIDENT_OBJECT_RP_ID_HASH, rp_id_hash, sizeof(rp_id_hash));
    test_read_object(FIDO_RESIDENT_OBJECT_CLIENT_ID, client_id, sizeof(client_id));
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, credential, sizeof(credential));
    test_read_object(FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, sizeof(public_key));
    fido_resident_metadata_t metadata;
    assert(resident_container_read_metadata(TEST_SLOT, &metadata) == PICOKEYS_OK);
    assert(metadata.status == FIDO_RESIDENT_STATUS_ACTIVE);
    assert(metadata.properties == FIDO_RESIDENT_PROPERTY_NATIVE);
    assert(metadata.expiration == 0);

    device_key_available = false;
    test_read_object(FIDO_RESIDENT_OBJECT_RP_ID_HASH, rp_id_hash, sizeof(rp_id_hash));
    test_read_object(FIDO_RESIDENT_OBJECT_CLIENT_ID, client_id, sizeof(client_id));
    assert(resident_container_read(TEST_SLOT, FIDO_RESIDENT_OBJECT_CREDENTIAL, &BYTE_BUFFER(client_id, sizeof(client_id))) == PICOKEYS_NO_LOGIN);
    test_read_object(FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, sizeof(public_key));
    device_key_available = true;

    file_t *secret_record = file_search((uint16_t)(0xd500u | TEST_SLOT));
    assert(file_has_data(secret_record));
    assert(!test_contains(file_get_data(secret_record), file_get_size(secret_record), credential, sizeof(credential)));

    assert(resident_container_update_credential(TEST_SLOT, updated_credential, sizeof(updated_credential)) == PICOKEYS_OK);
    assert(test_allocated_files() == 8);
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, updated_credential, sizeof(updated_credential));
    test_read_object(FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, sizeof(public_key));
    metadata = (fido_resident_metadata_t) {
        .status = FIDO_RESIDENT_STATUS_REVOKED,
        .properties = FIDO_RESIDENT_PROPERTY_IMPORTED,
        .expiration = 0x12345678u
    };
    assert(resident_container_update_metadata(TEST_SLOT, &metadata) == PICOKEYS_OK);
    memset(&metadata, 0, sizeof(metadata));
    assert(resident_container_read_metadata(TEST_SLOT, &metadata) == PICOKEYS_OK);
    assert(metadata.status == FIDO_RESIDENT_STATUS_REVOKED);
    assert(metadata.properties == FIDO_RESIDENT_PROPERTY_IMPORTED);
    assert(metadata.expiration == 0x12345678u);
    test_reboot();
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, updated_credential, sizeof(updated_credential));
    test_read_object(FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, sizeof(public_key));
    secret_record = file_search((uint16_t)(0xd900u | TEST_SLOT));
    assert(file_has_data(secret_record));
    file_get_data(secret_record)[FILE_OBJECT_RECORD_HEADER_SIZE] ^= 0x01;
    assert(resident_container_read(TEST_SLOT, FIDO_RESIDENT_OBJECT_CREDENTIAL, &BYTE_BUFFER(client_id, sizeof(client_id))) == PICOKEYS_WRONG_SIGNATURE);
    test_reboot();
    assert(resident_container_delete(TEST_SLOT) == PICOKEYS_OK);
    assert(test_allocated_files() == 0);
}

static void test_collision_rejected(void) {
    file_t *collision = file_new((uint16_t)(0xd100u | TEST_SLOT));
    static const uint8_t unrelated[] = { 1, 2, 3, 4 };
    assert(collision != NULL);
    assert(file_put_data(collision, CONST_BYTE_ARRAY(unrelated, sizeof(unrelated))) == PICOKEYS_OK);
    assert(!resident_container_can_create(TEST_SLOT));
}

static void test_interrupted_create_recovers(void) {
    uint8_t rp_id_hash[RP_ID_HASH_LEN] = { 0x31 };
    uint8_t client_id[42] = { 0x32 };
    static const uint8_t credential[] = { 0x33, 0x34, 0x35 };
    static const uint8_t public_key[] = { 0xa4, 0x01, 0x02 };

    for (size_t failed_commit = 1; failed_commit <= 3; failed_commit++) {
        test_reset();
        fail_sync_commit_at = failed_commit;
        assert(resident_container_create(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key)) != PICOKEYS_OK);

        test_reboot();
        assert(!resident_container_is_marker(file_search((uint16_t)(EF_CRED + TEST_SLOT))));
        assert(resident_container_can_create(TEST_SLOT));

        fail_sync_commit_at = 0;
        sync_commit_count = 0;
        assert(resident_container_create(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key)) == PICOKEYS_OK);
        test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, credential, sizeof(credential));
    }
}

static void test_interrupted_update_keeps_previous_generation(void) {
    uint8_t rp_id_hash[RP_ID_HASH_LEN] = { 0x41 };
    uint8_t client_id[42] = { 0x42 };
    static const uint8_t credential[] = { 0x43, 0x44, 0x45 };
    static const uint8_t updated_credential[] = { 0x53, 0x54, 0x55 };
    static const uint8_t public_key[] = { 0xa4, 0x01, 0x02 };

    for (size_t failed_commit = 1; failed_commit <= 2; failed_commit++) {
        test_reset();
        assert(resident_container_create(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key)) == PICOKEYS_OK);

        sync_commit_count = 0;
        fail_sync_commit_at = failed_commit;
        assert(resident_container_update_credential(TEST_SLOT, updated_credential, sizeof(updated_credential)) != PICOKEYS_OK);

        test_reboot();
        test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, credential, sizeof(credential));

        fail_sync_commit_at = 0;
        sync_commit_count = 0;
        assert(resident_container_update_credential(TEST_SLOT, updated_credential, sizeof(updated_credential)) == PICOKEYS_OK);
        test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, updated_credential, sizeof(updated_credential));
    }
}

static void test_existing_container_fixture(void) {
    static const uint8_t resident_policy[] = {
        FILE_OBJECT_POLICY_FORMAT_VERSION, 1,
        0x1f, 0xff, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
    };
    uint8_t rp_id_hash[RP_ID_HASH_LEN];
    uint8_t client_id[42];
    static const uint8_t credential[] = { 0x81, 0x82, 0x83, 0x84 };
    static const uint8_t updated_credential[] = { 0x91, 0x92, 0x93 };
    static const uint8_t public_key[] = { 0xa4, 0x01, 0x02, 0x03 };
    const struct {
        uint16_t object_type;
        const uint8_t *data;
        uint32_t data_size;
        uint8_t protection;
        uint16_t flags;
    } objects[] = {
        {
            .object_type = FIDO_RESIDENT_OBJECT_RP_ID_HASH,
            .data = rp_id_hash,
            .data_size = sizeof(rp_id_hash),
            .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC
        },
        {
            .object_type = FIDO_RESIDENT_OBJECT_CLIENT_ID,
            .data = client_id,
            .data_size = sizeof(client_id),
            .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC
        },
        {
            .object_type = FIDO_RESIDENT_OBJECT_CREDENTIAL,
            .data = credential,
            .data_size = sizeof(credential),
            .protection = FILE_OBJECT_PROTECTION_AEAD_SECRET,
            .flags = FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE
        },
        {
            .object_type = FIDO_RESIDENT_OBJECT_PUBLIC_KEY,
            .data = public_key,
            .data_size = sizeof(public_key),
            .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC
        }
    };
    uint8_t record_data[4][128] = { 0 };
    size_t record_sizes[4] = { 0 };
    uint8_t manifest_data[TEST_MANIFEST_CAPACITY];
    size_t manifest_size = 0;
    uint8_t marker[] = { 'P', 'K', 'F', '1', 1, TEST_SLOT, 0, 0 };
    uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE];
    file_object_manifest_t manifest = {
        .namespace_id = FIDO_OBJECT_NAMESPACE,
        .container_kind = FIDO_RESIDENT_CONTAINER_KIND,
        .container_id = TEST_SLOT,
        .generation = 1,
        .object_count = sizeof(objects) / sizeof(objects[0]),
        .has_object = true
    };

    test_reset();
    for (size_t i = 0; i < sizeof(rp_id_hash); i++) {
        rp_id_hash[i] = (uint8_t)(0x20u + i);
    }
    for (size_t i = 0; i < sizeof(client_id); i++) {
        client_id[i] = (uint8_t)(0x50u + i);
    }
    memcpy(public_root, device_key, sizeof(public_root));
    const file_object_authenticator_t *auth = fido_object_manifest_authenticator();
    const file_object_record_protector_t *protector = fido_object_record_protector();
    assert(auth && protector);
    assert(file_object_policy_hash(CONST_BYTE_ARRAY(resident_policy, sizeof(resident_policy)), policy_hash) == PICOKEYS_OK);

    for (size_t i = 0; i < sizeof(objects) / sizeof(objects[0]); i++) {
        uint16_t record_fid = (uint16_t)(((0xd3u + objects[i].object_type - 1u) << 8) | TEST_SLOT);
        manifest.objects[i] = (file_object_descriptor_t) {
            .object_type = objects[i].object_type,
            .generation = 1,
            .logical_size = objects[i].data_size,
            .record_id = record_fid,
            .stored_size = objects[i].data_size,
            .policy_id = TEST_RESIDENT_POLICY_ID,
            .protection = objects[i].protection,
            .flags = objects[i].flags
        };
        file_object_manifest_t record_manifest = manifest;
        record_manifest.object_count = 1;
        record_manifest.object = manifest.objects[i];
        byte_buffer_t record = BYTE_BUFFER(record_data[i], sizeof(record_data[i]));
        assert(file_object_record_seal(&record_manifest, policy_hash, protector, CONST_BYTE_ARRAY(objects[i].data, objects[i].data_size), &record) == PICOKEYS_OK);
        record_sizes[i] = record.len;
        assert(file_put_data(file_new(record_fid), CONST_BYTE_ARRAY(record_data[i], record_sizes[i])) == PICOKEYS_OK);
    }
    byte_buffer_t manifest_output = BYTE_BUFFER(manifest_data, sizeof(manifest_data));
    assert(file_object_manifest_build(&manifest, CONST_BYTE_ARRAY(NULL, 0), auth, &manifest_output) == PICOKEYS_OK);
    manifest_size = manifest_output.len;
    assert(file_put_data(file_new((uint16_t)(0xd100u | TEST_SLOT)), CONST_BYTE_ARRAY(manifest_data, manifest_size)) == PICOKEYS_OK);
    assert(file_put_data(file_new((uint16_t)(EF_CRED + TEST_SLOT)), CONST_BYTE_ARRAY(marker, sizeof(marker))) == PICOKEYS_OK);
    test_persist();

    for (size_t i = 0; i < sizeof(public_root); i++) {
        public_root[i] = (uint8_t)(0x80u + i);
    }
    test_reboot();
    test_read_object(FIDO_RESIDENT_OBJECT_RP_ID_HASH, rp_id_hash, sizeof(rp_id_hash));
    test_read_object(FIDO_RESIDENT_OBJECT_CLIENT_ID, client_id, sizeof(client_id));
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, credential, sizeof(credential));
    test_read_object(FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, sizeof(public_key));
    assert(file_get_size(file_search((uint16_t)(0xd100u | TEST_SLOT))) == manifest_size);
    assert(memcmp(file_get_data(file_search((uint16_t)(0xd100u | TEST_SLOT))), manifest_data, manifest_size) == 0);
    for (size_t i = 0; i < sizeof(objects) / sizeof(objects[0]); i++) {
        uint16_t record_fid = (uint16_t)(((0xd3u + objects[i].object_type - 1u) << 8) | TEST_SLOT);
        assert(file_get_size(file_search(record_fid)) == record_sizes[i]);
        assert(memcmp(file_get_data(file_search(record_fid)), record_data[i], record_sizes[i]) == 0);
    }

    assert(resident_container_update_credential(TEST_SLOT, updated_credential, sizeof(updated_credential)) == PICOKEYS_OK);
    test_reboot();
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, updated_credential, sizeof(updated_credential));
}

static bool test_credential_matches(const uint8_t *first, size_t first_size, const uint8_t *second, size_t second_size) {
    uint8_t output[32] = { 0 };
    byte_buffer_t data = BYTE_BUFFER(output, sizeof(output));
    int r = resident_container_read(TEST_SLOT, FIDO_RESIDENT_OBJECT_CREDENTIAL, &data);
    if (r != PICOKEYS_OK) {
        return false;
    }
    return (data.len == first_size && memcmp(output, first, first_size) == 0) || (data.len == second_size && memcmp(output, second, second_size) == 0);
}

static void test_power_loss_create_event(size_t failed_event) {
    uint8_t rp_id_hash[RP_ID_HASH_LEN] = { 0xa1 };
    uint8_t client_id[42] = { 0xa2 };
    static const uint8_t credential[] = { 0xa3, 0xa4 };
    static const uint8_t public_key[] = { 0xa4, 0x01, 0x02 };

    test_reset();
    if (setjmp(power_loss_env) == 0) {
        power_loss_event = 0;
        power_loss_at = failed_event;
        power_loss_armed = true;
        (void)resident_container_create(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key));
        assert(false);
    }
    test_reboot();

    assert(resident_container_can_create(TEST_SLOT));
    assert(resident_container_create(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key)) == PICOKEYS_OK);
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, credential, sizeof(credential));
}

static void test_power_loss_imported_create_event(size_t failed_event) {
    uint8_t rp_id_hash[RP_ID_HASH_LEN] = { 0x91 };
    uint8_t client_id[42] = { 0x92 };
    static const uint8_t credential[] = { 0x93, 0x94 };
    static const uint8_t public_key[] = { 0xa4, 0x01, 0x02 };
    static const uint8_t private_key[] = { 0x95, 0x96, 0x97 };
    static const uint8_t metadata[] = { 0xa0 };

    test_reset();
    if (setjmp(power_loss_env) == 0) {
        power_loss_event = 0;
        power_loss_at = failed_event;
        power_loss_armed = true;
        (void)resident_container_create_imported(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key), private_key, sizeof(private_key), metadata, sizeof(metadata));
        assert(false);
    }
    test_reboot();

    if (resident_container_is_marker(file_search((uint16_t)(EF_CRED + TEST_SLOT)))) {
        test_read_object(FIDO_RESIDENT_OBJECT_RP_ID_HASH, rp_id_hash, sizeof(rp_id_hash));
        test_read_object(FIDO_RESIDENT_OBJECT_CLIENT_ID, client_id, sizeof(client_id));
        test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, credential, sizeof(credential));
        test_read_object(FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, sizeof(public_key));
        test_read_object(FIDO_RESIDENT_OBJECT_PRIVATE_KEY, private_key, sizeof(private_key));
        test_read_object(FIDO_RESIDENT_OBJECT_METADATA, metadata, sizeof(metadata));
        fido_resident_metadata_t state;
        assert(resident_container_read_metadata(TEST_SLOT, &state) == PICOKEYS_OK);
        assert(state.status == FIDO_RESIDENT_STATUS_ACTIVE);
        assert(state.properties == FIDO_RESIDENT_PROPERTY_IMPORTED);
    }
    else {
        assert(resident_container_can_create(TEST_SLOT));
    }
}

static void test_power_loss_update_event(size_t failed_event) {
    uint8_t rp_id_hash[RP_ID_HASH_LEN] = { 0xb1 };
    uint8_t client_id[42] = { 0xb2 };
    static const uint8_t credential[] = { 0xb3, 0xb4 };
    static const uint8_t replacement[] = { 0xc3, 0xc4, 0xc5 };
    static const uint8_t public_key[] = { 0xa4, 0x01, 0x02 };

    test_reset();
    assert(resident_container_create(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key)) == PICOKEYS_OK);
    if (setjmp(power_loss_env) == 0) {
        power_loss_event = 0;
        power_loss_at = failed_event;
        power_loss_armed = true;
        (void)resident_container_update_credential(TEST_SLOT, replacement, sizeof(replacement));
        assert(false);
    }
    test_reboot();

    assert(test_credential_matches(credential, sizeof(credential), replacement, sizeof(replacement)));
    assert(resident_container_update_credential(TEST_SLOT, replacement, sizeof(replacement)) == PICOKEYS_OK);
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, replacement, sizeof(replacement));
}

static void test_power_loss_delete_event(size_t failed_event) {
    uint8_t rp_id_hash[RP_ID_HASH_LEN] = { 0xd1 };
    uint8_t client_id[42] = { 0xd2 };
    static const uint8_t credential[] = { 0xd3, 0xd4 };
    static const uint8_t public_key[] = { 0xa4, 0x01, 0x02 };

    test_reset();
    assert(resident_container_create(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key)) == PICOKEYS_OK);
    if (setjmp(power_loss_env) == 0) {
        power_loss_event = 0;
        power_loss_at = failed_event;
        power_loss_armed = true;
        (void)resident_container_delete(TEST_SLOT);
        assert(false);
    }
    test_reboot();

    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, credential, sizeof(credential));
    assert(resident_container_delete(TEST_SLOT) == PICOKEYS_OK);
}

static void test_power_loss_boundaries(void) {
    uint8_t rp_id_hash[RP_ID_HASH_LEN] = { 0xe1 };
    uint8_t client_id[42] = { 0xe2 };
    static const uint8_t credential[] = { 0xe3 };
    static const uint8_t replacement[] = { 0xe4 };
    static const uint8_t public_key[] = { 0xa4, 0x01, 0x02 };

    test_reset();
    assert(resident_container_create(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key)) == PICOKEYS_OK);
    size_t create_events = power_loss_event;
    assert(create_events > 0);

    test_reset();
    static const uint8_t private_key[] = { 0xf1 };
    static const uint8_t metadata[] = { 0xa0 };
    assert(resident_container_create_imported(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key), private_key, sizeof(private_key), metadata, sizeof(metadata)) == PICOKEYS_OK);
    size_t imported_create_events = power_loss_event;
    assert(imported_create_events > 0);
    assert(test_allocated_files() == 9);
    test_read_object(FIDO_RESIDENT_OBJECT_PRIVATE_KEY, private_key, sizeof(private_key));
    test_read_object(FIDO_RESIDENT_OBJECT_METADATA, metadata, sizeof(metadata));
    fido_resident_metadata_t state;
    assert(resident_container_read_metadata(TEST_SLOT, &state) == PICOKEYS_OK);
    assert(state.status == FIDO_RESIDENT_STATUS_ACTIVE);
    assert(state.properties == FIDO_RESIDENT_PROPERTY_IMPORTED);

    test_reset();
    assert(resident_container_create(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key)) == PICOKEYS_OK);
    power_loss_event = 0;
    assert(resident_container_update_credential(TEST_SLOT, replacement, sizeof(replacement)) == PICOKEYS_OK);
    size_t update_events = power_loss_event;
    assert(update_events > 0);

    power_loss_event = 0;
    assert(resident_container_delete(TEST_SLOT) == PICOKEYS_OK);
    size_t delete_events = power_loss_event;
    assert(delete_events > 0);

    for (size_t failed_event = 1; failed_event <= create_events; failed_event++) {
        test_power_loss_create_event(failed_event);
    }
    for (size_t failed_event = 1; failed_event <= imported_create_events; failed_event++) {
        test_power_loss_imported_create_event(failed_event);
    }
    for (size_t failed_event = 1; failed_event <= update_events; failed_event++) {
        test_power_loss_update_event(failed_event);
    }
    for (size_t failed_event = 1; failed_event <= delete_events; failed_event++) {
        test_power_loss_delete_event(failed_event);
    }
}

static void test_legacy_root_container_remains_accessible(void) {
    uint8_t rp_id_hash[RP_ID_HASH_LEN] = { 0x61 };
    uint8_t client_id[42] = { 0x62 };
    static const uint8_t credential[] = { 0x63, 0x64, 0x65 };
    static const uint8_t updated_credential[] = { 0x73, 0x74, 0x75 };
    static const uint8_t public_key[] = { 0xa4, 0x01, 0x02 };

    test_reset();
    memcpy(public_root, device_key, sizeof(public_root));
    assert(resident_container_create(TEST_SLOT, rp_id_hash, client_id, sizeof(client_id), credential, sizeof(credential), public_key, sizeof(public_key)) == PICOKEYS_OK);

    for (size_t i = 0; i < sizeof(public_root); i++) {
        public_root[i] = (uint8_t)(0x80u + i);
    }
    test_reboot();
    test_read_object(FIDO_RESIDENT_OBJECT_RP_ID_HASH, rp_id_hash, sizeof(rp_id_hash));
    test_read_object(FIDO_RESIDENT_OBJECT_CLIENT_ID, client_id, sizeof(client_id));
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, credential, sizeof(credential));
    test_read_object(FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, sizeof(public_key));

    device_key_available = false;
    assert(resident_container_read(TEST_SLOT, FIDO_RESIDENT_OBJECT_RP_ID_HASH, &BYTE_BUFFER(rp_id_hash, sizeof(rp_id_hash))) != PICOKEYS_OK);
    device_key_available = true;

    assert(resident_container_update_credential(TEST_SLOT, updated_credential, sizeof(updated_credential)) == PICOKEYS_OK);
    test_reboot();
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, updated_credential, sizeof(updated_credential));
}

int main(void) {
    test_reset();
    test_create_update_reboot_delete();
    test_reset();
    test_collision_rejected();
    test_interrupted_create_recovers();
    test_interrupted_update_keeps_previous_generation();
    test_existing_container_fixture();
    test_power_loss_boundaries();
    test_legacy_root_container_remains_accessible();
    puts("fido_resident_container_test: OK");
    return 0;
}
