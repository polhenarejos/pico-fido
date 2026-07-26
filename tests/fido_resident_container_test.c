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
#include "resident_container.h"

#include <assert.h>
#include <stdio.h>

#define TEST_FILE_COUNT 32u
#define TEST_FILE_CAPACITY 1024u
#define TEST_SLOT 7u

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

int file_read_at(const file_t *file, uint32_t offset, uint8_t *data, size_t len) {
    const test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data && len > 0) || offset > test_file->size || len > test_file->size - offset) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    memcpy(data, test_file->storage + offset, len);
    return PICOKEYS_OK;
}

int file_put_data(file_t *file, const uint8_t *data, uint32_t len) {
    test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data && len > 0) || len > sizeof(test_file->storage)) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (len > 0) {
        memcpy(test_file->storage, data, len);
    }
    test_file->size = len;
    test_file->file.data = len > 0 ? test_file->storage : NULL;
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
    test_persist();
}

bool flash_commit_sync(uint32_t timeout_ms) {
    (void)timeout_ms;
    sync_commit_count++;
    if (fail_sync_commit_at > 0 && sync_commit_count == fail_sync_commit_at) {
        return false;
    }
    test_persist();
    return true;
}

static void test_read_object(uint16_t object_type, const uint8_t *expected, size_t expected_size) {
    uint8_t output[256];
    size_t written = 0;
    assert(expected_size <= sizeof(output));
    assert(resident_container_read(TEST_SLOT, object_type, output, sizeof(output), &written) == PICOKEYS_OK);
    assert(written == expected_size);
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
    assert(test_allocated_files() == 6);
    test_read_object(FIDO_RESIDENT_OBJECT_RP_ID_HASH, rp_id_hash, sizeof(rp_id_hash));
    test_read_object(FIDO_RESIDENT_OBJECT_CLIENT_ID, client_id, sizeof(client_id));
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, credential, sizeof(credential));
    test_read_object(FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, sizeof(public_key));

    device_key_available = false;
    test_read_object(FIDO_RESIDENT_OBJECT_RP_ID_HASH, rp_id_hash, sizeof(rp_id_hash));
    test_read_object(FIDO_RESIDENT_OBJECT_CLIENT_ID, client_id, sizeof(client_id));
    assert(resident_container_read(TEST_SLOT, FIDO_RESIDENT_OBJECT_CREDENTIAL, client_id, sizeof(client_id), &(size_t){ 0 }) == PICOKEYS_NO_LOGIN);
    test_read_object(FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, sizeof(public_key));
    device_key_available = true;

    file_t *secret_record = file_search((uint16_t)(0xd500u | TEST_SLOT));
    assert(file_has_data(secret_record));
    assert(!test_contains(file_get_data(secret_record), file_get_size(secret_record), credential, sizeof(credential)));

    assert(resident_container_update_credential(TEST_SLOT, updated_credential, sizeof(updated_credential)) == PICOKEYS_OK);
    assert(test_allocated_files() == 6);
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, updated_credential, sizeof(updated_credential));
    test_read_object(FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, sizeof(public_key));
    test_reboot();
    test_read_object(FIDO_RESIDENT_OBJECT_CREDENTIAL, updated_credential, sizeof(updated_credential));
    test_read_object(FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, sizeof(public_key));

    secret_record = file_search((uint16_t)(0xd900u | TEST_SLOT));
    assert(file_has_data(secret_record));
    file_get_data(secret_record)[FILE_OBJECT_RECORD_HEADER_SIZE] ^= 0x01;
    assert(resident_container_read(TEST_SLOT, FIDO_RESIDENT_OBJECT_CREDENTIAL, client_id, sizeof(client_id), &(size_t){ 0 }) == PICOKEYS_WRONG_SIGNATURE);
    test_reboot();
    assert(resident_container_delete(TEST_SLOT) == PICOKEYS_OK);
    assert(test_allocated_files() == 0);
}

static void test_collision_rejected(void) {
    file_t *collision = file_new((uint16_t)(0xd100u | TEST_SLOT));
    static const uint8_t unrelated[] = { 1, 2, 3, 4 };
    assert(collision != NULL);
    assert(file_put_data(collision, unrelated, sizeof(unrelated)) == PICOKEYS_OK);
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
    assert(resident_container_read(TEST_SLOT, FIDO_RESIDENT_OBJECT_RP_ID_HASH, rp_id_hash, sizeof(rp_id_hash), &(size_t){ 0 }) != PICOKEYS_OK);
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
    test_legacy_root_container_remains_accessible();
    puts("fido_resident_container_test: OK");
    return 0;
}
