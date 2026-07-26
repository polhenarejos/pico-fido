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
#include "oath_container.h"
#include "object_container.h"

#include <assert.h>
#include <setjmp.h>
#include <stdio.h>

#define TEST_FILE_COUNT 16u
#define TEST_FILE_CAPACITY 1024u
#define TEST_SLOT 9u

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
static size_t power_loss_at;
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
    uint8_t output[256] = { 0 };
    size_t written = 0;
    assert(expected_size <= sizeof(output));
    assert(oath_container_read(TEST_SLOT, object_type, output, sizeof(output), &written) == PICOKEYS_OK);
    assert(written == expected_size);
    assert(memcmp(output, expected, expected_size) == 0);
}

static void test_create_update_reboot_delete(void) {
    static const uint8_t credential[] = { 0x71, 0x04, 't', 'e', 's', 't', 0x73, 0x06, 0x21, 0x06, 0xde, 0xad, 0xbe, 0xef };
    static const uint8_t metadata[] = { 0x71, 0x04, 't', 'e', 's', 't', 0x73, 0x02, 0x21, 0x06 };
    static const uint8_t updated_credential[] = { 0x71, 0x05, 'o', 't', 'h', 'e', 'r', 0x73, 0x06, 0x21, 0x06, 0xca, 0xfe, 0xba, 0xbe };
    static const uint8_t updated_metadata[] = { 0x71, 0x05, 'o', 't', 'h', 'e', 'r', 0x73, 0x02, 0x21, 0x06 };

    assert(oath_container_can_create(TEST_SLOT));
    assert(oath_container_create(TEST_SLOT, credential, sizeof(credential), metadata, sizeof(metadata)) == PICOKEYS_OK);
    assert(oath_container_is_marker(file_search((uint16_t)(EF_OATH_CRED + TEST_SLOT))));
    test_read_object(FIDO_OATH_OBJECT_CREDENTIAL, credential, sizeof(credential));
    test_read_object(FIDO_OATH_OBJECT_METADATA, metadata, sizeof(metadata));

    device_key_available = false;
    test_read_object(FIDO_OATH_OBJECT_CREDENTIAL, credential, sizeof(credential));
    test_read_object(FIDO_OATH_OBJECT_METADATA, metadata, sizeof(metadata));
    device_key_available = true;

    file_t *secret_record = file_search((uint16_t)(0xb200u | TEST_SLOT));
    assert(file_has_data(secret_record));
    assert(!test_contains(file_get_data(secret_record), file_get_size(secret_record), credential, sizeof(credential)));

    assert(oath_container_update(TEST_SLOT, updated_credential, sizeof(updated_credential), updated_metadata, sizeof(updated_metadata)) == PICOKEYS_OK);
    test_reboot();
    test_read_object(FIDO_OATH_OBJECT_CREDENTIAL, updated_credential, sizeof(updated_credential));
    test_read_object(FIDO_OATH_OBJECT_METADATA, updated_metadata, sizeof(updated_metadata));
    assert(oath_container_delete(TEST_SLOT) == PICOKEYS_OK);
    assert(!file_search((uint16_t)(EF_OATH_CRED + TEST_SLOT)));
}

static void test_collision_rejected(void) {
    static const uint8_t unrelated[] = { 1, 2, 3, 4 };
    assert(file_put_data(file_new((uint16_t)(0xb000u | TEST_SLOT)), unrelated, sizeof(unrelated)) == PICOKEYS_OK);
    assert(!oath_container_can_create(TEST_SLOT));
}

static void test_reset_purge_removes_corrupt_container(void) {
    static const uint8_t credential[] = { 0x81, 0x82, 0x83 };
    static const uint8_t metadata[] = { 0x84, 0x85 };

    assert(oath_container_create(TEST_SLOT, credential, sizeof(credential), metadata, sizeof(metadata)) == PICOKEYS_OK);
    file_t *manifest = file_search((uint16_t)(0xb000u | TEST_SLOT));
    assert(file_has_data(manifest));
    file_get_data(manifest)[0] ^= 0x01;
    assert(oath_container_read(TEST_SLOT, FIDO_OATH_OBJECT_CREDENTIAL, (uint8_t[16]){ 0 }, 16, &(size_t){ 0 }) != PICOKEYS_OK);
    assert(oath_container_purge(TEST_SLOT) == PICOKEYS_OK);
    assert(!file_search((uint16_t)(EF_OATH_CRED + TEST_SLOT)));
    for (uint16_t prefix = 0xb0u; prefix <= 0xb5u; prefix++) {
        assert(!file_search((uint16_t)((prefix << 8) | TEST_SLOT)));
    }
}

static void test_interrupted_update_keeps_previous_generation(void) {
    static const uint8_t credential[] = { 0x10, 0x11, 0x12 };
    static const uint8_t metadata[] = { 0x20, 0x21 };
    static const uint8_t replacement[] = { 0x30, 0x31, 0x32 };
    static const uint8_t replacement_metadata[] = { 0x40, 0x41 };

    for (size_t failed_commit = 1; failed_commit <= 2; failed_commit++) {
        test_reset();
        assert(oath_container_create(TEST_SLOT, credential, sizeof(credential), metadata, sizeof(metadata)) == PICOKEYS_OK);
        sync_commit_count = 0;
        fail_sync_commit_at = failed_commit;
        assert(oath_container_update(TEST_SLOT, replacement, sizeof(replacement), replacement_metadata, sizeof(replacement_metadata)) != PICOKEYS_OK);

        test_reboot();
        test_read_object(FIDO_OATH_OBJECT_CREDENTIAL, credential, sizeof(credential));
        test_read_object(FIDO_OATH_OBJECT_METADATA, metadata, sizeof(metadata));
    }
}

static bool test_credential_matches(const uint8_t *first, size_t first_size, const uint8_t *second, size_t second_size) {
    uint8_t output[32] = { 0 };
    size_t written = 0;
    if (oath_container_read(TEST_SLOT, FIDO_OATH_OBJECT_CREDENTIAL, output, sizeof(output), &written) != PICOKEYS_OK) {
        return false;
    }
    return (written == first_size && memcmp(output, first, first_size) == 0) || (written == second_size && memcmp(output, second, second_size) == 0);
}

static void test_power_loss_create_event(size_t failed_event) {
    static const uint8_t credential[] = { 0x41, 0x42 };
    static const uint8_t metadata[] = { 0x43, 0x44 };

    test_reset();
    if (setjmp(power_loss_env) == 0) {
        power_loss_event = 0;
        power_loss_at = failed_event;
        power_loss_armed = true;
        (void)oath_container_create(TEST_SLOT, credential, sizeof(credential), metadata, sizeof(metadata));
        assert(false);
    }
    test_reboot();

    if (!oath_container_is_marker(file_search((uint16_t)(EF_OATH_CRED + TEST_SLOT)))) {
        assert(oath_container_can_create(TEST_SLOT));
        assert(oath_container_create(TEST_SLOT, credential, sizeof(credential), metadata, sizeof(metadata)) == PICOKEYS_OK);
    }
    test_read_object(FIDO_OATH_OBJECT_CREDENTIAL, credential, sizeof(credential));
    test_read_object(FIDO_OATH_OBJECT_METADATA, metadata, sizeof(metadata));
}

static void test_power_loss_update_event(size_t failed_event) {
    static const uint8_t credential[] = { 0x51, 0x52 };
    static const uint8_t metadata[] = { 0x53, 0x54 };
    static const uint8_t replacement[] = { 0x61, 0x62, 0x63 };
    static const uint8_t replacement_metadata[] = { 0x64, 0x65 };

    test_reset();
    assert(oath_container_create(TEST_SLOT, credential, sizeof(credential), metadata, sizeof(metadata)) == PICOKEYS_OK);
    if (setjmp(power_loss_env) == 0) {
        power_loss_event = 0;
        power_loss_at = failed_event;
        power_loss_armed = true;
        (void)oath_container_update(TEST_SLOT, replacement, sizeof(replacement), replacement_metadata, sizeof(replacement_metadata));
        assert(false);
    }
    test_reboot();

    assert(test_credential_matches(credential, sizeof(credential), replacement, sizeof(replacement)));
    assert(oath_container_update(TEST_SLOT, replacement, sizeof(replacement), replacement_metadata, sizeof(replacement_metadata)) == PICOKEYS_OK);
    test_read_object(FIDO_OATH_OBJECT_CREDENTIAL, replacement, sizeof(replacement));
    test_read_object(FIDO_OATH_OBJECT_METADATA, replacement_metadata, sizeof(replacement_metadata));
}

static void test_power_loss_delete_event(size_t failed_event) {
    static const uint8_t credential[] = { 0x71, 0x72 };
    static const uint8_t metadata[] = { 0x73, 0x74 };

    test_reset();
    assert(oath_container_create(TEST_SLOT, credential, sizeof(credential), metadata, sizeof(metadata)) == PICOKEYS_OK);
    if (setjmp(power_loss_env) == 0) {
        power_loss_event = 0;
        power_loss_at = failed_event;
        power_loss_armed = true;
        (void)oath_container_delete(TEST_SLOT);
        assert(false);
    }
    test_reboot();

    test_read_object(FIDO_OATH_OBJECT_CREDENTIAL, credential, sizeof(credential));
    assert(oath_container_delete(TEST_SLOT) == PICOKEYS_OK);
}

static void test_power_loss_boundaries(void) {
    static const uint8_t credential[] = { 0x71 };
    static const uint8_t metadata[] = { 0x72 };
    static const uint8_t replacement[] = { 0x73 };
    static const uint8_t replacement_metadata[] = { 0x74 };

    test_reset();
    assert(oath_container_create(TEST_SLOT, credential, sizeof(credential), metadata, sizeof(metadata)) == PICOKEYS_OK);
    size_t create_events = power_loss_event;
    assert(create_events > 0);

    power_loss_event = 0;
    assert(oath_container_update(TEST_SLOT, replacement, sizeof(replacement), replacement_metadata, sizeof(replacement_metadata)) == PICOKEYS_OK);
    size_t update_events = power_loss_event;
    assert(update_events > 0);

    power_loss_event = 0;
    assert(oath_container_delete(TEST_SLOT) == PICOKEYS_OK);
    size_t delete_events = power_loss_event;
    assert(delete_events > 0);

    for (size_t failed_event = 1; failed_event <= create_events; failed_event++) {
        test_power_loss_create_event(failed_event);
    }
    for (size_t failed_event = 1; failed_event <= update_events; failed_event++) {
        test_power_loss_update_event(failed_event);
    }
    for (size_t failed_event = 1; failed_event <= delete_events; failed_event++) {
        test_power_loss_delete_event(failed_event);
    }
}

int main(void) {
    test_reset();
    test_create_update_reboot_delete();
    test_reset();
    test_collision_rejected();
    test_reset();
    test_reset_purge_removes_corrupt_container();
    test_interrupted_update_keeps_previous_generation();
    test_power_loss_boundaries();
    puts("fido_oath_container_test: OK");
    return 0;
}
