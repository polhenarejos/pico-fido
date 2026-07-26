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
#include "otp_container.h"

#include <assert.h>
#include <setjmp.h>
#include <stdio.h>

#define TEST_FILE_COUNT 32u
#define TEST_FILE_CAPACITY 1024u

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
static uint8_t root_key[32];
static jmp_buf power_loss_env;
static size_t power_loss_event;
static size_t power_loss_at;
static bool power_loss_armed;

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
    power_loss_event = 0;
    power_loss_at = SIZE_MAX;
    power_loss_armed = false;
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

static test_file_t *test_file_from_handle(const file_t *file) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (&test_files[i].file == file) {
            return &test_files[i];
        }
    }
    return NULL;
}

void derive_kbase(uint8_t kbase[32]) {
    memcpy(kbase, root_key, sizeof(root_key));
}

int load_keydev(uint8_t key[32]) {
    memcpy(key, root_key, sizeof(root_key));
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
    memcpy(test_file->storage, data, len);
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
    test_persist();
    return true;
}

static void test_read_slot(uint8_t slot, const uint8_t *expected, size_t expected_size) {
    uint8_t output[128] = { 0 };
    size_t written = 0;
    assert(otp_container_read_slot(slot, output, sizeof(output), &written) == PICOKEYS_OK);
    assert(written == expected_size);
    assert(memcmp(output, expected, expected_size) == 0);
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

static bool test_slot_matches(uint8_t slot, const uint8_t *expected, size_t expected_size) {
    uint8_t output[128] = { 0 };
    size_t written = 0;
    return otp_container_read_slot(slot, output, sizeof(output), &written) == PICOKEYS_OK && written == expected_size && memcmp(output, expected, expected_size) == 0;
}

static void test_power_loss_swap(const uint8_t *secret0, size_t secret0_size, const uint8_t *metadata0, size_t metadata0_size, const uint8_t *secret1, size_t secret1_size, const uint8_t *metadata1, size_t metadata1_size) {
    test_reset();
    assert(otp_container_write_slot(0, secret0, secret0_size, metadata0, metadata0_size) == PICOKEYS_OK);
    assert(otp_container_write_slot(1, secret1, secret1_size, metadata1, metadata1_size) == PICOKEYS_OK);
    power_loss_event = 0;
    assert(otp_container_swap_slots(0, true, secret0, secret0_size, metadata0, metadata0_size, 1, true, secret1, secret1_size, metadata1, metadata1_size) == PICOKEYS_OK);
    size_t swap_events = power_loss_event;
    assert(swap_events > 0);

    for (size_t failed_event = 1; failed_event <= swap_events; failed_event++) {
        test_reset();
        assert(otp_container_write_slot(0, secret0, secret0_size, metadata0, metadata0_size) == PICOKEYS_OK);
        assert(otp_container_write_slot(1, secret1, secret1_size, metadata1, metadata1_size) == PICOKEYS_OK);
        if (setjmp(power_loss_env) == 0) {
            power_loss_event = 0;
            power_loss_at = failed_event;
            power_loss_armed = true;
            (void)otp_container_swap_slots(0, true, secret0, secret0_size, metadata0, metadata0_size, 1, true, secret1, secret1_size, metadata1, metadata1_size);
            assert(false);
        }
        test_reboot();
        bool previous = test_slot_matches(0, secret0, secret0_size) && test_slot_matches(1, secret1, secret1_size);
        bool swapped = test_slot_matches(0, secret1, secret1_size) && test_slot_matches(1, secret0, secret0_size);
        assert(previous || swapped);
    }
}

int main(void) {
    static const uint8_t secret0[] = { 0x10, 0x11, 0x12, 0x13 };
    static const uint8_t secret1[] = { 0x20, 0x21, 0x22 };
    static const uint8_t updated0[] = { 0x30, 0x31, 0x32, 0x33, 0x34 };
    static const uint8_t metadata0[] = { 0x40, 0x41 };
    static const uint8_t metadata1[] = { 0x50, 0x51 };
    static const uint8_t updated_metadata0[] = { 0x60, 0x61 };

    for (size_t i = 0; i < sizeof(root_key); i++) {
        root_key[i] = (uint8_t)(i + 1u);
    }

    assert(otp_container_write_slot(0, secret0, sizeof(secret0), metadata0, sizeof(metadata0)) == PICOKEYS_OK);
    assert(otp_container_is_marker(file_search(EF_OTP_SLOT1)));
    assert(otp_container_has_slot(0));
    test_read_slot(0, secret0, sizeof(secret0));
    file_t *secret_record = file_search(0xb800u);
    assert(file_has_data(secret_record));
    assert(!test_contains(file_get_data(secret_record), file_get_size(secret_record), secret0, sizeof(secret0)));

    assert(otp_container_write_slot(0, updated0, sizeof(updated0), updated_metadata0, sizeof(updated_metadata0)) == PICOKEYS_OK);
    assert(otp_container_write_slot(1, secret1, sizeof(secret1), metadata1, sizeof(metadata1)) == PICOKEYS_OK);
    test_read_slot(0, updated0, sizeof(updated0));
    test_read_slot(1, secret1, sizeof(secret1));

    assert(otp_container_swap_slots(0, true, updated0, sizeof(updated0), updated_metadata0, sizeof(updated_metadata0), 1, true, secret1, sizeof(secret1), metadata1, sizeof(metadata1)) == PICOKEYS_OK);
    test_read_slot(0, secret1, sizeof(secret1));
    test_read_slot(1, updated0, sizeof(updated0));

    assert(otp_container_delete_slot(0) == PICOKEYS_OK);
    assert(!otp_container_has_slot(0));
    assert(otp_container_has_slot(1));
    assert(!file_search(EF_OTP_SLOT1));
    test_read_slot(1, updated0, sizeof(updated0));

    assert(otp_container_swap_slots(1, true, updated0, sizeof(updated0), updated_metadata0, sizeof(updated_metadata0), 2, false, NULL, 0, NULL, 0) == PICOKEYS_OK);
    assert(!otp_container_has_slot(1));
    assert(otp_container_has_slot(2));
    test_read_slot(2, updated0, sizeof(updated0));

    test_power_loss_swap(secret0, sizeof(secret0), metadata0, sizeof(metadata0), secret1, sizeof(secret1), metadata1, sizeof(metadata1));

    test_reset();
    static const uint8_t unrelated[] = { 0x70, 0x71, 0x72 };
    assert(file_put_data(file_new(0xb800u), unrelated, sizeof(unrelated)) == PICOKEYS_OK);
    assert(otp_container_write_slot(0, secret0, sizeof(secret0), metadata0, sizeof(metadata0)) == PICOKEYS_WRONG_DATA);
    assert(memcmp(file_get_data(file_search(0xb800u)), unrelated, sizeof(unrelated)) == 0);

    puts("fido_otp_container_test: OK");
    return 0;
}
