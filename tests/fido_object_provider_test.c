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
#include "object_provider.h"

#include <assert.h>
#include <stdio.h>

#define TEST_AAD_NAMESPACE_OFFSET 5u
#define TEST_AAD_KIND_OFFSET 7u
#define TEST_AAD_CONTAINER_ID_OFFSET 9u
#define TEST_AAD_TYPE_OFFSET 13u
#define TEST_AAD_TAG_OFFSET 15u
#define TEST_AAD_GENERATION_OFFSET 17u
#define TEST_AAD_LOGICAL_SIZE_OFFSET 21u
#define TEST_AAD_POLICY_ID_OFFSET 25u
#define TEST_AAD_POLICY_HASH_OFFSET 27u
#define TEST_AAD_KEY_DOMAIN_OFFSET 43u
#define TEST_AAD_PROTECTION_OFFSET 44u
#define TEST_AAD_FLAGS_OFFSET 45u
#define TEST_AAD_RECORD_ID_OFFSET 47u

static uint8_t test_device_key[32];
static uint8_t test_public_root[32];
static bool test_device_key_available = true;

void derive_kbase(uint8_t kbase[32]) {
    memcpy(kbase, test_public_root, sizeof(test_public_root));
}

int load_keydev(uint8_t key[32]) {
    if (!test_device_key_available) {
        return PICOKEYS_NO_LOGIN;
    }
    memcpy(key, test_device_key, sizeof(test_device_key));
    return PICOKEYS_OK;
}

static void test_root_reset(void) {
    for (size_t i = 0; i < sizeof(test_device_key); i++) {
        test_device_key[i] = (uint8_t)(i + 1);
        test_public_root[i] = (uint8_t)(0x80u + i);
    }
    test_device_key_available = true;
}

static file_object_record_identity_t test_identity(uint8_t protection, uint8_t key_domain) {
    file_object_record_identity_t identity = {
        .namespace_id = FIDO_OBJECT_NAMESPACE,
        .container_kind = 1,
        .container_id = 0x01020304,
        .object_type = 5,
        .object_tag = 1,
        .generation = 3,
        .logical_size = 5,
        .policy_id = 0x0201,
        .key_domain = key_domain,
        .protection = protection,
        .flags = FILE_OBJECT_FLAG_NON_EXPORTABLE,
        .record_id = UINT64_C(0x0102030405060708)
    };
    for (size_t i = 0; i < sizeof(identity.policy_hash); i++) {
        identity.policy_hash[i] = (uint8_t)(0xb0 + i);
    }
    return identity;
}

static void test_aad_build(const file_object_record_identity_t *identity, uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE]) {
    memset(aad, 0, FILE_OBJECT_RECORD_AAD_SIZE);
    memcpy(aad, "PKOR", 4);
    aad[4] = FILE_OBJECT_RECORD_FORMAT_VERSION;
    put_uint16_be(identity->namespace_id, aad + TEST_AAD_NAMESPACE_OFFSET);
    put_uint16_be(identity->container_kind, aad + TEST_AAD_KIND_OFFSET);
    put_uint32_be(identity->container_id, aad + TEST_AAD_CONTAINER_ID_OFFSET);
    put_uint16_be(identity->object_type, aad + TEST_AAD_TYPE_OFFSET);
    put_uint16_be(identity->object_tag, aad + TEST_AAD_TAG_OFFSET);
    put_uint32_be(identity->generation, aad + TEST_AAD_GENERATION_OFFSET);
    put_uint32_be(identity->logical_size, aad + TEST_AAD_LOGICAL_SIZE_OFFSET);
    put_uint16_be(identity->policy_id, aad + TEST_AAD_POLICY_ID_OFFSET);
    memcpy(aad + TEST_AAD_POLICY_HASH_OFFSET, identity->policy_hash, FILE_OBJECT_POLICY_HASH_SIZE);
    aad[TEST_AAD_KEY_DOMAIN_OFFSET] = identity->key_domain;
    aad[TEST_AAD_PROTECTION_OFFSET] = identity->protection;
    put_uint16_be(identity->flags, aad + TEST_AAD_FLAGS_OFFSET);
    put_uint64_be(identity->record_id, aad + TEST_AAD_RECORD_ID_OFFSET);
    put_uint64_be(identity->record_id, nonce);
    put_uint32_be(identity->generation, nonce + sizeof(uint64_t));
}

static void test_manifest_authentication(void) {
    static const uint8_t data[] = { 1, 2, 3, 4, 5 };
    const file_object_authenticator_t *auth = fido_object_manifest_authenticator();
    uint8_t first[FILE_OBJECT_AUTH_TAG_SIZE];
    uint8_t second[FILE_OBJECT_AUTH_TAG_SIZE];

    assert(auth != NULL);
    assert(auth->start(auth->ctx) == PICOKEYS_OK);
    assert(auth->update(auth->ctx, data, 2) == PICOKEYS_OK);
    assert(auth->update(auth->ctx, data + 2, sizeof(data) - 2) == PICOKEYS_OK);
    assert(auth->finish(auth->ctx, first) == PICOKEYS_OK);
    assert(auth->start(auth->ctx) == PICOKEYS_OK);
    assert(auth->update(auth->ctx, data, sizeof(data)) == PICOKEYS_OK);
    assert(auth->finish(auth->ctx, second) == PICOKEYS_OK);
    assert(memcmp(first, second, sizeof(first)) == 0);

    test_device_key_available = false;
    assert(auth->start(auth->ctx) == PICOKEYS_OK);
    auth->abort(auth->ctx);
    test_device_key_available = true;
}

static void test_authenticated_public_record(void) {
    static const uint8_t plaintext[] = { 0x10, 0x20, 0x30, 0x40, 0x50 };
    const file_object_record_protector_t *protector = fido_object_record_protector();
    file_object_record_identity_t identity = test_identity(FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC, 0);
    uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE];
    uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE];
    uint8_t stored[sizeof(plaintext)];
    uint8_t output[sizeof(plaintext)];
    uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE];

    assert(protector != NULL);
    test_aad_build(&identity, aad, nonce);
    assert(protector->seal(protector->ctx, &identity, nonce, aad, plaintext, sizeof(plaintext), stored, tag) == PICOKEYS_OK);
    assert(memcmp(stored, plaintext, sizeof(plaintext)) == 0);

    test_device_key_available = false;
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_OK);
    assert(memcmp(output, plaintext, sizeof(plaintext)) == 0);
    test_device_key_available = true;

    stored[0] ^= 0x01;
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_WRONG_SIGNATURE);
}

static void test_secret_record(void) {
    static const uint8_t plaintext[] = { 0x10, 0x20, 0x30, 0x40, 0x50 };
    const file_object_record_protector_t *protector = fido_object_record_protector();
    file_object_record_identity_t identity = test_identity(FILE_OBJECT_PROTECTION_AEAD_SECRET, 0);
    uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE];
    uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE];
    uint8_t stored[sizeof(plaintext)];
    uint8_t output[sizeof(plaintext)];
    uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE];

    assert(protector != NULL);
    test_aad_build(&identity, aad, nonce);
    assert(protector->seal(protector->ctx, &identity, nonce, aad, plaintext, sizeof(plaintext), stored, tag) == PICOKEYS_OK);
    assert(memcmp(stored, plaintext, sizeof(plaintext)) != 0);
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_OK);
    assert(memcmp(output, plaintext, sizeof(plaintext)) == 0);

    test_device_key_available = false;
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_NO_LOGIN);
    test_device_key_available = true;

    tag[0] ^= 0x01;
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_WRONG_SIGNATURE);

    identity = test_identity(FILE_OBJECT_PROTECTION_AEAD_SECRET, 1);
    test_aad_build(&identity, aad, nonce);
    assert(protector->seal(protector->ctx, &identity, nonce, aad, plaintext, sizeof(plaintext), stored, tag) == PICOKEYS_WRONG_DATA);
}

static void test_oath_secret_record(void) {
    static const uint8_t plaintext[] = { 0x61, 0x62, 0x63, 0x64, 0x65 };
    const file_object_record_protector_t *protector = fido_oath_object_record_protector();
    file_object_record_identity_t identity = test_identity(FILE_OBJECT_PROTECTION_AEAD_SECRET, 0);
    identity.namespace_id = FIDO_OATH_OBJECT_NAMESPACE;
    uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE];
    uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE];
    uint8_t stored[sizeof(plaintext)];
    uint8_t output[sizeof(plaintext)];
    uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE];

    assert(fido_oath_object_manifest_authenticator() != NULL);
    assert(protector != NULL);
    test_aad_build(&identity, aad, nonce);
    assert(protector->seal(protector->ctx, &identity, nonce, aad, plaintext, sizeof(plaintext), stored, tag) == PICOKEYS_OK);
    assert(memcmp(stored, plaintext, sizeof(plaintext)) != 0);

    test_device_key_available = false;
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_OK);
    assert(memcmp(output, plaintext, sizeof(plaintext)) == 0);
    test_device_key_available = true;

    identity.namespace_id = FIDO_OBJECT_NAMESPACE;
    test_aad_build(&identity, aad, nonce);
    assert(protector->seal(protector->ctx, &identity, nonce, aad, plaintext, sizeof(plaintext), stored, tag) == PICOKEYS_WRONG_DATA);
}

static void test_otp_secret_record(void) {
    static const uint8_t plaintext[] = { 0x71, 0x72, 0x73, 0x74, 0x75 };
    const file_object_record_protector_t *protector = fido_otp_object_record_protector();
    file_object_record_identity_t identity = test_identity(FILE_OBJECT_PROTECTION_AEAD_SECRET, 0);
    identity.namespace_id = FIDO_OTP_OBJECT_NAMESPACE;
    uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE];
    uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE];
    uint8_t stored[sizeof(plaintext)];
    uint8_t output[sizeof(plaintext)];
    uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE];

    assert(fido_otp_object_manifest_authenticator() != NULL);
    assert(protector != NULL);
    test_aad_build(&identity, aad, nonce);
    assert(protector->seal(protector->ctx, &identity, nonce, aad, plaintext, sizeof(plaintext), stored, tag) == PICOKEYS_OK);
    assert(memcmp(stored, plaintext, sizeof(plaintext)) != 0);

    test_device_key_available = false;
    assert(protector->unseal(protector->ctx, &identity, nonce, aad, stored, sizeof(stored), tag, output) == PICOKEYS_OK);
    assert(memcmp(output, plaintext, sizeof(plaintext)) == 0);
    test_device_key_available = true;

    identity.namespace_id = FIDO_OATH_OBJECT_NAMESPACE;
    test_aad_build(&identity, aad, nonce);
    assert(protector->seal(protector->ctx, &identity, nonce, aad, plaintext, sizeof(plaintext), stored, tag) == PICOKEYS_WRONG_DATA);
}

int main(void) {
    test_root_reset();
    test_manifest_authentication();
    test_root_reset();
    test_authenticated_public_record();
    test_root_reset();
    test_secret_record();
    test_root_reset();
    test_oath_secret_record();
    test_root_reset();
    test_otp_secret_record();
    puts("fido_object_provider_test: OK");
    return 0;
}
