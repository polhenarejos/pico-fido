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

#ifndef _VAULT_H_
#define _VAULT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ctap2_cbor.h"
#include "credential.h"
#include "serial.h"
#include "fs/vault_container.h"

#define VAULT_X448_BYTES       PICOKEYS_VAULT_X448_BYTES
#define VAULT_APP_ID 0u
#define VAULT_CREDENTIAL_METADATA_MAX 512
#define VAULT_KEY_BYTES PICOKEYS_VAULT_KEY_SIZE
#define VAULT_ID_BYTES PICOKEYS_VAULT_KEY_SIZE
#define VAULT_ENROLL_CHALLENGE_BYTES PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES
#define VAULT_ENROLL_CERT_MAX PICOKEYS_VAULT_ENROLL_CERT_MAX
#define VAULT_ENROLL_MIN_PACKET_LEN PICOKEYS_VAULT_ENROLL_MIN_PACKET_LEN
#define VAULT_LABEL_MAX 64
#define VAULT_ENROLL_PLAIN_MAX PICOKEYS_VAULT_ENROLL_PLAIN_MAX
#define VAULT_STORE_LEN PICOKEYS_VAULT_RECORD_SIZE
#define VAULT_BLOB_SERIAL_MAX 16
#define VAULT_BLOB_SERIAL_LEN_OFFSET (4 + VAULT_ID_BYTES + VAULT_ID_BYTES)
#define VAULT_BLOB_SERIAL_OFFSET (VAULT_BLOB_SERIAL_LEN_OFFSET + 1)
#define VAULT_BLOB_ALGORITHM_OFFSET (VAULT_BLOB_SERIAL_OFFSET + VAULT_BLOB_SERIAL_MAX)
#define VAULT_BLOB_HEADER_LEN (VAULT_BLOB_ALGORITHM_OFFSET + 1)
#define VAULT_BLOB_NONCE_BYTES PICOKEYS_VAULT_BLOB_NONCE_SIZE
#define VAULT_PLAIN_MAX (MAX_CRED_ID_LENGTH + VAULT_CREDENTIAL_METADATA_MAX + 256)
#define VAULT_BLOB_MAX (VAULT_BLOB_HEADER_LEN + 24 + VAULT_PLAIN_MAX + 32)
extern int vault_load_key(uint8_t key[VAULT_KEY_BYTES]);
extern int vault_enrollment_finish(const uint8_t *packet, size_t packet_len);
extern int vault_export_blob(const uint8_t *requested_id, size_t requested_id_len, uint8_t algorithm, uint8_t *blob, size_t blob_capacity, size_t *blob_len, uint8_t *metadata, size_t metadata_capacity, size_t *metadata_len);
extern int vault_import_blob(const uint8_t *blob, size_t blob_len);
extern int vault_encode_credential_metadata(const Credential *credential, const uint8_t rp_id_hash[RP_ID_HASH_LEN], uint8_t *buffer, size_t buffer_len, size_t *metadata_len);
extern CborError vault_vendor_command(uint64_t vendorCmd, CborByteString vendorParam, CborByteString pinUvAuthParam, uint64_t pinUvAuthProtocol, const uint8_t *raw_vendor_params, size_t raw_vendor_params_len, uint64_t vault_algorithm, bool vault_algorithm_present, CborEncoder encoder, size_t *resp_size, bool *response_handled, int *ctap_error);

#endif
