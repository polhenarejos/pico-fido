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

#ifndef _RESIDENT_CONTAINER_H_
#define _RESIDENT_CONTAINER_H_

#include "file.h"
#include "fido.h"

#define FIDO_RESIDENT_CONTAINER_KIND 0x0001u
#define FIDO_RESIDENT_OBJECT_RP_ID_HASH 0x0001u
#define FIDO_RESIDENT_OBJECT_CLIENT_ID 0x0002u
#define FIDO_RESIDENT_OBJECT_CREDENTIAL 0x0003u
#define FIDO_RESIDENT_OBJECT_PUBLIC_KEY 0x0004u

bool resident_container_is_marker(const file_t *file);
bool resident_container_can_create(uint8_t slot);
int resident_container_create(uint8_t slot, const uint8_t rp_id_hash[RP_ID_HASH_LEN], const uint8_t *client_id, size_t client_id_size, const uint8_t *credential, size_t credential_size, const uint8_t *public_key, size_t public_key_size);
int resident_container_object_size(uint8_t slot, uint16_t object_type, uint32_t *object_size);
int resident_container_read(uint8_t slot, uint16_t object_type, byte_buffer_t *data);
int resident_container_update_credential(uint8_t slot, const uint8_t *credential, size_t credential_size);
int resident_container_delete(uint8_t slot);

#endif // _RESIDENT_CONTAINER_H_
