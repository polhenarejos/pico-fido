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

#ifndef _OATH_CONTAINER_H_
#define _OATH_CONTAINER_H_

#include "file.h"

#define FIDO_OATH_CONTAINER_KIND 0x0002u
#define FIDO_OATH_OBJECT_CREDENTIAL 0x0001u
#define FIDO_OATH_OBJECT_METADATA 0x0002u

bool oath_container_is_marker(const file_t *file);
bool oath_container_can_create(uint8_t slot);
int oath_container_create(uint8_t slot, const uint8_t *credential, size_t credential_size, const uint8_t *metadata, size_t metadata_size);
int oath_container_object_size(uint8_t slot, uint16_t object_type, uint32_t *object_size);
int oath_container_read(uint8_t slot, uint16_t object_type, byte_buffer_t *data);
int oath_container_update(uint8_t slot, const uint8_t *credential, size_t credential_size, const uint8_t *metadata, size_t metadata_size);
int oath_container_delete(uint8_t slot);
int oath_container_purge(uint8_t slot);

#endif // _OATH_CONTAINER_H_
