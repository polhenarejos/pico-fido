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

#ifndef _OTP_CONTAINER_H_
#define _OTP_CONTAINER_H_

#include "file.h"

#define FIDO_OTP_SLOT_COUNT 4u

bool otp_container_is_marker(const file_t *file);
bool otp_container_has_slot(uint8_t slot);
int otp_container_read_slot(uint8_t slot, uint8_t *data, size_t capacity, size_t *written);
int otp_container_write_slot(uint8_t slot, const uint8_t *data, size_t data_size, const uint8_t *metadata, size_t metadata_size);
int otp_container_delete_slot(uint8_t slot);
int otp_container_swap_slots(uint8_t slot1, bool present1, const uint8_t *data1, size_t data1_size, const uint8_t *metadata1, size_t metadata1_size, uint8_t slot2, bool present2, const uint8_t *data2, size_t data2_size, const uint8_t *metadata2, size_t metadata2_size);

#endif // _OTP_CONTAINER_H_
