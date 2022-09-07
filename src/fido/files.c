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

#include "file.h"
#include "files.h"

file_t file_entries[] = {
    {.fid = 0x3f00, .parent = 0xff, .name = NULL, .type = FILE_TYPE_DF, .data = NULL, .ef_structure = 0, .acl = {0}},                                                                     // MF
    {.fid = EF_KEY_DEV, .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff}},  // Device Key
    {.fid = EF_EE_DEV,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff}},   // End Entity Certificate Device
    {.fid = EF_COUNTER,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff}},   // Global counter
    { .fid = 0x0000, .parent = 0xff, .name = NULL, .type = FILE_TYPE_UNKNOWN, .data = NULL, .ef_structure = 0, .acl = {0} } //end
};

const file_t *MF = &file_entries[0];
const file_t *file_last = &file_entries[sizeof(file_entries)/sizeof(file_t)-1];
file_t *ef_keydev = NULL;
file_t *ef_certdev = NULL;
file_t *ef_counter = NULL;
