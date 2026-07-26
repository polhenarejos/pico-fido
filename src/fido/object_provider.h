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

#ifndef _OBJECT_PROVIDER_H_
#define _OBJECT_PROVIDER_H_

#include "object_container.h"

#define FIDO_OBJECT_NAMESPACE 0x0002u

const file_object_authenticator_t *fido_object_manifest_authenticator(void);
const file_object_record_protector_t *fido_object_record_protector(void);
const file_object_authenticator_t *fido_object_legacy_manifest_authenticator(void);
const file_object_record_protector_t *fido_object_legacy_record_protector(void);

#endif // _OBJECT_PROVIDER_H_
