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

#ifndef _CBOR_MAKE_CREDENTIAL_H_
#define _CBOR_MAKE_CREDENTIAL_H_

#include "ctap2_cbor.h"

typedef struct PublicKeyCredentialEntity
{
    CborCharString name;
} PublicKeyCredentialEntity;

typedef struct PublicKeyCredentialRpEntity
{
    PublicKeyCredentialEntity parent;
    CborCharString id;
} PublicKeyCredentialRpEntity;

typedef struct PublicKeyCredentialUserEntity
{
    PublicKeyCredentialEntity parent;
    CborByteString id;
    CborCharString displayName;
} PublicKeyCredentialUserEntity;

typedef struct PublicKeyCredentialParameters {
    CborCharString type;
    int64_t alg;
} PublicKeyCredentialParameters;

typedef struct PublicKeyCredentialDescriptor {
    CborCharString type;
    CborByteString id;
    CborCharString transports[8];
    size_t transports_len;
} PublicKeyCredentialDescriptor;


#endif //_CBOR_MAKE_CREDENTIAL_H_
