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

#ifndef _CTAP2_CBOR_H_
#define _CTAP2_CBOR_H_

#include "cbor.h"
#include "common.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"

extern uint8_t *driver_prepare_response();
extern void driver_exec_finished(size_t size_next);
extern int cbor_process(uint8_t, const uint8_t *data, size_t len);
extern const uint8_t aaguid[16];

extern const bool _btrue, _bfalse;
#define ptrue (&_btrue)
#define pfalse (&_bfalse)

#define CBOR_CHECK(f)           \
    do                          \
    {                           \
        error = f;      \
        if (error != CborNoError) \
        {                       \
            printf("Cannot encode CBOR [%s:%d]: %s (%d)\n", __FILE__, __LINE__, #f, error); \
            goto err; \
        } \
    } while (0)

#define CBOR_FREE(x) \
    do               \
    {                \
        if (x)       \
        {            \
            free(x); \
            x = NULL; \
        }            \
    } while (0)

#define CBOR_ERROR(e) \
    do                \
    {                 \
        error = e;    \
        printf("Cbor ERROR [%s:%d]: %d\n", __FILE__, __LINE__, e); \
        goto err;     \
    } while (0)

#define CBOR_ASSERT(c)                      \
    do                                      \
    {                                       \
        if (!c)                             \
        {                                   \
            error = CborErrorImproperValue; \
            printf("Cbor ASSERT [%s:%d]: %s\n", __FILE__, __LINE__, #c); \
            goto err;                       \
        }                                   \
    } while (0)

#define PINUVAUTHTOKEN_MC           0x1
#define PINUVAUTHTOKEN_GA           0x2
#define PINUVAUTHTOKEN_CM           0x4
#define PINUVAUTHTOKEN_BE           0x8
#define PINUVAUTHTOKEN_LBW         0x10
#define PINUVAUTHTOKEN_ACFG        0x20

typedef struct CborByteString {
    uint8_t *data;
    size_t len;
    bool present;
    bool nofree;
} CborByteString;

typedef struct CborCharString {
    char *data;
    size_t len;
    bool present;
    bool nofree;
} CborCharString;

#define CBOR_FREE_BYTE_STRING(v) \
    do                           \
    {                            \
        if ((v).nofree != true) \
        CBOR_FREE((v).data);  \
        else \
        (v).data = NULL; \
        (v).len = 0; \
        (v).present = false; \
    } while (0)

#define CBOR_PARSE_MAP_START(_p, _n)                   \
    CBOR_ASSERT(cbor_value_is_map(&(_p)) == true); \
    CborValue _f##_n; \
    CBOR_CHECK(cbor_value_enter_container(&(_p), &(_f##_n))); \
    while (cbor_value_at_end(&(_f##_n)) == false)

#define CBOR_PARSE_ARRAY_START(_p, _n)                   \
    CBOR_ASSERT(cbor_value_is_array(&(_p)) == true); \
    CborValue _f##_n; \
    CBOR_CHECK(cbor_value_enter_container(&(_p), &(_f##_n))); \
    while (cbor_value_at_end(&(_f##_n)) == false)

#define CBOR_FIELD_GET_UINT(v, _n) \
    do { \
        CBOR_ASSERT(cbor_value_is_unsigned_integer(&(_f##_n)) == true); \
        CBOR_CHECK(cbor_value_get_uint64(&(_f##_n), &(v))); \
        CBOR_CHECK(cbor_value_advance_fixed(&(_f##_n))); \
    } while (0)

#define CBOR_FIELD_GET_INT(v, _n) \
    do { \
        CBOR_ASSERT(cbor_value_is_integer(&(_f##_n)) == true); \
        CBOR_CHECK(cbor_value_get_int64(&(_f##_n), &(v))); \
        CBOR_CHECK(cbor_value_advance_fixed(&(_f##_n))); \
    } while (0)

#define CBOR_FIELD_GET_BYTES(v, _n) \
    do { \
        CBOR_ASSERT(cbor_value_is_byte_string(&(_f##_n)) == true); \
        CBOR_CHECK(cbor_value_dup_byte_string(&(_f##_n), &(v).data, &(v).len, &(_f##_n))); \
        (v).present = true; \
    } while (0)

#define CBOR_FIELD_GET_TEXT(v, _n) \
    do { \
        CBOR_ASSERT(cbor_value_is_text_string(&(_f##_n)) == true); \
        CBOR_CHECK(cbor_value_dup_text_string(&(_f##_n), &(v).data, &(v).len, &(_f##_n))); \
        (v).present = true; \
    } while (0)

#define CBOR_FIELD_GET_BOOL(v, _n) \
    do { \
        CBOR_ASSERT(cbor_value_is_boolean(&(_f##_n)) == true); \
        bool val; \
        CBOR_CHECK(cbor_value_get_boolean(&(_f##_n), &val)); \
        v = (val == true ? ptrue : pfalse); \
        CBOR_CHECK(cbor_value_advance_fixed(&(_f##_n))); \
    } while (0)

#define CBOR_FIELD_GET_KEY_TEXT(_n) \
    CBOR_ASSERT(cbor_value_is_text_string(&(_f##_n)) == true); \
    char _fd##_n[64]; \
    size_t _fdl##_n = sizeof(_fd##_n); \
    CBOR_CHECK(cbor_value_copy_text_string(&(_f##_n), _fd##_n, &_fdl##_n, &(_f##_n)))

#define CBOR_FIELD_KEY_TEXT_VAL_TEXT(_n, _t, _v) \
    if (strcmp(_fd##_n, _t) == 0) { \
        CBOR_ASSERT(cbor_value_is_text_string(&_f##_n) == true); \
        CBOR_CHECK(cbor_value_dup_text_string(&(_f##_n), &(_v).data, &(_v).len, &(_f##_n))); \
        (_v).present = true; \
        continue; \
    }

#define CBOR_FIELD_KEY_TEXT_VAL_BYTES(_n, _t, _v) \
    if (strcmp(_fd##_n, _t) == 0) { \
        CBOR_ASSERT(cbor_value_is_byte_string(&_f##_n) == true); \
        CBOR_CHECK(cbor_value_dup_byte_string(&(_f##_n), &(_v).data, &(_v).len, &(_f##_n))); \
        (_v).present = true; \
        continue; \
    }

#define CBOR_FIELD_KEY_TEXT_VAL_INT(_n, _t, _v) \
    if (strcmp(_fd##_n, _t) == 0) { \
        CBOR_FIELD_GET_INT(_v, _n); \
        continue; \
    }

#define CBOR_FIELD_KEY_TEXT_VAL_UINT(_n, _t, _v) \
    if (strcmp(_fd##_n, _t) == 0) { \
        CBOR_FIELD_GET_UINT(_v, _n); \
        continue; \
    }

#define CBOR_FIELD_KEY_TEXT_VAL_BOOL(_n, _t, _v) \
    if (strcmp(_fd##_n, _t) == 0) { \
        CBOR_FIELD_GET_BOOL(_v, _n); \
        continue; \
    }

#define CBOR_PARSE_MAP_END(_p, _n)  \
    CBOR_CHECK(cbor_value_leave_container(&(_p), &(_f##_n)))

#define CBOR_PARSE_ARRAY_END(_p, _n)  CBOR_PARSE_MAP_END(_p, _n)

#define CBOR_ADVANCE(_n) CBOR_CHECK(cbor_value_advance(&_f##_n));

#define CBOR_APPEND_KEY_UINT_VAL_BYTES(p, k, v) \
    do { \
        if ((v).data && (v).len > 0) { \
            CBOR_CHECK(cbor_encode_uint(&(p), (k))); \
            CBOR_CHECK(cbor_encode_byte_string(&(p), (v).data, (v).len)); \
        } } while (0)

#define CBOR_APPEND_KEY_UINT_VAL_STRING(p, k, v) \
    do { \
        if ((v).data && (v).len > 0) { \
            CBOR_CHECK(cbor_encode_uint(&(p), (k))); \
            CBOR_CHECK(cbor_encode_text_stringz(&(p), (v).data)); \
        } } while (0)


#define CBOR_APPEND_KEY_UINT_VAL_UINT(p, k, v) \
    do { \
        CBOR_CHECK(cbor_encode_uint(&(p), (k))); \
        CBOR_CHECK(cbor_encode_uint(&(p), (v))); \
    } while (0)

#define CBOR_APPEND_KEY_UINT_VAL_INT(p, k, v) \
    do { \
        CBOR_CHECK(cbor_encode_int(&(p), (k))); \
        CBOR_CHECK(cbor_encode_int(&(p), (v))); \
    } while (0)

#define CBOR_APPEND_KEY_UINT_VAL_BOOL(p, k, v) \
    do { \
        CBOR_CHECK(cbor_encode_uint(&(p), (k))); \
        CBOR_CHECK(cbor_encode_boolean(&(p), (v))); \
    } while (0)

#define CBOR_APPEND_KEY_UINT_VAL_PBOOL(p, k, v) \
    do { \
        if (v != NULL) { \
            CBOR_CHECK(cbor_encode_uint(&(p), (k))); \
            CBOR_CHECK(cbor_encode_boolean(&(p), v == ptrue ? true : false)); \
        } } while (0)

extern CborError COSE_key(mbedtls_ecp_keypair *, CborEncoder *, CborEncoder *);
extern CborError COSE_key_shared(mbedtls_ecdh_context *key, CborEncoder *mapEncoderParent, CborEncoder *mapEncoder);
extern CborError COSE_public_key(int alg, CborEncoder *mapEncoderParent, CborEncoder *mapEncoder);

#endif //_CTAP2_CBOR_H_
