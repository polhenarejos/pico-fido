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

#ifndef ENABLE_EMULATION
#include "pico/stdlib.h"
#endif
#include "hid/ctap_hid.h"
#include "ctap.h"
#include "fido.h"
#include "usb.h"
#include "apdu.h"
#include "management.h"
#include "ctap2_cbor.h"

const bool _btrue = true, _bfalse = false;

int cbor_reset();
int cbor_get_info();
int cbor_make_credential(const uint8_t *data, size_t len);
int cbor_client_pin(const uint8_t *data, size_t len);
int cbor_get_assertion(const uint8_t *data, size_t len, bool next);
int cbor_get_next_assertion(const uint8_t *data, size_t len);
int cbor_selection();
int cbor_cred_mgmt(const uint8_t *data, size_t len);
int cbor_config(const uint8_t *data, size_t len);
int cbor_vendor(const uint8_t *data, size_t len);
int cbor_large_blobs(const uint8_t *data, size_t len);

const uint8_t aaguid[16] =
{ 0x89, 0xFB, 0x94, 0xB7, 0x06, 0xC9, 0x36, 0x73, 0x9B, 0x7E, 0x30, 0x52, 0x6D, 0x96, 0x81, 0x45 };                          // First 16 bytes of SHA256("Pico FIDO2")

const uint8_t *cbor_data = NULL;
size_t cbor_len = 0;
uint8_t cmd = 0;

int cbor_parse(uint8_t cmd, const uint8_t *data, size_t len) {
    if (len == 0 && cmd == CTAPHID_CBOR) {
        return CTAP1_ERR_INVALID_LEN;
    }
    if (len > 0) {
        DEBUG_DATA(data + 1, len - 1);
    }
    if (cap_supported(CAP_FIDO2)) {
        driver_prepare_response_hid();
        if (cmd == CTAPHID_CBOR) {
            if (data[0] == CTAP_MAKE_CREDENTIAL) {
                return cbor_make_credential(data + 1, len - 1);
            }
            if (data[0] == CTAP_GET_INFO) {
                return cbor_get_info();
            }
            else if (data[0] == CTAP_RESET) {
                return cbor_reset();
            }
            else if (data[0] == CTAP_CLIENT_PIN) {
                return cbor_client_pin(data + 1, len - 1);
            }
            else if (data[0] == CTAP_GET_ASSERTION) {
                return cbor_get_assertion(data + 1, len - 1, false);
            }
            else if (data[0] == CTAP_GET_NEXT_ASSERTION) {
                return cbor_get_next_assertion(data + 1, len - 1);
            }
            else if (data[0] == CTAP_SELECTION) {
                return cbor_selection();
            }
            else if (data[0] == CTAP_CREDENTIAL_MGMT || data[0] == 0x41) {
                return cbor_cred_mgmt(data + 1, len - 1);
            }
            else if (data[0] == CTAP_CONFIG) {
                return cbor_config(data + 1, len - 1);
            }
            else if (data[0] == CTAP_LARGE_BLOBS) {
                return cbor_large_blobs(data + 1, len - 1);
            }
        }
        else if (cmd == CTAP_VENDOR_CBOR) {
            return cbor_vendor(data, len);
        }
    }
    return CTAP1_ERR_INVALID_CMD;
}

#ifndef ENABLE_EMULATION
void cbor_thread() {

    card_init_core1();
    while (1) {
        uint32_t m;
        queue_remove_blocking(&usb_to_card_q, &m);

        if (m == EV_EXIT) {

            break;
        }
        apdu.sw = cbor_parse(cmd, cbor_data, cbor_len);
        if (apdu.sw == 0) {
            DEBUG_DATA(res_APDU + 1, res_APDU_size);
        }

        finished_data_size = res_APDU_size + 1;

        uint32_t flag = EV_EXEC_FINISHED;
        queue_add_blocking(&card_to_usb_q, &flag);
    }
}
#endif

int cbor_process(uint8_t last_cmd, const uint8_t *data, size_t len) {
    cbor_data = data;
    cbor_len = len;
    cmd = last_cmd;
    res_APDU = ctap_resp->init.data + 1;
    res_APDU_size = 0;
    return 1;
}

CborError COSE_key_params(int crv, int alg, mbedtls_ecp_group *grp, mbedtls_ecp_point *Q, CborEncoder *mapEncoderParent, CborEncoder *mapEncoder) {
    CborError error = CborNoError;
    int kty = 1;
    if (crv == FIDO2_CURVE_P256 || crv == FIDO2_CURVE_P384 || crv == FIDO2_CURVE_P521 || crv == FIDO2_CURVE_P256K1) {
        kty = 2;
    }

    CBOR_CHECK(cbor_encoder_create_map(mapEncoderParent, mapEncoder, 5));

    CBOR_CHECK(cbor_encode_uint(mapEncoder, 1));
    CBOR_CHECK(cbor_encode_uint(mapEncoder, kty));

    CBOR_CHECK(cbor_encode_uint(mapEncoder, 3));
    CBOR_CHECK(cbor_encode_negative_int(mapEncoder, -alg));

    CBOR_CHECK(cbor_encode_negative_int(mapEncoder, 1));
    CBOR_CHECK(cbor_encode_uint(mapEncoder, crv));


    CBOR_CHECK(cbor_encode_negative_int(mapEncoder, 2));
    uint8_t pkey[67];
    if (kty == 2) {
        size_t plen = mbedtls_mpi_size(&grp->P);
        CBOR_CHECK(mbedtls_mpi_write_binary(&Q->X, pkey, plen));
        CBOR_CHECK(cbor_encode_byte_string(mapEncoder, pkey, plen));

        CBOR_CHECK(cbor_encode_negative_int(mapEncoder, 3));

        CBOR_CHECK(mbedtls_mpi_write_binary(&Q->Y, pkey, plen));
        CBOR_CHECK(cbor_encode_byte_string(mapEncoder, pkey, plen));
    }
    else {
        size_t olen = 0;
        CBOR_CHECK(mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, pkey, sizeof(pkey)));
        CBOR_CHECK(cbor_encode_byte_string(mapEncoder, pkey, olen));
    }

    CBOR_CHECK(cbor_encoder_close_container(mapEncoderParent, mapEncoder));
    err:
    return error;
}
CborError COSE_key(mbedtls_ecp_keypair *key, CborEncoder *mapEncoderParent, CborEncoder *mapEncoder) {
    int crv = mbedtls_curve_to_fido(key->grp.id), alg = 0;
    if (key->grp.id == MBEDTLS_ECP_DP_SECP256R1) {
        alg = FIDO2_ALG_ES256;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_SECP384R1) {
        alg = FIDO2_ALG_ES384;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_SECP521R1) {
        alg = FIDO2_ALG_ES512;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_SECP256K1) {
        alg = FIDO2_ALG_ES256K;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_CURVE25519) {
        alg = FIDO2_ALG_ECDH_ES_HKDF_256;
    }
    else if (key->grp.id == MBEDTLS_ECP_DP_ED25519) {
        alg = FIDO2_ALG_EDDSA;
    }
    return COSE_key_params(crv, alg, &key->grp, &key->Q, mapEncoderParent, mapEncoder);
}
CborError COSE_key_shared(mbedtls_ecdh_context *key, CborEncoder *mapEncoderParent, CborEncoder *mapEncoder) {
    int crv = mbedtls_curve_to_fido(key->ctx.mbed_ecdh.grp.id), alg = FIDO2_ALG_ECDH_ES_HKDF_256;
    return COSE_key_params(crv, alg, &key->ctx.mbed_ecdh.grp, &key->ctx.mbed_ecdh.Q, mapEncoderParent, mapEncoder);
}
CborError COSE_public_key(int alg, CborEncoder *mapEncoderParent, CborEncoder *mapEncoder) {
    CborError error = CborNoError;
    CBOR_CHECK(cbor_encoder_create_map(mapEncoderParent, mapEncoder, 2));
    CBOR_CHECK(cbor_encode_text_stringz(mapEncoder, "alg"));
    CBOR_CHECK(cbor_encode_negative_int(mapEncoder, -alg));
    CBOR_CHECK(cbor_encode_text_stringz(mapEncoder, "type"));
    CBOR_CHECK(cbor_encode_text_stringz(mapEncoder, "public-key"));
    CBOR_CHECK(cbor_encoder_close_container(mapEncoderParent, mapEncoder));
    err:
    return error;
}
CborError COSE_read_key(CborValue *f, int64_t *kty, int64_t *alg, int64_t *crv, CborByteString *kax, CborByteString *kay) {
    int64_t kkey = 0;
    CborError error = CborNoError;
    CBOR_PARSE_MAP_START(*f, 0)
    {
        CBOR_FIELD_GET_INT(kkey, 0);
        if (kkey == 1) {
            CBOR_FIELD_GET_INT(*kty, 0);
        }
        else if (kkey == 3) {
            CBOR_FIELD_GET_INT(*alg, 0);
        }
        else if (kkey == -1) {
            CBOR_FIELD_GET_INT(*crv, 0);
        }
        else if (kkey == -2) {
            CBOR_FIELD_GET_BYTES(*kax, 0);
        }
        else if (kkey == -3) {
            CBOR_FIELD_GET_BYTES(*kay, 0);
        }
        else {
            CBOR_ADVANCE(0);
        }
    }
    CBOR_PARSE_MAP_END(*f, 0);
    err:
    return error;
}