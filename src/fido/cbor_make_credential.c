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

#include "common.h"
#include "mbedtls/chachapoly.h"
#include "ctap2_cbor.h"
#include "cbor_make_credential.h"
#include "fido.h"
#include "ctap.h"
#include "files.h"
#include "random.h"
#include "hsm.h"
#include <math.h>
#include "apdu.h"

bool credential_verify(CborByteString *cred_id, const uint8_t *rp_id_hash) {
    if (cred_id->len < 4+12+16)
        return false;
    size_t cipher_len = cred_id->len - (4 + 12 + 16);
    uint8_t key[32], *iv = cred_id->data + 4, *cipher = cred_id->data + 4 + 12, *tag = cred_id->data - 16, *data = (uint8_t *)calloc(1, cipher_len);
    memset(key, 0, sizeof(key));
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    int ret = mbedtls_chachapoly_auth_decrypt(&chatx, cred_id->len - (4 + 12 + 16), iv, rp_id_hash, 32, tag, cipher, data);
    free(data);
    if (ret == 0)
        return true;
    return false;
}

int verify_user(CborByteString *clientDataHash, CborByteString *pinUvAuthParam) {
    return CborNoError;
}

int cbor_make_credential(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    CborByteString clientDataHash = {0}, pinUvAuthParam = {0};
    PublicKeyCredentialRpEntity rp = {0};
    PublicKeyCredentialUserEntity user = {0};
    PublicKeyCredentialParameters pubKeyCredParams[16] = {0};
    size_t pubKeyCredParams_len = 0;
    PublicKeyCredentialDescriptor excludeList[16] = {0};
    size_t excludeList_len = 0;
    CredOptions options = {0};
    uint64_t pinUvAuthProtocol = 0, enterpriseAttestation = 0, credProtect = 0;
    const bool *hmac_secret = NULL;
    uint8_t *cred_id = NULL, *aut_data = NULL;
    size_t resp_size = 0;

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1) {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 4 && val_c != val_u)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        if (val_u < val_c)
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        val_c = val_u + 1;
        if (val_u == 0x01) { // clientDataHash
            CBOR_FIELD_GET_BYTES(clientDataHash, 1);
        }
        else if (val_u == 0x02) { // rp
            CBOR_PARSE_MAP_START(_f1, 2) {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "id", rp.id);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "name", rp.parent.name);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x03) { // user
            CBOR_PARSE_MAP_START(_f1, 2) {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_BYTES(2, "id", user.id);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "name", user.parent.name);
                CBOR_FIELD_KEY_TEXT_VAL_TEXT(2, "displayName", user.displayName);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x04) { // pubKeyCredParams
            CBOR_PARSE_ARRAY_START(_f1, 2) {
                PublicKeyCredentialParameters *pk = &pubKeyCredParams[pubKeyCredParams_len];
                CBOR_PARSE_MAP_START(_f2, 3) {
                    CBOR_FIELD_GET_KEY_TEXT(3);
                    CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "type", pk->type);
                    CBOR_FIELD_KEY_TEXT_VAL_INT(3, "alg", pk->alg);
                }
                CBOR_PARSE_MAP_END(_f2, 3);
                pubKeyCredParams_len++;
            }
            CBOR_PARSE_ARRAY_END(_f1, 2);
        }
        else if (val_u == 0x05) { // excludeList
            CBOR_PARSE_ARRAY_START(_f1, 2) {
                    PublicKeyCredentialDescriptor *pc = &excludeList[excludeList_len];
                CBOR_PARSE_MAP_START(_f2, 3) {
                    CBOR_FIELD_GET_KEY_TEXT(3);
                    CBOR_FIELD_KEY_TEXT_VAL_BYTES(3, "id", pc->id);
                    CBOR_FIELD_KEY_TEXT_VAL_TEXT(3, "type", pc->type);
                    if (strcmp(_fd3, "transports") == 0) {
                        CBOR_PARSE_ARRAY_START(_f3, 4) {
                            CBOR_FIELD_GET_TEXT(pc->transports[pc->transports_len], 4);
                            pc->transports_len++;
                        }
                        CBOR_PARSE_ARRAY_END(_f3, 4);
                    }
                }
                CBOR_PARSE_MAP_END(_f2, 3);
                excludeList_len++;
            }
            CBOR_PARSE_ARRAY_END(_f1, 2);
        }
        else if (val_u == 0x06) { // extensions
            CBOR_PARSE_MAP_START(_f1, 2) {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "hmac-secret", hmac_secret);
                CBOR_FIELD_KEY_TEXT_VAL_UINT(2, "credProtect", credProtect);
                CBOR_ADVANCE(2);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x07) { // options
            options.present = true;
            CBOR_PARSE_MAP_START(_f1, 2) {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "rk", options.rk);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "up", options.up);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "uv", options.uv);
                CBOR_ADVANCE(2);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x08) { // pinUvAuthParam
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else if (val_u == 0x09) { // pinUvAuthProtocol
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x0A) { // enterpriseAttestation
            CBOR_FIELD_GET_UINT(enterpriseAttestation, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    uint8_t rp_id_hash[32];
    mbedtls_sha256((uint8_t *)rp.id.data, rp.id.len, rp_id_hash, 0);
    printf("IEEEEEE 1\n");
    int curve = -1, alg = 0;
    if (pubKeyCredParams_len == 0)
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);

    for (int i = 0; i < pubKeyCredParams_len; i++) {
        if (strcmp(pubKeyCredParams[i].type.data, "public-key") != 0)
            continue;
        if (pubKeyCredParams[i].alg == FIDO2_ALG_ES256)
            curve = FIDO2_CURVE_P256;
        else if (pubKeyCredParams[i].alg == FIDO2_ALG_ES384)
            curve = FIDO2_CURVE_P384;
        else if (pubKeyCredParams[i].alg == FIDO2_ALG_ES512)
            curve = FIDO2_CURVE_P521;
        else if (pubKeyCredParams[i].alg == 0) // no present
            curve = -1;
        else
            curve = 0;
        if (curve > 0) {
            alg = pubKeyCredParams[i].alg;
            break;
        }
    }
    if (curve == 0)
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_ALGORITHM);
    else if (curve == -1)
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);

    if (pinUvAuthParam.present == true) {
        if (pinUvAuthParam.len == 0 || pinUvAuthParam.data == NULL) {
            if (check_user_presence() == false)
                CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
            if (!file_has_data(ef_pin))
                CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
            else
                CBOR_ERROR(CTAP2_ERR_PIN_INVALID);
        }
        else {
            if (pinUvAuthProtocol == 0)
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2)
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
    }
    if (options.present) {
        if (options.uv == ptrue) { //5.3
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        if (options.up != NULL) { //5.6
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        //else if (options.up == NULL) //5.7
            //rup = ptrue;
    }
    if (pinUvAuthParam.present == false && options.uv == pfalse && file_has_data(ef_pin)) { //8.1
        CBOR_ERROR(CTAP2_ERR_PUAT_REQUIRED);
    }
    if (enterpriseAttestation > 0) {
        if (enterpriseAttestation != 1 && enterpriseAttestation != 2) { //9.2.1
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        //Unfinished. See 6.1.2.9
    }
    if (pinUvAuthParam.present == true) { //11.1
        int ret = verify_user(&clientDataHash, &pinUvAuthParam);
        if (ret != CborNoError)
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        //Check pinUvAuthToken permissions. See 6.1.2.11
    }
    printf("IEEEEEE 2\n");
    for (int e = 0; e < excludeList_len; e++) { //12.1
        if (excludeList[e].type.present == false || excludeList[e].id.present == false)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        if (strcmp(excludeList[e].type.data, "public-key") != 0)
            continue;
        if (credential_verify(&excludeList[e].id, rp_id_hash) == true)
            CBOR_ERROR(CTAP2_ERR_CREDENTIAL_EXCLUDED);
    }

    if (pinUvAuthParam.present && options.up == ptrue) { //14.1
        if (check_user_presence() == false)
            CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
        //rup = ptrue;
    }

    const known_app_t *ka = find_app_by_rp_id_hash(rp_id_hash);
    CborEncoder encoder, mapEncoder, mapEncoder2;
    uint8_t cbor_buf[1024];
    cbor_encoder_init(&encoder, cbor_buf, sizeof(cbor_buf), 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder,  CborIndefiniteLength));
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x01, rp.id);
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, rp_id_hash, 32));
    CBOR_APPEND_KEY_UINT_VAL_BYTES(mapEncoder, 0x03, user.id);
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x04, user.displayName);
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x05, user.displayName);
    CBOR_APPEND_KEY_UINT_VAL_UINT(mapEncoder, 0x06, 1);
    CBOR_APPEND_KEY_UINT_VAL_PBOOL(mapEncoder, 0x07, hmac_secret);
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
    CBOR_CHECK(cbor_encode_boolean(&mapEncoder, (!ka || ka->use_sign_count == ptrue)));
    if (alg != FIDO2_ALG_ES256 || curve != FIDO2_CURVE_P256) {
        CBOR_APPEND_KEY_UINT_VAL_UINT(mapEncoder, 0x09, alg);
        CBOR_APPEND_KEY_UINT_VAL_UINT(mapEncoder, 0x0A, curve);
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    size_t rs = cbor_encoder_get_buffer_size(&encoder, cbor_buf);
    size_t cred_id_len = 4 + 12 + rs + 16;
    cred_id = (uint8_t *)calloc(1, 4 + 12 + rs + 16);
    uint8_t key[32];
    memset(key, 0, sizeof(key));
    uint8_t iv[12];
    random_gen(NULL, iv, sizeof(12));
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    int ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, rs, iv, rp_id_hash, 32, cbor_buf, cred_id + 4 + 12, cred_id + 4 + 12 + rs);
    if (ret != 0) {
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }
    memcpy(cred_id, "\xf1\xd0\x02\x00", 4);
    memcpy(cred_id + 4, iv, 12);

    mbedtls_ecp_group_id mbedtls_curve = MBEDTLS_ECP_DP_SECP256R1;
    if (curve == FIDO2_CURVE_P256)
        mbedtls_curve = MBEDTLS_ECP_DP_SECP256R1;
    else if (curve == FIDO2_CURVE_P384)
        mbedtls_curve = MBEDTLS_ECP_DP_SECP384R1;
    else if (curve == FIDO2_CURVE_P521)
        mbedtls_curve = MBEDTLS_ECP_DP_SECP521R1;
    else if (curve == FIDO2_CURVE_P256K1)
        mbedtls_curve = MBEDTLS_ECP_DP_SECP256K1;
    else if (curve == FIDO2_CURVE_X25519)
        mbedtls_curve = MBEDTLS_ECP_DP_CURVE25519;
    else if (curve == FIDO2_CURVE_X448)
        mbedtls_curve = MBEDTLS_ECP_DP_CURVE448;
    else
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_ALGORITHM);
    printf("IEEEEEE 3\n");
    mbedtls_ecdsa_context ekey;
    mbedtls_ecdsa_init(&ekey);
    uint8_t key_path[KEY_PATH_LEN];
    memcpy(key_path, cred_id, KEY_PATH_LEN);
    *(uint32_t *)key_path = 0x80000000 | 10022;
    for (int i = 1; i < KEY_PATH_ENTRIES; i++)
        *(uint32_t *)(key_path+i*sizeof(uint32_t)) |= 0x80000000;
    ret = derive_key(NULL, false, key_path, mbedtls_curve, &ekey);
    if (ret != 0) {
        mbedtls_ecdsa_free(&ekey);
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }

    uint8_t flags = FIDO2_AUT_FLAG_UP | FIDO2_AUT_FLAG_AT;
    if (getUserVerifiedFlagValue())
        flags |= FIDO2_AUT_FLAG_UV;
    size_t ext_len = 0;
    uint8_t ext [512];
    if (hmac_secret != NULL || credProtect != 0) {
        cbor_encoder_init(&encoder, ext, sizeof(ext), 0);
        int l = 0;
        if (hmac_secret != NULL)
            l++;
        if (credProtect != 0)
            l++;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, l));
        if (credProtect != 0) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, "credProtect"));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, credProtect));
        }
        if (hmac_secret != NULL) {

            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, "hmac-secret"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, *hmac_secret));
        }

        CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
        ext_len = cbor_encoder_get_buffer_size(&encoder, ext);
        flags |= FIDO2_AUT_FLAG_ED;
    }
    uint8_t pkey[66];
    const mbedtls_ecp_curve_info *cinfo = mbedtls_ecp_curve_info_from_grp_id(mbedtls_curve);
    if (cinfo == NULL)
        CBOR_ERROR(CTAP1_ERR_OTHER);
    size_t olen = 0, pkey_len = ceil((float)cinfo->bit_size/8);
    uint32_t ctr = *(uint32_t *)file_get_data(ef_counter);
    cbor_encoder_init(&encoder, cbor_buf, sizeof(cbor_buf), 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder,  5));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 1));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 2));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 3));
    CBOR_CHECK(cbor_encode_negative_int(&mapEncoder, -alg));
    CBOR_CHECK(cbor_encode_negative_int(&mapEncoder, 1));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, curve));
    CBOR_CHECK(cbor_encode_negative_int(&mapEncoder, 2));
    mbedtls_mpi_write_binary(&ekey.Q.X, pkey, pkey_len);
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, pkey, pkey_len));
    CBOR_CHECK(cbor_encode_negative_int(&mapEncoder, 3));
    mbedtls_mpi_write_binary(&ekey.Q.Y, pkey, pkey_len);
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, pkey, pkey_len));

    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    rs = cbor_encoder_get_buffer_size(&encoder, cbor_buf);
    printf("IEEEEEE 4\n");
    size_t aut_data_len = 32 + 1 + 4 + (16 + 2 + cred_id_len + rs) + ext_len;
    aut_data = (uint8_t *)calloc(1, aut_data_len + clientDataHash.len);
    uint8_t *pa = aut_data;
    memcpy(pa, rp_id_hash, 32); pa += 32;
    *pa++ = flags;
    *pa++ = ctr >> 24;
    *pa++ = ctr >> 16;
    *pa++ = ctr >> 8;
    *pa++ = ctr & 0xff;
    memcpy(pa, aaguid, 16); pa += 16;
    *pa++ = cred_id_len >> 8;
    *pa++ = cred_id_len & 0xff;
    memcpy(pa, cred_id, cred_id_len); pa += cred_id_len;
    memcpy(pa, cbor_buf, rs); pa += rs;
    memcpy(pa, ext, ext_len); pa += ext_len;
    if (pa-aut_data != aut_data_len)
        CBOR_ERROR(CTAP1_ERR_OTHER);

    memcpy(pa, clientDataHash.data, clientDataHash.len);
    uint8_t hash[32], sig[MBEDTLS_ECDSA_MAX_LEN];
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), aut_data, aut_data_len+clientDataHash.len, hash);

    bool self_attestation = true;
    if (ka && ka->use_self_attestation == pfalse)
    {
        mbedtls_ecdsa_free(&ekey);
        mbedtls_ecdsa_init(&ekey);
        ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &ekey, file_get_data(ef_keydev), 32);
        self_attestation = false;
    }
    ret = mbedtls_ecdsa_write_signature(&ekey, MBEDTLS_MD_SHA256, hash, 32, sig, sizeof(sig), &olen, random_gen, NULL);
    mbedtls_ecdsa_free(&ekey);
    printf("IEEEEEE 5\n");
    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_PACKET_SIZE, 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 3));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
    CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, "packed"));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, aut_data, aut_data_len));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));

    CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2,  self_attestation == false ? 3 : 2));
    CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "alg"));
    CBOR_CHECK(cbor_encode_negative_int(&mapEncoder2, self_attestation ? -alg : -FIDO2_ALG_ES256));
    CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "sig"));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, sig, olen));
    if (self_attestation == false) {
        CborEncoder arrEncoder;
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "x5c"));
        CBOR_CHECK(cbor_encoder_create_array(&mapEncoder2, &arrEncoder, 1));
        CBOR_CHECK(cbor_encode_byte_string(&arrEncoder, file_get_data(ef_certdev), file_get_size(ef_certdev)));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder2, &arrEncoder));
    }
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));

    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    printf("IEEEEEE 6\n");
    err:
        CBOR_FREE_BYTE_STRING(clientDataHash);
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(rp.id);
    CBOR_FREE_BYTE_STRING(rp.parent.name);
    CBOR_FREE_BYTE_STRING(user.id);
    CBOR_FREE_BYTE_STRING(user.displayName);
    CBOR_FREE_BYTE_STRING(user.parent.name);
    for (int n = 0; n < pubKeyCredParams_len; n++) {
        CBOR_FREE_BYTE_STRING(pubKeyCredParams[n].type);
    }

    for (int m = 0; m < excludeList_len; m++) {
        CBOR_FREE_BYTE_STRING(excludeList[m].type);
        CBOR_FREE_BYTE_STRING(excludeList[m].id);
        for (int n = 0; n < excludeList[m].transports_len; n++) {
            CBOR_FREE_BYTE_STRING(excludeList[m].transports[n]);
        }
    }
    if (aut_data)
        free(aut_data);
    if (cred_id)
        free(cred_id);
    if (error != CborNoError) {
        if (error == CborErrorImproperValue)
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        return error;
    }
    res_APDU_size = resp_size;
    return 0;
}

