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

#include "cbor.h"
#include "ctap.h"
#include "ctap2_cbor.h"
#include "bsp/board.h"
#include "fido.h"
#include "files.h"
#include "random.h"
#include "crypto_utils.h"
#include "hsm.h"
#include "apdu.h"
#include "cbor_make_credential.h"
#include "credential.h"
#include <math.h>

CborCharString rpIdx = {0};
CborByteString pinUvAuthParamx = {0}, clientDataHashx = {0};
bool residentx = false;
Credential credsx[MAX_CREDENTIAL_COUNT_IN_LIST] = {0};
uint64_t pinUvAuthProtocolx = 0;
CredExtensions extensionx = {0};
CredOptions optionsx = {0};
uint8_t flagsx = 0;
uint8_t credentialCounter = 1;
uint8_t numberOfCredentialsx = 0;

int cbor_get_assertion(const uint8_t *data, size_t len) {
    size_t resp_size = 0;
    uint64_t pinUvAuthProtocol = 0;
    CredOptions options = {0};
    CredExtensions extensions = {0};
    CborParser parser;
    CborEncoder encoder, mapEncoder, mapEncoder2;
    CborValue map;
    CborError error = CborNoError;
    CborByteString pinUvAuthParam = {0}, clientDataHash = {0};
    CborCharString rpId = {0};
    PublicKeyCredentialDescriptor allowList[MAX_CREDENTIAL_COUNT_IN_LIST] = {0};
    Credential creds[MAX_CREDENTIAL_COUNT_IN_LIST] = {0};
    size_t allowList_len = 0, creds_len = 0;
    uint8_t *aut_data = NULL;
    bool asserted = false;

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1) {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 2 && val_c != val_u)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        if (val_u < val_c)
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_TEXT(rpId, 1);
        }
        else if (val_u == 0x02) {
            CBOR_FIELD_GET_BYTES(clientDataHash, 1);
        }
        else if (val_u == 0x03) { // excludeList
            CBOR_PARSE_ARRAY_START(_f1, 2) {
                    PublicKeyCredentialDescriptor *pc = &allowList[allowList_len];
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
                allowList_len++;
            }
            CBOR_PARSE_ARRAY_END(_f1, 2);
        }
        else if (val_u == 0x04) { // extensions
            CBOR_PARSE_MAP_START(_f1, 2) {
                CBOR_FIELD_GET_KEY_TEXT(2);
                CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "hmac-secret", extensions.hmac_secret);
                CBOR_FIELD_KEY_TEXT_VAL_UINT(2, "credProtect", extensions.credProtect);
                CBOR_ADVANCE(2);
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x05) { // options
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
        else if (val_u == 0x06) { // pinUvAuthParam
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else if (val_u == 0x07) { // pinUvAuthProtocol
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    uint8_t flags = FIDO2_AUT_FLAG_AT;
    uint8_t rp_id_hash[32];
    mbedtls_sha256((uint8_t *)rpId.data, rpId.len, rp_id_hash, 0);

    if (pinUvAuthParam.present == true) {
        if (pinUvAuthParam.len == 0 || pinUvAuthParam.data == NULL) {
            if (check_user_presence() == false)
                CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
            if (!file_has_data(ef_pin))
                CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
            else
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        else {
            if (pinUvAuthProtocol == 0)
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2)
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
    }
    if (options.present) {
        if (options.uv == ptrue) { //4.3
            CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        }
        //if (options.up != NULL) { //4.5
        //    CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        //}
        if (options.rk != NULL) {
            CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
        }
        //else if (options.up == NULL) //5.7
            //rup = ptrue;
    }

    if (pinUvAuthParam.present == true) { //6.1
        int ret = verify(pinUvAuthProtocol, paut.data, clientDataHash.data, clientDataHash.len, pinUvAuthParam.data);
        if (ret != CborNoError)
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        if (getUserVerifiedFlagValue() == false)
            CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
        flags |= FIDO2_AUT_FLAG_UV;
        // Check pinUvAuthToken permissions. See 6.2.2.4
    }

    bool resident = false;
    if (allowList_len > 0)
    {
        for (int e = 0; e < allowList_len; e++) {
            if (allowList[e].type.present == false || allowList[e].id.present == false)
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            if (strcmp(allowList[e].type.data, "public-key") != 0)
                continue;
            if (credential_load(allowList[e].id.data, allowList[e].id.len, rp_id_hash, &creds[e]) != 0)
                CBOR_FREE_BYTE_STRING(allowList[e].id);
        }
        creds_len = allowList_len;
    }
    else {
        for (int i = 0; i < MAX_RESIDENT_CREDENTIALS && creds_len < MAX_CREDENTIAL_COUNT_IN_LIST; i++) {
            file_t *ef = search_dynamic_file(EF_CRED + i);
            if (!file_has_data(ef) || memcmp(file_get_data(ef), rp_id_hash, 32) != 0)
                continue;
            int ret = credential_load(file_get_data(ef) + 32, file_get_size(ef) - 32, rp_id_hash, &creds[creds_len]);
            if (ret != 0)
                credential_free(&creds[creds_len]);
            else
                creds_len++;
        }
        resident = true;
    }
    uint8_t numberOfCredentials = 0;
    for (int i = 0; i < creds_len; i++) {
        if (creds[i].present == true) {
            if (creds[i].extensions.present == true) {
                if (creds[i].extensions.credProtect == CRED_PROT_UV_REQUIRED && !(flags & FIDO2_AUT_FLAG_UV))
                    credential_free(&creds[i]);
                else if (creds[i].extensions.credProtect == CRED_PROT_UV_OPTIONAL_WITH_LIST && resident == true && !(flags & FIDO2_AUT_FLAG_UV))
                    credential_free(&creds[i]);
                else
                    numberOfCredentials++;
            }
            else
                numberOfCredentials++;
        }
    }
    if (numberOfCredentials == 0)
        CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);

    if (options.up == ptrue || options.present == false || options.up == NULL) { //9.1
        if (pinUvAuthParam.present == true) {
            if (getUserPresentFlagValue() == false) {
                if (check_user_presence() == false)
                    CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
            }
        }
        flags |= FIDO2_AUT_FLAG_UP;
        clearUserPresentFlag();
        clearUserVerifiedFlag();
        clearPinUvAuthTokenPermissionsExceptLbw();
    }
    if (numberOfCredentials == 0)
        CBOR_ERROR(CTAP2_ERR_NO_CREDENTIALS);
    Credential *selcred = NULL;
    if (resident == false) {
        selcred = &creds[0];
    }
    else {
        if (numberOfCredentials == 1)
            selcred = &creds[0];
        else {
            asserted = true;
            rpIdx = rpId;
            pinUvAuthParamx = pinUvAuthParamx;
            clientDataHashx = clientDataHash;
            residentx = resident;
            for (int i = 0; i < MAX_CREDENTIAL_COUNT_IN_LIST; i++)
                credsx[i] = creds[i];
            numberOfCredentialsx = numberOfCredentials;
            pinUvAuthProtocolx = pinUvAuthProtocol;
            extensionx = extensions;
            optionsx = options;
            flagsx = flags;
        }
    }

    uint8_t cred_id[MAX_CRED_ID_LENGTH];
    size_t cred_id_len = 0;
    if (credential_create_cred(selcred, cred_id, &cred_id_len) != 0)
        CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);

    mbedtls_ecdsa_context ekey;
    mbedtls_ecdsa_init(&ekey);
    int ret = fido_load_key(selcred->curve, cred_id, &ekey);
    if (ret != 0) {
        mbedtls_ecdsa_free(&ekey);
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }

    size_t ext_len = 0;
    uint8_t ext [512];
    if (extensions.present == true) {
        cbor_encoder_init(&encoder, ext, sizeof(ext), 0);
        int l = 0;
        if (extensions.hmac_secret != NULL)
            l++;
        if (extensions.credProtect != 0)
            l++;
        CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, l));
        if (extensions.credProtect != 0) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, "credProtect"));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, extensions.credProtect));
        }
        if (extensions.hmac_secret != NULL) {

            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, "hmac-secret"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, *extensions.hmac_secret));
        }

        CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
        ext_len = cbor_encoder_get_buffer_size(&encoder, ext);
        flags |= FIDO2_AUT_FLAG_ED;
    }
    uint8_t pkey[66];
    const mbedtls_ecp_curve_info *cinfo = mbedtls_ecp_curve_info_from_grp_id(ekey.grp.id);
    if (cinfo == NULL)
        CBOR_ERROR(CTAP1_ERR_OTHER);
    size_t olen = 0, pkey_len = ceil((float)cinfo->bit_size/8);
    uint32_t ctr = *(uint32_t *)file_get_data(ef_counter);
    uint8_t cbor_buf[1024];
    cbor_encoder_init(&encoder, cbor_buf, sizeof(cbor_buf), 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder,  5));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 1));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 2));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 3));
    CBOR_CHECK(cbor_encode_negative_int(&mapEncoder, -selcred->alg));
    CBOR_CHECK(cbor_encode_negative_int(&mapEncoder, 1));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, selcred->curve));
    CBOR_CHECK(cbor_encode_negative_int(&mapEncoder, 2));
    mbedtls_mpi_write_binary(&ekey.Q.X, pkey, pkey_len);
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, pkey, pkey_len));
    CBOR_CHECK(cbor_encode_negative_int(&mapEncoder, 3));
    mbedtls_mpi_write_binary(&ekey.Q.Y, pkey, pkey_len);
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, pkey, pkey_len));

    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    size_t rs = cbor_encoder_get_buffer_size(&encoder, cbor_buf);

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
    ret = mbedtls_ecdsa_write_signature(&ekey, MBEDTLS_MD_SHA256, hash, 32, sig, sizeof(sig), &olen, random_gen, NULL);
    mbedtls_ecdsa_free(&ekey);

    uint8_t lfields = 3;
    if (resident)
        lfields++;
    if (numberOfCredentials > 1)
        lfields++;
    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_PACKET_SIZE, 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, lfields));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
    CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, 2));
    CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "type"));
    CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "public-key"));
    CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, cred_id, cred_id_len));
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, aut_data, aut_data_len));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, sig, olen));

    if (resident) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, 1));
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "id"));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, selcred->userId.data, selcred->userId.len));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    }
    if (numberOfCredentials > 1) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, numberOfCredentials));
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    res_APDU_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    err:
    if (asserted == false) {
        CBOR_FREE_BYTE_STRING(clientDataHash);
        CBOR_FREE_BYTE_STRING(pinUvAuthParam);
        CBOR_FREE_BYTE_STRING(rpId);
    }

    for (int m = 0; m < allowList_len; m++) {
        CBOR_FREE_BYTE_STRING(allowList[m].type);
        CBOR_FREE_BYTE_STRING(allowList[m].id);
        for (int n = 0; n < allowList[m].transports_len; n++) {
            CBOR_FREE_BYTE_STRING(allowList[m].transports[n]);
        }
    }
    if (aut_data)
        free(aut_data);
    if (error != CborNoError) {
        if (error == CborErrorImproperValue)
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        return error;
    }
    res_APDU_size = resp_size;
    return 0;
}
