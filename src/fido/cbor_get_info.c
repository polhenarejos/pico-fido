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

#include "picokeys.h"
#include "ctap2_cbor.h"
#include "hid/ctap_hid.h"
#include "fido.h"
#include "ctap.h"
#include "files.h"
#include "apdu.h"
#include "version.h"
#include "crypto_utils.h"
#include "random.h"
#include "mbedtls/hkdf.h"

#define CRED_STORE_STATE_SIZE 16
#define DEV_STATE_SIZE (2 * CRED_STORE_STATE_SIZE)

static int encrypt_dev_state_block(const file_t *ef_dev_state, dev_state_t state, uint8_t output[DEV_STATE_SIZE]) {
    static const uint8_t salt[32] = { 0 };
    uint8_t key[CRED_STORE_STATE_SIZE] = { 0 };
    int ret = PICOKEYS_EXEC_ERROR;
    size_t dev_state_offset;
    const uint8_t *info;
    if (state == DEV_STATE_DEV_ID) {
        dev_state_offset = 0;
        info = (const uint8_t *) "encIdentifier";
    }
    else if (state == DEV_STATE_CRED_STATE) {
        dev_state_offset = CRED_STORE_STATE_SIZE;
        info = (const uint8_t *) "encCredStoreState";
    }
    else {
        return PICOKEYS_EXEC_ERROR;
    }

    if (file_get_size(ef_dev_state) != DEV_STATE_SIZE || dev_state_offset > DEV_STATE_SIZE - CRED_STORE_STATE_SIZE || !ppaut.data || ppaut.len != 32) {
        goto cleanup;
    }

    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, sizeof(salt), ppaut.data, ppaut.len, info, strlen((const char *) info), key, sizeof(key));
    if (ret != 0) {
        goto cleanup;
    }

    ret = random_fill_buffer(output, CRED_STORE_STATE_SIZE);
    if (ret != 0) {
        goto cleanup;
    }

    memcpy(output + CRED_STORE_STATE_SIZE, file_get_data(ef_dev_state) + dev_state_offset, CRED_STORE_STATE_SIZE);
    ret = aes_encrypt(key, output, sizeof(key) * 8, PICOKEYS_AES_MODE_CBC, output + CRED_STORE_STATE_SIZE, CRED_STORE_STATE_SIZE);

cleanup:
    mbedtls_platform_zeroize(key, sizeof(key));
    return ret;
}

int cbor_get_info(void) {
    CborEncoder encoder, mapEncoder, arrayEncoder, mapEncoder2;
    CborError error = CborNoError;
    uint8_t enc_identifier[DEV_STATE_SIZE] = { 0 }, enc_cred_store_state[DEV_STATE_SIZE] = { 0 };
    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);
    uint8_t lfields = 20;
    file_t *ef_ee_ea = file_search_by_fid(EF_EE_DEV_EA, NULL, SPECIFY_EF);
    bool enterprise_profile = ((get_opts() & FIDO2_OPT_EA) && file_has_data(ef_ee_ea));
#ifndef ENABLE_EMULATION
    if (phy_data.vid != 0x1050) {
        lfields++;
    }
#else
    lfields++;
#endif
    file_t *ef_pin_policy = file_search_by_fid(EF_PIN_COMPLEXITY_POLICY, NULL, SPECIFY_EF);
    if (file_get_size(ef_pin_policy) > 2) {
        lfields += 1;
    }
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, lfields));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 5));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "U2F_V2"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "FIDO_2_0"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "FIDO_2_1"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "FIDO_2_2"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "FIDO_2_3"));
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 8 + (file_has_data(ef_pin_policy) ? 1 : 0)));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "uvm"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "credBlob"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "credProtect"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "hmac-secret"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "largeBlobKey"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "minPinLength"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "hmac-secret-mc"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "thirdPartyPayment"));
    if (file_has_data(ef_pin_policy)) {
        CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "pinComplexityPolicy"));
    }
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, aaguid, sizeof(aaguid)));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
    CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &arrayEncoder, enterprise_profile ? 11 : 10));
    if (enterprise_profile) {
        CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "ep"));
        CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    }
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "rk"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, !(get_opts() & FIDO2_OPT_NORK)));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "alwaysUv"));
    //bool alwaysUv = file_has_data(ef_pin) && (get_opts() & FIDO2_OPT_AUV || !getUserVerifiedFlagValue());
    //CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, alwaysUv));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, get_opts() & FIDO2_OPT_AUV));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "credMgmt"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "authnrCfg"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "clientPin"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, file_has_data(ef_pin)));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "largeBlobs"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "perCredMgmtRO"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "pinUvAuthToken"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "setMinPINLength"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "makeCredUvNotRqd"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, get_opts() & FIDO2_OPT_AUV ? false : get_opts() & FIDO2_OPT_MCUV_NOTRQD));
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_MSG_SIZE));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x06));
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 2));
    CBOR_CHECK(cbor_encode_uint(&arrayEncoder, 1)); // PIN protocols
    CBOR_CHECK(cbor_encode_uint(&arrayEncoder, 2)); // PIN protocols
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_CREDENTIAL_COUNT_IN_LIST)); // MAX_CRED_COUNT_IN_LIST

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_CRED_ID_LENGTH)); // MAX_CRED_ID_MAX_LENGTH

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0A));

    uint8_t curves = 3;
#ifdef MBEDTLS_EDDSA_C
    curves++;
#endif
#ifndef ENABLE_EMULATION
    if (phy_data.enabled_curves & PHY_CURVE_SECP256K1) {
#endif
        curves++;
#ifndef ENABLE_EMULATION
    }
#endif
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, curves));
    CBOR_CHECK(COSE_public_key(FIDO2_ALG_ES256, &arrayEncoder, &mapEncoder2));
#ifdef MBEDTLS_EDDSA_C
    CBOR_CHECK(COSE_public_key(FIDO2_ALG_EDDSA, &arrayEncoder, &mapEncoder2));
#endif
    CBOR_CHECK(COSE_public_key(FIDO2_ALG_ES384, &arrayEncoder, &mapEncoder2));
    CBOR_CHECK(COSE_public_key(FIDO2_ALG_ES512, &arrayEncoder, &mapEncoder2));
#ifndef ENABLE_EMULATION
    if (phy_data.enabled_curves & PHY_CURVE_SECP256K1) {
#endif
        CBOR_CHECK(COSE_public_key(FIDO2_ALG_ES256K, &arrayEncoder, &mapEncoder2));
#ifndef ENABLE_EMULATION
    }
#endif

    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0B));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_LARGE_BLOB_SIZE)); // maxSerializedLargeBlobArray

    file_t *ef_minpin = file_search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0C));
    if (file_has_data(ef_minpin) && file_get_data(ef_minpin)[1] == 1) {
        CBOR_CHECK(cbor_encode_boolean(&mapEncoder, true));
    }
    else {
        CBOR_CHECK(cbor_encode_boolean(&mapEncoder, false));
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0D));
    if (file_has_data(ef_minpin)) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, *file_get_data(ef_minpin))); // minPINLength
    }
    else {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 4)); // minPINLength

    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0E));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, PICO_FIDO_VERSION)); // firmwareVersion

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0F));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_CREDBLOB_LENGTH)); // maxCredBlobLength

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x10));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_RPIDS_MINPIN_LENGTH)); // maxRPIDsForSetMinPINLength
#ifndef ENABLE_EMULATION
    if (phy_data.vid != 0x1050) {
#endif
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x15));
        CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 6));
        CBOR_CHECK(cbor_encode_uint(&arrayEncoder, CTAP_CONFIG_AUT_DISABLE));
        CBOR_CHECK(cbor_encode_uint(&arrayEncoder, CTAP_CONFIG_EA_UPLOAD));
        CBOR_CHECK(cbor_encode_uint(&arrayEncoder, CTAP_CONFIG_MCUV_NOTRQD));
        CBOR_CHECK(cbor_encode_uint(&arrayEncoder, CTAP_CONFIG_AUT_ENABLE));
        CBOR_CHECK(cbor_encode_uint(&arrayEncoder, CTAP_CONFIG_NORK));
        CBOR_CHECK(cbor_encode_uint(&arrayEncoder, CTAP_CONFIG_PIN_POLICY));
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));
#ifndef ENABLE_EMULATION
    }
#endif

    file_t *ef_dev_state = file_search_by_fid(EF_DEV_STATE, NULL, SPECIFY_EF);
    if (file_get_size(ef_dev_state) != DEV_STATE_SIZE) {
        file_put_data(ef_dev_state, random_bytes_get(32), 32);
        flash_commit();
    }
    if (encrypt_dev_state_block(ef_dev_state, DEV_STATE_DEV_ID, enc_identifier) != 0 ||
        encrypt_dev_state_block(ef_dev_state, DEV_STATE_CRED_STATE, enc_cred_store_state) != 0) {
        mbedtls_platform_zeroize(enc_identifier, sizeof(enc_identifier));
        mbedtls_platform_zeroize(enc_cred_store_state, sizeof(enc_cred_store_state));
        return CTAP2_ERR_PROCESSING;
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x19));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, enc_identifier, sizeof(enc_identifier)));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x1B));
    CBOR_CHECK(cbor_encode_boolean(&mapEncoder, file_has_data(ef_pin_policy)));
    if (file_get_size(ef_pin_policy) > 2) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x1C));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, file_get_data(ef_pin_policy) + 2, file_get_size(ef_pin_policy) - 2));
    }

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x1D));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 63)); // maxPINLength

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x1E));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, enc_cred_store_state, sizeof(enc_cred_store_state)));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x1F));
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 4));
    CBOR_CHECK(cbor_encode_uint(&arrayEncoder, 0x01));
    CBOR_CHECK(cbor_encode_uint(&arrayEncoder, 0x02));
    CBOR_CHECK(cbor_encode_uint(&arrayEncoder, 0x03));
    CBOR_CHECK(cbor_encode_uint(&arrayEncoder, 0xFF));
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));

err:
    mbedtls_platform_zeroize(enc_identifier, sizeof(enc_identifier));
    mbedtls_platform_zeroize(enc_cred_store_state, sizeof(enc_cred_store_state));
    if (error != CborNoError) {
        return -CTAP2_ERR_INVALID_CBOR;
    }
    res_APDU_size = (uint16_t)cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    return 0;
}
