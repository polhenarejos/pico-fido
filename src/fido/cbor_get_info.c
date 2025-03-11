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

#include "ctap2_cbor.h"
#include "hid/ctap_hid.h"
#include "fido.h"
#include "ctap.h"
#include "files.h"
#include "apdu.h"
#include "version.h"

int cbor_get_info() {
    CborEncoder encoder, mapEncoder, arrayEncoder, mapEncoder2;
    CborError error = CborNoError;
    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 15));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 3));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "U2F_V2"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "FIDO_2_0"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "FIDO_2_1"));
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 6));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "credBlob"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "credProtect"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "hmac-secret"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "largeBlobKey"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "minPinLength"));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "thirdPartyPayment"));
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, aaguid, sizeof(aaguid)));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
    CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &arrayEncoder, 9));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "ep"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, get_opts() & FIDO2_OPT_EA));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "rk"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "alwaysUv"));
    if (file_has_data(ef_pin) && (get_opts() & FIDO2_OPT_AUV || !getUserVerifiedFlagValue())) {
        CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    }
    else {
        CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, false));
    }
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "credMgmt"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "authnrCfg"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "clientPin"));
    if (file_has_data(ef_pin)) {
        CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    }
    else {
        CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, false));
    }
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "largeBlobs"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "pinUvAuthToken"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
    CBOR_CHECK(cbor_encode_text_stringz(&arrayEncoder, "setMinPINLength"));
    CBOR_CHECK(cbor_encode_boolean(&arrayEncoder, true));
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
    if (!phy_data.enabled_curves_present || (phy_data.enabled_curves & PHY_CURVE_SECP256K1)) {
#endif
        CBOR_CHECK(COSE_public_key(FIDO2_ALG_ES256K, &arrayEncoder, &mapEncoder2));
#ifndef ENABLE_EMULATION
    }
#endif

    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0B));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, MAX_LARGE_BLOB_SIZE)); // maxSerializedLargeBlobArray

    file_t *ef_minpin = search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
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

    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x15));
    CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 2));
    CBOR_CHECK(cbor_encode_uint(&arrayEncoder, CTAP_CONFIG_AUT_ENABLE));
    CBOR_CHECK(cbor_encode_uint(&arrayEncoder, CTAP_CONFIG_AUT_DISABLE));
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrayEncoder));

    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
err:
    if (error != CborNoError) {
        return -CTAP2_ERR_INVALID_CBOR;
    }
    res_APDU_size = (uint16_t)cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    return 0;
}
