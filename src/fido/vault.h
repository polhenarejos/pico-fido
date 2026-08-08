/*
 * Vault vendor support for Pico FIDO.
 */
#ifndef _VAULT_H_
#define _VAULT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ctap2_cbor.h"
#include "credential.h"
#include "mbedtls/x509_crt.h"
#include "serial.h"

#define VAULT_X448_BYTES       56
#define VAULT_CHANNEL_KEY_BYTES 32
#define VAULT_CHANNEL_INFO "pico-fido-vault-v1"
#define VAULT_CREDENTIAL_METADATA_MAX 512
#define VAULT_KEY_BYTES 32
#define VAULT_ID_BYTES 32
#define VAULT_ENROLL_CHALLENGE_BYTES 32
#define VAULT_ENROLL_CERT_MAX 1900
#define VAULT_ENROLL_MIN_PACKET_LEN (2 + 12 + VAULT_KEY_BYTES + 16)
#define VAULT_LABEL_MAX 64
#define VAULT_ENROLL_PLAIN_MAX (VAULT_KEY_BYTES + 1 + VAULT_LABEL_MAX)
#define VAULT_STORE_LEN (1 + 12 + VAULT_KEY_BYTES + 16)
#define VAULT_BLOB_SERIAL_MAX 16
#define VAULT_BLOB_SERIAL_LEN_OFFSET (4 + VAULT_ID_BYTES + VAULT_ID_BYTES)
#define VAULT_BLOB_SERIAL_OFFSET (VAULT_BLOB_SERIAL_LEN_OFFSET + 1)
#define VAULT_BLOB_ALGORITHM_OFFSET (VAULT_BLOB_SERIAL_OFFSET + VAULT_BLOB_SERIAL_MAX)
#define VAULT_BLOB_HEADER_LEN (VAULT_BLOB_ALGORITHM_OFFSET + 1)
#define VAULT_BLOB_NONCE_BYTES 12
#define VAULT_PLAIN_MAX (MAX_CRED_ID_LENGTH + VAULT_CREDENTIAL_METADATA_MAX + 256)
#define VAULT_BLOB_MAX (VAULT_BLOB_HEADER_LEN + 24 + VAULT_PLAIN_MAX + 32)
#define VAULT_ALGORITHM_CHACHAPOLY 1
#define VAULT_ALGORITHM_AESGCM 2
#define VAULT_ALGORITHM_CHACHAPOLY_AESGCM 3
#define VAULT_ALGORITHM_AESGCM_CHACHAPOLY 4
#define VAULT_ENROLL_WINDOW_MS 60000u
#define VAULT_ENROLL_HOLD_MS 10000u



extern uint8_t vault_enroll_private[VAULT_X448_BYTES];
extern uint8_t vault_enroll_public[VAULT_X448_BYTES];
extern uint8_t vault_enroll_challenge[VAULT_ENROLL_CHALLENGE_BYTES];
extern bool vault_enroll_active;
extern bool vault_enrollment_button_accepted;
extern uint8_t vault_channel_key[VAULT_CHANNEL_KEY_BYTES];
extern bool vault_channel_init;

int vault_pin_auth(uint8_t protocol, const CborByteString *auth, const uint8_t *raw_params, size_t raw_params_len, uint64_t subcommand);
int vault_x448_generate(uint8_t private_key[VAULT_X448_BYTES], uint8_t public_key[VAULT_X448_BYTES]);
int vault_x448_shared(const uint8_t private_key[VAULT_X448_BYTES], const uint8_t peer_public[VAULT_X448_BYTES], uint8_t shared[VAULT_X448_BYTES]);
int vault_validate_certificate(mbedtls_x509_crt *certificate);
int vault_hash_key(const uint8_t key[VAULT_KEY_BYTES], uint8_t digest[VAULT_ID_BYTES]);
int vault_load_key(uint8_t key[VAULT_KEY_BYTES]);
bool vault_algorithm_valid(uint8_t algorithm);
bool vault_enrollment_button_ready(void);
void vault_enrollment_clear(void);
void vault_enrollment_reset(void);
int vault_unenroll(void);
int vault_enrollment_finish(const uint8_t *packet, size_t packet_len);
int vault_export_blob(const uint8_t *requested_id, size_t requested_id_len, uint8_t algorithm, uint8_t *blob, size_t blob_capacity, size_t *blob_len, uint8_t *metadata, size_t metadata_capacity, size_t *metadata_len);
int vault_import_blob(const uint8_t *blob, size_t blob_len);
int vault_encode_credential_metadata(const Credential *credential, const uint8_t rp_id_hash[RP_ID_HASH_LEN], uint8_t *buffer, size_t buffer_len, size_t *metadata_len);
CborError vault_vendor_command(uint64_t vendorCmd, CborByteString vendorParam, CborByteString pinUvAuthParam, uint64_t pinUvAuthProtocol, const uint8_t *raw_vendor_params, size_t raw_vendor_params_len, uint64_t vault_algorithm, bool vault_algorithm_present, CborByteString *requested_id, CborEncoder encoder, size_t *resp_size, bool *response_handled, int *ctap_error);

#endif
