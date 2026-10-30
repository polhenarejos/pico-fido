# PicoKeys Vault vs. CXP/CXF: deferred credential recovery

This document compares three different layers that are easy to conflate:

- Credential Exchange Format (CXF) is a representation of credential data.
- Credential Exchange Protocol (CXP) is a provider-to-provider exchange protocol that protects and transports CXF data.
- Asynchronous Remote Key Generation (ARKG) is a cryptographic construction for deriving related public/private key pairs asynchronously. It is not, by itself, a credential backup protocol.
- PicoKeys Vault is this repository's vendor-specific mechanism for exporting selected resident FIDO credentials into an authenticated encrypted envelope and importing them into another enrolled Pico FIDO device.

The comparison is about security and timing properties, not which mechanism is universally better. The standards and drafts were checked on 2026-09-06. The implementation statements are derived from the source paths listed in [References](#references).

## Main distinction: intermediary trust and device timing

> Key difference: Vault was designed as an intermediary-zero-trust architecture. CXP either trusts an intermediate provider with the credential or requires the source and destination to be prepared before export.

```text
PicoKeys Vault: one-device start, more devices later
    A establishes the Vault domain and its shared secret
        -> A exports to an opaque artifact
        -> passive storage never gets the credential key
        -> B, C, ... can join the same domain later

CXP/CXF: three modes
    trusted-provider path: A -> M imports and sees the key -> M exports to B
    passive path: B creates request/key -> A exports for B -> storage -> B
    self path: one provider -> external storage, with an optional shared symmetric secret
```

Vault can operate with one enrolled device and be expanded later by adding devices that share the Vault secret. It does not require every existing or future device to be present at the same time, and a passive storage intermediary cannot decrypt the recovery artifact by design.

CXP supports indirect and file-based transport, so a passive storage service need not see the private key. In that mode, however, the minimum direct exchange is two prepared endpoints: A and B. B must create the request and cryptographic parameters before A exports. If an intermediate provider M imports from A and later exports to B, M is no longer passive; it becomes a trusted key-handling sink and later source. [CXP §2.1, §2.2, §3.2–§3.4]

This document does not repeat Vault or PKV1 implementation details. See the [Vault design proposal](vaulted_passkeys_proposal.md) and the implementation sources in [References](#references).

## FIDO CXP and CXF

### Format versus protocol

CXF 1.0 is currently a FIDO Proposed Standard, with the March 9, 2026 errata revision. It defines credential data structures and explicitly does not assume a particular transfer protocol. CXP 1.0 remains a FIDO Working Draft; the current 2024-10-03 document describes a protocol for moving credentials between exporting and importing providers, and the FIDO download page still describes the credential-exchange material as early-review work.

CXP/CXF is a host-provider exchange layer, not a CTAP or CTAPHID-native credential protocol. Its exchange objects use JSON; its credential payload uses a ZIP archive with separately encrypted JWE files, commonly using DEFLATE; and its indirect mode is explicitly file-based. The protocol does not define a CTAPHID transport or optimize the exchange for CTAPHID. PicoKeys Vault, by contrast, is implemented in the device-native FIDO vendor-command path, including CTAPHID vendor commands ([`ctap.h`](../../src/fido/ctap.h), [`device.py`](../../pico-vault-enroller/pico_vault_enroller/device.py)).

The CXF passkey object contains the credential ID, RP ID, user-facing username and display name, user handle, and a `key` field. The `key` field is the credential private key, encoded as PKCS#8 ASN.1 DER and then Base64url-encoded. CXF therefore represents portable private-key material directly. It is not a hardware-wrapped reference and it is not an authenticator-state image (CXF §3.3.12).

The current CXF passkey rules also say that passkeys with a non-zero signature counter must be excluded from export; an importer must set imported passkey counters to zero and must not increment them afterward. That is an explicit portability rule, not preservation of the source authenticator's counter.

### CXP response modes

- Direct: the importer creates the export request, the exporter returns the response through the exchange interface, and the importer decrypts the CXF payload. The importer is therefore a key-handling endpoint and sees the credential private key.
- Indirect: the same exporter/importer cryptographic relationship is used, but the request and response are carried as files. A passive filesystem or storage service does not see the private key; the importer still decrypts the payload and sees it. The request may be prepared by the importer or an Authorizing Party, but preparing the request does not make that party a blind relay.
- Self: the exporter and importer are the same provider. CXP says that this provider may use a symmetric key supplied by the credential owner or Authorizing Party to derive the response-encryption key, with external storage as the intended use case. It does not define how that secret is generated, shared, stored, recovered, or bound to a replacement authenticator. This is the closest CXP mode to a Vault-style shared-secret backup, but it is only a protocol hook, not the Vault architecture.

Indirect mode therefore changes delivery and simultaneity, not the final importer's access to the credential. Only a passive intermediary remains outside the key-handling boundary ([CXP §2.2, §3.2.1, §3.2.2, §3.5.2]).

### Who can see the key

The roles must be kept separate:

- The exporting Credential Provider is the source provider. It must obtain the credential data and create the protected export response. At this boundary it can access the private key represented by CXF.
- The importing Credential Provider is the final destination. It decrypts the response and stores the CXF credentials, so standardized import semantics give it access to the private key. The specification does not require that the operating system or a user-facing application receive a plaintext copy if the provider implements the boundary in hardware.
- An optional Authorizing Party can authorize or attest the exchange and help create migration-key material. It is not automatically a holder of the credential private key.
- A transport, filesystem, or orchestrating intermediary need not see the private key when CXP protection is correctly used. CXP says its encrypted response is intended to remain confidential between the exporting and importing providers. The intermediary can still observe or affect availability, and can see whatever non-secret request or envelope metadata the protocol exposes.

This is why “the provider sees the private key” is incomplete. The exporting and importing providers are inside the key-handling boundary; an arbitrary storage intermediary is not necessarily inside it. CXP itself also says that it does not address threats introduced by compromised Credential Providers. Encryption between providers is not a substitute for trusting the provider implementations that can decrypt or use the credential.

### Timing and state

CXP is not restricted to two devices being online simultaneously. Its indirect mode requires the exporter to write the export response to the filesystem, and the response can later be supplied to the importer. Its request-file flow likewise allows an import request to be carried by the credential owner. However, the importer initiates the exchange by creating an export request containing supported encryption and archive parameters; normally the request includes public cryptographic material needed by the exporter. Thus the destination need not be online at export time, but its exchange request or equivalent cryptographic preparation exists before the exporter creates the package.

CXF carries passkey metadata and selected FIDO2 extension data. It does not define a complete snapshot of authenticator identity, PIN state, attestation state, global counters, firmware state, or other device state. CXP/CXF should therefore be described as credential migration or portability, not exact authenticator-state backup. The importing provider obtains a portable private key and may place it in hardware or software according to its own implementation; the format alone cannot preserve original hardware-binding semantics.

## ARKG

The current ARKG reference is `draft-bradleylundberg-cfrg-arkg-11`, published July 5, 2026. It is an active individual IETF Internet-Draft with no RFC stream or intended RFC status and explicitly has no formal standing in the IETF standards process. Its intended status is informational in the draft itself. It must be treated as work in progress, not as a finalized FIDO backup standard.

ARKG has three relevant operations:

1. The delegating party creates an ARKG seed pair and keeps the private seed.
2. A subordinate party uses the public seed, context, and fresh input to derive a public key and key handle.
3. The delegating party later uses the private seed and key handle to derive the corresponding private key.

The construction is useful when a public key must be prepared without access to the private-key holder. The draft identifies backup-key generation as one possible application: a primary authenticator could generate a public key for a paired backup authenticator. That example is an architecture built around ARKG; it is not a protocol for importing arbitrary existing WebAuthn credentials.

The distinction has a practical consequence. An ordinary credential created before ARKG was enabled has no ARKG seed relationship or key handle. ARKG cannot retroactively turn that arbitrary private key into an ARKG-derived credential without an additional migration design that would itself need to handle the private key. A recovery design using ARKG must therefore be built into credential generation and registration from the beginning, or must create a new ARKG-aware credential rather than recover the old one.

The persistent secret in ARKG is the private seed (or equally sensitive seed-generation material). The public seed and key handles can be distributed, although the draft notes that handles encode private-key material and should not be revealed unnecessarily. Compromise of the private seed compromises the corresponding family of derived private keys. ARKG does not specify credential metadata, resident-credential storage, WebAuthn backup flags, signature counters, enrollment authorization, device replacement, or artifact retention. It is a cryptographic primitive/construction, not a complete credential backup workflow.

Yubico documents an ARKG-backed `previewSign` capability, and its Build with Us repository describes the related firmware as preview/beta and limited to early-access hardware. That is useful implementation evidence, not evidence that ARKG or the Yubico preview is a standardized FIDO credential-backup mechanism.

## Security and trust comparison

The symbols are security judgments: `✅` favorable, `❌` unfavorable or exposed to the stated trust boundary, `⚠️` the specification leaves an important behavior undefined, and `—` not applicable. The first five rows are the central comparison.

| Property | PicoKeys Vault | CXP/CXF direct | CXP/CXF indirect | CXP/CXF self | ARKG |
|---|---|---|---|---|---|
| Initial device requirement | ✅ One enrolled device is enough; more devices can join later. | ❌ A and B must participate in the exchange. | ❌ A and B, or their prepared provider endpoints, must exist before export. | ✅ One provider can create a backup. | — Not a generic backup deployment. |
| Destination must exist before export | ✅ No. B can be purchased and enrolled later. | ❌ B creates the export request and cryptographic parameters first. | ❌ B or its request-producing provider must exist first. | ✅ No separate destination is required for backup creation. | — Not a generic replacement flow. |
| Protocol/transport layer | ✅ Device-native FIDO/CTAPHID vendor path. | ❌ Host-provider exchange; not CTAPHID-native. | ❌ Host-provider JSON files carrying the request/response; not CTAPHID-native. | ❌ Host-provider exchange with external storage; not CTAPHID-native. | — Not specified. |
| Passive storage intermediary | ✅ Zero-trust toward storage; it cannot decrypt the artifact. | — Not required by the mode. | ✅ Storage can relay ciphertext; it does not see the private key. | ✅ External storage is intended. | — Not a backup protocol. |
| Intermediate provider M: A→M→B | ✅ Not required or trusted. | ❌ M is the importer/sink and must handle the private key before exporting to B. | ❌ If M is a provider rather than passive storage, it has the same key access. | ❌ The self provider remains the key-handling provider. | — Not specified. |
| Untrusted intermediate sees the private key | ✅ No intermediate provider sees it. | ❌ The importing provider sees it. | ❌ An intermediate provider sees it; passive storage does not. | ❌ The self provider sees it. | — Not an import protocol. |
| Destination-independent recovery | ✅ Available after A is gone and before B exists. | ❌ B's request/key material is required first. | ❌ B's request/key material is required first. | ❌ CXP does not define a complete destination-independent recovery flow. | ❌ Not a generic recovery protocol. |
| Long-lived shared secret | ❌ Required across Vault devices. | ✅ No. | ✅ No. | ❌ Self mode permits one supplied by the owner or Authorizing Party. | ✅ No shared secret; ARKG uses a private seed. |
| Recovery after A is gone and B did not exist | ✅ Supported, if the recovery material and artifact survive. | ❌ No direct destination existed to prepare the exchange. | ❌ No B request/key existed to encrypt to. | ❌ Replacement-device recovery is not defined. | ❌ Not generic. |
| Works with existing credentials | ✅ Supported resident credentials | ✅ If exportable under CXF rules | ✅ If exportable under CXF rules | ✅ If exportable under CXF rules | ❌ Not by itself; the ARKG relationship must exist at creation. |
| Provider interoperability | ❌ Vendor-specific | ✅ Primary goal | ✅ Primary goal | ❌ Self is provider backup, not cross-provider migration | — Not specified. |
| Exact authenticator-state backup | ❌ No | ❌ No | ❌ No | ❌ No | — Not specified |

## Threat-model comparison

| Threat or role | PicoKeys Vault | CXP/CXF direct | CXP/CXF indirect | CXP/CXF self | ARKG |
|---|---|---|---|---|---|
| Passive storage compromise | ✅ No private key by design | — Not required by the mode. | ✅ No private key if storage is only a relay. | ✅ Storage need not have the secret. | — |
| Intermediate provider compromise | ✅ No intermediate provider is needed or trusted. | ❌ M/importer can use the credential. | ❌ M can use it if M is a provider rather than passive storage. | ❌ The self provider is the key-handling provider. | — |
| Untrusted intermediate sees private key | ✅ No intermediate provider sees it. | ❌ Importer/provider sees it. | ❌ M sees it if M is a provider; passive storage does not. | ❌ Self provider sees it. | — |
| A destroyed before B exists | ✅ Deferred recovery is the intended case. | ❌ Direct exchange cannot start without B's request/key material. | ❌ No B request/key existed to encrypt to. | ❌ Replacement is undefined. | ❌ Not a generic recovery protocol. |
| Initial deployment with one device | ✅ Supported; later devices can join the Vault domain. | ❌ Requires A and B. | ❌ Requires A and B or their provider endpoints. | ✅ One provider can create a backup. | — Not a generic backup deployment. |
| Future B compromised | ❌ B can use imported credentials. | ❌ B can use imported credentials. | ❌ B can use imported credentials. | ❌ The provider can use the stored credential. | ❌ A holder of the derived key can use it. |
| Source/provider compromise | ❌ Source can authorize/export credentials. | ❌ Exporter can access CXF private keys. | ❌ Exporter can access CXF private keys. | ❌ The self provider can access the credential. | ❌ Seed holder can derive the key family. |

## Choosing between the mechanisms

- Choose CXP/CXF for standardized provider migration when the destination can prepare first and provider endpoints are acceptable key-handling boundaries.
- Choose ARKG for a new derived-key design; it is not a generic recovery protocol for existing credentials.
- Choose PicoKeys Vault when B may not exist at export time and passive storage must remain unable to decrypt the recovery artifact.

## References

### Primary specifications

1. [FIDO Credential Exchange Format 1.0, Proposed Standard, March 9, 2026 errata](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html), especially §1.2, §3.3.12, §5.1.
2. [FIDO Credential Exchange Protocol 1.0, Working Draft, October 3, 2024](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html), especially §2.1–§2.2, §3.2–§3.4, §6. The [FIDO download page](https://fidoalliance.org/download-credential-exchange-specifications/) describes the credential-exchange specifications as early-review material.
3. [Web Authentication: An API for accessing Public Key Credentials — Level 3](https://www.w3.org/TR/webauthn-3/), especially §6.1.1, §6.1.3, and the definitions of backup eligibility/state.
4. [FIDO Client to Authenticator Protocol 2.3, Proposed Standard, February 26, 2026](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html), used for the surrounding CTAP/WebAuthn authenticator model. Vault commands in this repository are vendor commands, not a CXP/CXF or CTAP-standard credential export/import command.
5. [The Asynchronous Remote Key Generation (ARKG) algorithm, draft-bradleylundberg-cfrg-arkg-11, July 5, 2026](https://datatracker.ietf.org/doc/draft-bradleylundberg-cfrg-arkg/11/), especially §1, §2, §6, and §10. The Datatracker status page identifies it as an active individual Internet-Draft with no formal IETF standards-process standing.
6. [Yubico Signing Extension Preview](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/), which identifies `previewSign` and ARKG as preview capability material.
7. [Yubico Build with Us](https://github.com/YubicoLabs/build-with-us), whose README describes the relevant firmware as preview/beta and early-access material.

### Repository implementation sources

8. [`src/fido/fido_vault.c`](../../src/fido/fido_vault.c): `vault_pin_auth`, `vault_export_blob`, `vault_import_blob`, `vault_encode_credential_metadata`, and `vault_vendor_command`.
9. [`pico-keys-sdk/src/vault.c`](../../pico-keys-sdk/src/vault.c): Vault ID/key derivation, enrollment certificate/serial validation, X448/HKDF/AES-GCM enrollment decoding, and Vault-container integration.
10. [`pico-keys-sdk/src/fs/vault_container.c`](../../pico-keys-sdk/src/fs/vault_container.c): persistent wrapped-`Kvault` storage and retrieval.
11. [`src/fido/credential.c`](../../src/fido/credential.c): `credential_import` validation and imported resident-credential creation.
12. [`src/fido/cbor_get_assertion.c`](../../src/fido/cbor_get_assertion.c): imported-credential `signCount = 0` behavior and suppression of native counter advancement.
13. [`pico-vault-enroller/pico_vault_enroller/device.py`](../../pico-vault-enroller/pico_vault_enroller/device.py): PIN token, enrollment ceremony, vendor transport, and certificate acquisition flow.
14. [`pico-vault-enroller/pico_vault_enroller/crypto.py`](../../pico-vault-enroller/pico_vault_enroller/crypto.py): passphrase-protected enrollment JSON, `Kvault`, X448 key, certificate, and backend certificate request.
15. [`docs/vault/vaulted_passkeys_proposal.md`](vaulted_passkeys_proposal.md): non-normative design proposal; it is useful context but is not authoritative where the current implementation differs.
