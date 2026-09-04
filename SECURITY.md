# Security Policy

## System and scope

This repository contains Pico FIDO firmware for Raspberry Pi Pico and ESP32
devices. The security scope includes CTAP and U2F command handling, PIN and
user-presence authorization, credential and seed storage, Vault operations,
USB HID/CCID interfaces, reset and recovery paths, and secure-boot, secure-lock,
and OTP integration.

Issues in bundled SDK or third-party code are in scope when the integration
creates a product security impact. Otherwise, report them to the upstream
project as well.

## Threat model and security invariants

USB requests and other host-provided input are untrusted. An attacker may also
have physical access to a device. Private credentials, seeds, PIN state, Vault
material, and authorization state must not be exposed or bypassed through
malformed input, unauthorized commands, reset, recovery, or downgrade paths.

Security-sensitive parsing must be bounds-checked, authorization must occur
before protected operations, and failures must not leave the device in a more
privileged state. Hardware protection differs by MCU; consult the project
documentation when assessing flash-dump and physical-extraction claims.

## Reporting

Use a private GitHub security advisory for the
[pico-fido repository](https://github.com/polhenarejos/pico-fido/security/advisories/new)
when available. Otherwise contact the maintainers through the private channel
listed by the project. Include the affected version or commit, board and MCU,
transport, attack prerequisites, impact, and a minimal reproduction.

Do not include private keys, seeds, PINs, credentials, license files, device
images containing secrets, or other sensitive data in a report. Do not open a
public issue for an unpatched vulnerability.

## Out of scope and limitations

Pure documentation issues, specification questions without a security impact,
and third-party vulnerabilities with no impact from this product's integration
are not security findings here. Hardware limitations described in the project
documentation are not by themselves vulnerabilities; report a bypass or an
impact that exceeds the documented limitation.

Only the latest release on the default branch is currently supported.
