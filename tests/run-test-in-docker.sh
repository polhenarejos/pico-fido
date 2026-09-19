#!/bin/bash -eu

source tests/docker_env.sh

if [ -z "${PICO_FIDO_VAULT_ENROLLMENT_JSON:-}" ] && [ -z "${PICO_FIDO_VAULT_ENROLLMENT:-}" ]; then
    default_enrollment="$HOME/.config/PicoKeys/vault/enrollment-35d3ddbcebc9-Test.json"
    if [ -f "$default_enrollment" ]; then
        PICO_FIDO_VAULT_ENROLLMENT_JSON="$(<"$default_enrollment")"
    fi
fi

run_in_docker \
    -e "PICO_FIDO_VAULT_ENROLLMENT_JSON=${PICO_FIDO_VAULT_ENROLLMENT_JSON:-}" \
    -e "PICO_FIDO_VAULT_ENROLLMENT=${PICO_FIDO_VAULT_ENROLLMENT:-}" \
    -e "PICO_FIDO_VAULT_PASSPHRASE=${PICO_FIDO_VAULT_PASSPHRASE:-}" \
    ./tests/start-up-and-test.sh
