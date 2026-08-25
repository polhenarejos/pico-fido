#!/bin/bash -eu

source tests/docker_env.sh
run_in_docker \
    -e "PICO_FIDO_VAULT_ENROLLMENT_JSON=${PICO_FIDO_VAULT_ENROLLMENT_JSON:-}" \
    -e "PICO_FIDO_VAULT_PASSPHRASE=${PICO_FIDO_VAULT_PASSPHRASE:-}" \
    ./tests/start-up-and-test.sh
