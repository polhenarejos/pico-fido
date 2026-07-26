#!/bin/bash -eu

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "${PICO_FIDO_SILENT_CONTAINER:-0}" != "1" ]; then
    cd "${ROOT_DIR}"
    source tests/docker_env.sh
    run_in_docker \
        -e PICO_FIDO_SILENT_CONTAINER=1 \
        -e CURRENT_FIDO_EMULATOR="${CURRENT_FIDO_EMULATOR:-${ROOT_DIR}/build_in_docker/pico_fido}" \
        ./tests/run-test-042-in-docker.sh
    exit $?
fi

WORK_DIR="$(mktemp -d /tmp/pico-fido-test042-ci.XXXXXX)"
PCSC_PID=""

stop_pcscd() {
    if [ -n "${PCSC_PID}" ]; then
        kill "${PCSC_PID}" 2>/dev/null || true
        wait "${PCSC_PID}" 2>/dev/null || true
        PCSC_PID=""
    fi
}

cleanup() {
    status=$?
    stop_pcscd

    if [ "${status}" -ne 0 ]; then
        echo "pcscd log:" >&2
        tail -n 80 "${WORK_DIR}/pcscd.log" >&2 || true
    fi

    rm -rf "${WORK_DIR}"
    exit "${status}"
}

trap cleanup EXIT
trap 'exit 130' INT TERM

/usr/sbin/pcscd --foreground >"${WORK_DIR}/pcscd.log" 2>&1 &
PCSC_PID=$!

sleep 2

FIDO2_HID_DIR="$(python3 -c 'from pathlib import Path; import fido2.hid; print(Path(fido2.hid.__file__).parent)')"
cp -R "${ROOT_DIR}/tests/docker/fido2/." "${FIDO2_HID_DIR}/"

CURRENT_FIDO_EMULATOR="${CURRENT_FIDO_EMULATOR}" \
PYTEST="$(command -v pytest)" \
"${ROOT_DIR}/tests/run-test-042-silent-authentication.sh"
