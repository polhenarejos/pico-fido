#!/bin/bash -eu

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEGACY_FIDO_EMULATOR="${LEGACY_FIDO_EMULATOR:-/tmp/pico-fido-legacy-build/pico_fido}"
CURRENT_FIDO_EMULATOR="${CURRENT_FIDO_EMULATOR:-${ROOT_DIR}/build_emulation/pico_fido}"
PYTEST="${PYTEST:-${ROOT_DIR}/tests/venv/bin/pytest}"
TEST_FILE="${ROOT_DIR}/tests/pico-fido/test_041_object_compatibility.py"
KEEP_COMPAT_ARTIFACTS="${KEEP_COMPAT_ARTIFACTS:-0}"
WORK_DIR="$(mktemp -d /tmp/pico-fido-test041.XXXXXX)"
FLASH_DIR="${WORK_DIR}/flash"
STATE_DIR="${WORK_DIR}/state"
EMULATOR_PID=""

mkdir -p "${FLASH_DIR}" "${STATE_DIR}"

stop_emulator() {
    if [ -n "${EMULATOR_PID}" ]; then
        kill "${EMULATOR_PID}" 2>/dev/null || true
        wait "${EMULATOR_PID}" 2>/dev/null || true
        EMULATOR_PID=""
    fi
}

cleanup() {
    status=$?
    stop_emulator

    if [ "${status}" -ne 0 ] || [ "${KEEP_COMPAT_ARTIFACTS}" = "1" ]; then
        echo "Compatibility artifacts: ${WORK_DIR}"
    else
        rm -rf "${WORK_DIR}"
    fi

    exit "${status}"
}

wait_for_emulator() {
    log_file="$1"

    for _ in $(seq 1 100); do
        if grep -q "HID server listening" "${log_file}"; then
            return 0
        fi
        if ! kill -0 "${EMULATOR_PID}" 2>/dev/null; then
            echo "Emulator exited before opening the HID listener:"
            cat "${log_file}"
            return 1
        fi
        sleep 0.1
    done

    echo "Timed out waiting for the HID listener:"
    cat "${log_file}"
    return 1
}

wait_for_ccid() {
    log_file="$1"

    if python3 - "${EMULATOR_PID}" <<'PY'
import os
import sys
import time

from smartcard.System import readers


emulator_pid = int(sys.argv[1])
deadline = time.monotonic() + 10
last_error = "no PC/SC readers found"

while time.monotonic() < deadline:
    try:
        available_readers = readers()
        if not available_readers:
            last_error = "no PC/SC readers found"

        for reader in available_readers:
            connection = reader.createConnection()
            try:
                connection.connect()
            except Exception as error:
                last_error = f"{reader}: {error}"
                continue

            try:
                connection.disconnect()
            except Exception:
                pass
            sys.exit(0)
    except Exception as error:
        last_error = str(error)

    try:
        os.kill(emulator_pid, 0)
    except ProcessLookupError:
        print("emulator exited while waiting for CCID", file=sys.stderr)
        sys.exit(2)

    time.sleep(0.1)

print(f"CCID did not become ready: {last_error}", file=sys.stderr)
sys.exit(1)
PY
    then
        return 0
    else
        status=$?
    fi

    echo "Emulator did not expose a usable CCID card:" >&2
    cat "${log_file}" >&2
    return "${status}"
}

start_emulator() {
    emulator="$1"
    phase="$2"
    log_file="${WORK_DIR}/${phase}.log"

    (
        cd "${FLASH_DIR}"
        exec "${emulator}" >"${log_file}" 2>&1
    ) &
    EMULATOR_PID=$!
    wait_for_emulator "${log_file}"
    wait_for_ccid "${log_file}"
}

run_phase() {
    phase="$1"
    emulator="$2"

    echo "Running test 041 phase: ${phase}"
    start_emulator "${emulator}" "${phase}"
    PICO_FIDO_COMPAT_PHASE="${phase}" PICO_FIDO_COMPAT_DIR="${STATE_DIR}" "${PYTEST}" -q "${TEST_FILE}"
    stop_emulator

    if [ "${phase}" = "upgrade" ]; then
        if grep -a -q "legacy-container-compat.example" "${FLASH_DIR}/memory.flash"; then
            echo "Legacy RP ID remains plaintext in the upgraded flash image." >&2
            return 1
        fi
        for secret in "legacy-oath-secret" "container-oath-secret"; do
            if grep -a -q "${secret}" "${FLASH_DIR}/memory.flash"; then
                echo "OATH secret remains plaintext in the upgraded flash image." >&2
                return 1
            fi
        done
    fi
}

trap cleanup EXIT
trap 'exit 130' INT TERM

for required_file in "${LEGACY_FIDO_EMULATOR}" "${CURRENT_FIDO_EMULATOR}" "${PYTEST}" "${TEST_FILE}"; do
    if [ ! -f "${required_file}" ]; then
        echo "Required file not found: ${required_file}" >&2
        exit 1
    fi
done

for executable in "${LEGACY_FIDO_EMULATOR}" "${CURRENT_FIDO_EMULATOR}" "${PYTEST}"; do
    if [ ! -x "${executable}" ]; then
        echo "File is not executable: ${executable}" >&2
        exit 1
    fi
done

run_phase create "${LEGACY_FIDO_EMULATOR}"
run_phase upgrade "${CURRENT_FIDO_EMULATOR}"
run_phase restart "${CURRENT_FIDO_EMULATOR}"

echo "Test 041 compatibility workflow passed."
