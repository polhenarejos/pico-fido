#!/bin/bash -eu

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CURRENT_FIDO_EMULATOR="${CURRENT_FIDO_EMULATOR:-${ROOT_DIR}/build_emulation/pico_fido}"
PYTEST="${PYTEST:-${ROOT_DIR}/tests/venv/bin/pytest}"
TEST_FILE="${ROOT_DIR}/tests/pico-fido/test_042_silent_authentication.py"
KEEP_SILENT_ARTIFACTS="${KEEP_SILENT_ARTIFACTS:-0}"
WORK_DIR="$(mktemp -d /tmp/pico-fido-test042.XXXXXX)"
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

    if [ "${status}" -ne 0 ] || [ "${KEEP_SILENT_ARTIFACTS}" = "1" ]; then
        echo "Silent-authentication artifacts: ${WORK_DIR}"
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

start_emulator() {
    phase="$1"
    log_file="${WORK_DIR}/${phase}.log"

    (
        cd "${FLASH_DIR}"
        export PICOKEYS_EMULATION_DISABLE_CCID=1
        exec "${CURRENT_FIDO_EMULATOR}" >"${log_file}" 2>&1
    ) &
    EMULATOR_PID=$!
    wait_for_emulator "${log_file}"
}

run_phase() {
    phase="$1"

    echo "Running test 042 phase: ${phase}"
    start_emulator "${phase}"
    PICO_FIDO_SILENT_PHASE="${phase}" PICO_FIDO_SILENT_DIR="${STATE_DIR}" "${PYTEST}" -q "${TEST_FILE}"
    stop_emulator
}

trap cleanup EXIT
trap 'exit 130' INT TERM

for required_file in "${CURRENT_FIDO_EMULATOR}" "${PYTEST}" "${TEST_FILE}"; do
    if [ ! -f "${required_file}" ]; then
        echo "Required file not found: ${required_file}" >&2
        exit 1
    fi
done

for executable in "${CURRENT_FIDO_EMULATOR}" "${PYTEST}"; do
    if [ ! -x "${executable}" ]; then
        echo "File is not executable: ${executable}" >&2
        exit 1
    fi
done

run_phase create
run_phase verify

echo "Test 042 silent-authentication workflow passed."
