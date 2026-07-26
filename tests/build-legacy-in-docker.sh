#!/bin/bash -eu

source tests/docker_env.sh

LEGACY_SOURCE_DIR="${LEGACY_SOURCE_DIR:-${PWD}/legacy}"
LEGACY_BUILD_DIR="${LEGACY_BUILD_DIR:-${LEGACY_SOURCE_DIR}/build_in_docker}"

if [ ! -f "${LEGACY_SOURCE_DIR}/CMakeLists.txt" ]; then
    echo "Legacy checkout not found: ${LEGACY_SOURCE_DIR}" >&2
    exit 1
fi

run_in_docker mkdir -p "${LEGACY_BUILD_DIR}"
run_in_docker -w "${LEGACY_BUILD_DIR}" cmake -DENABLE_EMULATION=1 -DENABLE_EDDSA=1 "${LEGACY_SOURCE_DIR}"
run_in_docker -w "${LEGACY_BUILD_DIR}" make -j "${NUM_PROC}"
