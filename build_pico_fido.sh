#!/bin/bash

VERSION_MAJOR="7"
VERSION_MINOR="0"
SUFFIX="${VERSION_MAJOR}.${VERSION_MINOR}"
#if ! [[ -z "${GITHUB_SHA}" ]]; then
#    SUFFIX="${SUFFIX}.${GITHUB_SHA}"
#fi

mkdir -p build_release
mkdir -p release
rm -rf -- release/*
cd build_release

PICO_SDK_PATH="${PICO_SDK_PATH:-../../pico-sdk}"
SECURE_BOOT_PKEY="${SECURE_BOOT_PKEY:-../../ec_private_key.pem}"
boards=("pico" "pico2")

for board_name in "${boards[@]}"
do
    rm -rf -- ./*
    PICO_SDK_PATH="${PICO_SDK_PATH}" cmake .. -DPICO_BOARD=$board_name -DSECURE_BOOT_PKEY=${SECURE_BOOT_PKEY}
    make -j`nproc`
    mv pico_fido.uf2 ../release/pico_fido_$board_name-$SUFFIX.uf2
done
