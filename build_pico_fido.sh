#!/bin/bash

VERSION_MAJOR="6"
VERSION_MINOR="4"
SUFFIX="${VERSION_MAJOR}.${VERSION_MINOR}"
#if ! [[ -z "${GITHUB_SHA}" ]]; then
#    SUFFIX="${SUFFIX}.${GITHUB_SHA}"
#fi

rm -rf release/*
mkdir -p build_release
mkdir -p release
cd build_release
PICO_SDK_PATH="${PICO_SDK_PATH:-../../pico-sdk}"
board_dir=${PICO_SDK_PATH}/src/boards/include/boards
for board in "$board_dir"/*
do
    board_name="$(basename -- $board .h)"
    rm -rf *
    PICO_SDK_PATH="${PICO_SDK_PATH}" cmake .. -DPICO_BOARD=$board_name -DSECURE_BOOT_PKEY=../../ec_private_key.pem
    make -j`nproc`
    mv pico_fido.uf2 ../release/pico_fido_$board_name-$SUFFIX.uf2
done
