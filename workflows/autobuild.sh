#!/bin/bash

git submodule update --init --recursive
sudo apt update
sudo apt install -y cmake gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib build-essential pkg-config libusb-1.0-0-dev
git clone https://github.com/raspberrypi/pico-sdk
cd pico-sdk
git submodule update --init
cd ..
git clone https://github.com/raspberrypi/picotool
cd picotool
git submodule update --init lib/mbedtls
mkdir build
cd build
cmake ..
make -j`nproc`
sudo make install
cd ../..
mkdir build_pico
cd build_pico
cmake -DPICO_SDK_PATH=../pico-sdk ..
make -j`nproc`
