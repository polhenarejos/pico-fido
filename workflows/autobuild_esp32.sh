#!/bin/bash

git submodule update --init --recursive
sudo apt update
sudo apt install -y cmake gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib
git clone https://github.com/raspberrypi/pico-sdk
cd pico-sdk
git submodule update --init
cd ..
mkdir build
cd build
cmake -DPICO_SDK_PATH=../pico-sdk ..
make

sudo apt install -y git wget flex bison gperf python3 python3-pip python3-venv cmake ninja-build ccache libffi-dev libssl-dev dfu-util libusb-1.0-0
git clone --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32s3
. ./export.sh
cd ..
mkdir build_esp
cd build_esp
idf.py all
