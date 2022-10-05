#!/bin/bash

VERSION_MAJOR="2"
VERSION_MINOR="0"

rm -rf release/*
cd build_release

for board in adafruit_feather_rp2040 \
    adafruit_itsybitsy_rp2040 \
    adafruit_kb2040 \
    adafruit_macropad_rp2040 \
    adafruit_qtpy_rp2040 \
    adafruit_trinkey_qt2040 \
    arduino_nano_rp2040_connect \
    datanoisetv_rp2040_dsp \
    eetree_gamekit_rp2040 \
    garatronic_pybstick26_rp2040 \
    melopero_shake_rp2040 \
    pico \
    pico_w \
    pimoroni_badger2040 \
    pimoroni_interstate75 \
    pimoroni_keybow2040 \
    pimoroni_motor2040 \
    pimoroni_pga2040 \
    pimoroni_picolipo_4mb \
    pimoroni_picolipo_16mb \
    pimoroni_picosystem \
    pimoroni_plasma2040 \
    pimoroni_servo2040 \
    pimoroni_tiny2040 \
    pimoroni_tiny2040_2mb \
    seeed_xiao_rp2040 \
    solderparty_rp2040_stamp \
    solderparty_rp2040_stamp_carrier \
    solderparty_rp2040_stamp_round_carrier \
    sparkfun_micromod \
    sparkfun_promicro \
    sparkfun_thingplus \
    vgaboard \
    waveshare_rp2040_lcd_0.96 \
    waveshare_rp2040_plus_4mb \
    waveshare_rp2040_plus_16mb \
    waveshare_rp2040_zero \
    wiznet_w5100s_evb_pico
do
    rm -rf *
    PICO_SDK_PATH=~/Devel/pico/pico-sdk cmake .. -DPICO_BOARD=$board
    make -kj20
    mv pico_fido.uf2 ../release/pico_fido_$board-$VERSION_MAJOR.$VERSION_MINOR.uf2

done
