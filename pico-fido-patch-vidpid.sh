#!/bin/bash

#
# This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
# Copyright (c) 2022 Pol Henarejos.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

VERSION_MAJOR="4" #Version of Pico CCID Core
VERSION_MINOR="0"

echo "----------------------------"
echo "VID/PID patcher for Pico FIDO"
echo "----------------------------"
echo ""

if [ "$#" -le 0 ]; then
    echo "Usage: $0 VID:PID [input_uf2_file] [output_uf2_file]"
    exit 1
fi

IFS=':' read -r -a ARR <<< "$1"

if [ ${#ARR[@]} -ne 2 ]; then
    echo "ERROR: Specify vendor and product ids as VID:PID (e.g., $0 CAFE:1234)"
    exit 1
fi

VID=${ARR[0]}
PID=${ARR[1]}

if [ ${#VID} -ne 4 ]; then
    echo "ERROR: VID length must be 4 hexadecimal characters"
    exit 1
fi

if [ ${#PID} -ne 4 ]; then
    echo "ERROR: PID length must be 4 hexadecimal characters"
    exit 1
fi

if ! [[ $VID =~ ^[0-9A-Fa-f]{1,}$ ]] ; then
    echo "ERROR: VID must contain hexadecimal characters"
    exit 1
fi

if ! [[ $PID =~ ^[0-9A-Fa-f]{1,}$ ]] ; then
    echo "ERROR: PID must contain hexadecimal characters"
    exit 1
fi

UF2_FILE_IF="pico_fido.uf2"
UF2_FILE_OF="$UF2_FILE_IF"

if [ "$#" -ge 2 ]; then
    UF2_FILE_IF="$2"
    UF2_FILE_OF="$UF2_FILE_IF"
fi

if [ "$#" -ge 3 ]; then
    UF2_FILE_OF="$3"
fi


echo -n "Patching ${UF2_FILE_IF}... "

if [[ ! -f "$UF2_FILE_IF" ]]; then
    echo "ERROR: UF2 file ${UF2_FILE_IF} does not exist"
    exit 1
fi

if [ "$UF2_FILE_IF" != "$UF2_FILE_OF" ]; then
    cp -R $UF2_FILE_IF $UF2_FILE_OF
fi

LITTLE_VID="\x${VID:2:2}\x${VID:0:2}"
LITTLE_PID="\x${PID:2:2}\x${PID:0:2}"

perl -pi -e "s/[\x00-\xff]{4}\x$VERSION_MINOR\x$VERSION_MAJOR\x01\x02\x03\x01\x00\x00/$LITTLE_VID$LITTLE_PID\x$VERSION_MINOR\x$VERSION_MAJOR\x01\x02\x03\x01\x00\x00/" $UF2_FILE_OF

echo "Done!"
echo ""
echo "Patched file was saved in ${UF2_FILE_OF}"
