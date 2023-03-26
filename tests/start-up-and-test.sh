#!/bin/bash -eu

/usr/sbin/pcscd &
sleep 2
rm -f memory.flash
cp -R tests/docker/fido2/* /usr/local/lib/python3.9/dist-packages/fido2/hid
./build_in_docker/pico_fido > /dev/null &
pytest tests
