# Pico FIDO
This project aims at transforming your Raspberry Pico into a FIDO key integrated. The Pico works as a FIDO key, like a normal USB key for authentication.

## Features
Pico FIDO has implemented the following features:

- CTAP 2.1 / CTAP 1
- WebAuthn
- U2F
- HMAC-Secret extension
- CredProtect extension
- User presence enforcement through physical button
- User Verification with PIN
- Discoverable credentials
- Credential management
- ECDSA and EDDSA authentication
- App registration and login
- Device selection
- Support for vendor Config
- Backup with 24 words
- Secure lock to protect the device from flash dumpings
- Permissions support (MC, GA, CM, ACFG, LBW)
- Authenticator configuration
- minPinLength extension
- Self attestation
- Enterprise attestation
- credBlobs extension
- largeBlobKey extension
- largeBlobs support (2048 bytes máx.)
- OATH (based on YKOATH protocol specification)
- TOTP / HOTP
- Yubikey OTP
- Challenge-response generation
- Emulated keyboard interface
- Button press generates an OTP that is written directly is it was typed
- Yubico YKMAN compatible
- Nitrokey nitropy and nitroapp compatible

All these features are compliant with the specification. Therefore, if you detect some behaviour that is not expected or it does not follow the rules of specs, please open an issue.

## Security considerations
Pico FIDO is an open platform so be careful. The contents in the flash memory may be easily dumpled and obtain the private/master keys. Therefore, it is not possible to encrypt the content. At least, one key (the master, the supreme key) must be stored in clear text.

If the Pico is stolen the contents of private and secret keys can be read.

## Download
Please, go to the [Release page](https://github.com/polhenarejos/pico-fido/releases "Release page") and download the UF2 file for your board.

Note that UF2 files are shiped with a dummy VID/PID to avoid license issues (FEFF:FCFD). If you are planning to use it with OpenSC or similar, you should modify Info.plist of CCID driver to add these VID/PID or use the [Pico Patcher tool](https://www.picokeys.com/pico-patcher/).

Alternatively you can use the legacy VID/PID patcher as follows:
`./patch_vidpid.sh VID:PID input_hsm_file.uf2 output_hsm_file.uf2`

You can use whatever VID/PID (i.e., 234b:0000 from FISJ), but remember that you are not authorized to distribute the binary with a VID/PID that you do not own.

Note that the pure-browser option [Pico Patcher tool](https://www.picokeys.com/pico-patcher/) is the most recommended.

## Build
Before building, ensure you have installed the toolchain for the Pico and the Pico SDK is properly located in your drive.

    git clone https://github.com/polhenarejos/pico-fido
    cd pico-fido
    mkdir build
    cd build
    PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DPICO_BOARD=board_type -DUSB_VID=0x1234 -DUSB_PID=0x5678
    make

Note that PICO_BOARD, USB_VID and USB_PID are optional. If not provided, pico board and VID/PID FEFF:FCFD will be used.

After make ends, the binary file pico_fido.uf2 will be generated. Put your pico board into loading mode, by pushing BOOTSEL button while pluging on, and copy the UF2 to the new fresh usb mass storage Pico device. Once copied, the pico mass storage will be disconnected automatically and the pico board will reset with the new firmware. A blinking led will indicate the device is ready to work.

**Remark:** Pico Fido uses HID interface and thus, VID/PID values are irrelevant in terms of operativity. You can safely use any arbitrary value or the default ones.

## Led blink
Pico FIDO uses the led to indicate the current status. Four states are available:
### Press to confirm
The Led is almost on all the time. It goes off for 100 miliseconds every second.

![Press to confirm](https://user-images.githubusercontent.com/55573252/162008917-6a730eac-396c-44cc-890e-802294be30a3.gif)

### Idle mode
In idle mode, the Pico FIDO goes to sleep. It waits for a command and it is awaken by the driver. The Led is almost off all the time. It goes on for 500 milliseconds every second.

![Idle mode](https://user-images.githubusercontent.com/55573252/162008980-d5a5caad-072e-400c-98e3-2c606b4b2af9.gif)

### Active mode
In active mode, the Pico FIDO is awaken and ready to receive a command. It blinks four times in a second.

![Active](https://user-images.githubusercontent.com/55573252/162008997-1ea8cd7e-5384-4893-9dcb-b473153fc375.gif)

### Processing
While processing, the Pico FIDO is busy and cannot receive additional commands until the current is processed. In this state, the Led blinks 20 times in a second.

![Processing](https://user-images.githubusercontent.com/55573252/162009007-df45111e-2473-4a92-97c5-15c3cd19babd.gif)

## Driver

Pico FIDO uses the `HID` driver, present in all OS. It should be detected by all OS and browser/applications, like normal USB FIDO keys.

## Tests

Tests can be found at `tests` folder. It is based on [FIDO2 tests](https://github.com/solokeys/fido2-tests "FIDO2 tests") from Solokeys, but adapted to [python-fido2](https://github.com/Yubico/python-fido2 "python-fido2") v1.0 package, which is a major refactor from previous 0.8 version and includes latests improvements from CTAP 2.1.

All tests can be run by

```
pytest
```

or by selecting a subset with `-k <test>` flag:
```
pytest -k test_credprotect
```

## Credits
Pico FIDO uses the following libraries or portion of code:
- MbedTLS for cryptographic operations.
- TinyUSB for low level USB procedures.
- TinyCBOR for CBOR parsing and formatting.
