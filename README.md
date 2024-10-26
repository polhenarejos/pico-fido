# Pico FIDO
This project transforms your Raspberry Pi Pico into an integrated FIDO Passkey, functioning like a standard USB Passkey for authentication.

## Features
Pico FIDO includes the following features:

- CTAP 2.1 / CTAP 1
- WebAuthn
- U2F
- HMAC-Secret extension
- CredProtect extension
- User presence enforcement through physical button
- User verification with PIN
- Discoverable credentials (resident keys)
- Credential management
- ECDSA authentication
- Support for SECP256R1, SECP384R1, SECP521R1, and SECP256K1 curves
- App registration and login
- Device selection
- Support for vendor configuration
- Backup with 24 words
- Secure lock to protect the device from flash dumps
- Permissions support (MC, GA, CM, ACFG, LBW)
- Authenticator configuration
- minPinLength extension
- Self attestation
- Enterprise attestation
- credBlobs extension
- largeBlobKey extension
- Large blobs support (2048 bytes max)
- OATH (based on YKOATH protocol specification)
- TOTP / HOTP
- Yubikey OTP
- Challenge-response generation
- Emulated keyboard interface
- Button press generates an OTP that is directly typed
- Yubico YKMAN compatible
- Nitrokey nitropy and nitroapp compatible

All features comply with the specifications. If you encounter unexpected behavior or deviations from the specifications, please open an issue.

## Security Considerations

Pico FIDO is an open platform, so exercise caution. The flash memory contents can be easily dumped, potentially revealing private/master keys. It is not feasible to encrypt the content, meaning at least one key (the master key) must be stored in clear text.

If the Pico is stolen, the private and secret keys can be accessed.

## Download
Please visit the [Release page](https://github.com/polhenarejos/pico-fido/releases "Release page") to download the UF2 file for your board.

Note that UF2 files are shipped with a dummy VID/PID to avoid license issues (FEFF:FCFD). If you plan to use it with OpenSC or similar software, you will need to modify the Info.plist of the CCID driver to add these VID/PID values or use the [Pico Patcher tool](https://www.picokeys.com/pico-patcher/).

Alternatively, you can use the legacy VID/PID patcher with the following command:
```sh
./patch_vidpid.sh VID:PID input_hsm_file.uf2 output_hsm_file.uf2
```
You can use any VID/PID (e.g., 234b:0000 from FISJ), but remember that you are not authorized to distribute the binary with a VID/PID that you do not own.

For ease of use, the pure-browser option [Pico Patcher tool](https://www.picokeys.com/pico-patcher/) is highly recommended.

## Build
Before building, ensure you have installed the toolchain for the Pico and that the Pico SDK is properly located on your drive.

```sh
git clone --recursive https://github.com/polhenarejos/pico-fido
cd pico-fido
mkdir build
cd build
PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DPICO_BOARD=board_type -DUSB_VID=0x1234 -DUSB_PID=0x5678
make
```

Note that `PICO_BOARD`, `USB_VID`, and `USB_PID` are optional. If not provided, the default Pico board and VID/PID `FEFF:FCFD` will be used.

After `make` finishes, the binary file `pico_fido.uf2` will be generated. Put your Pico board into loading mode by holding the BOOTSEL button while plugging it in, then copy the UF2 file to the new USB mass storage Pico device. Once copied, the Pico mass storage will disconnect automatically, and the Pico board will reset with the new firmware. A blinking LED will indicate that the device is ready to work.

**Remark:** Pico FIDO uses the HID interface, so VID/PID values are irrelevant in terms of operativity. You can safely use any arbitrary values or the default ones. They are only necessary in case you need to use 3rd-party tools from other vendors.

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

Pico FIDO uses the `HID` driver, which is present in all operating systems. It should be detected by all OS and browser/applications just like normal USB FIDO keys.

## Tests

Tests can be found in the `tests` folder. They are based on [FIDO2 tests](https://github.com/solokeys/fido2-tests "FIDO2 tests") from Solokeys but adapted to the [python-fido2](https://github.com/Yubico/python-fido2 "python-fido2") v1.0 package, which is a major refactor from the previous 0.8 version and includes the latest improvements from CTAP 2.1.

To run all tests, use:

```sh
pytest
```

To run a subset of tests, use the `-k <test>` flag:

```sh
pytest -k test_credprotect
```

## Credits
Pico FIDO uses the following libraries or portion of code:
- MbedTLS for cryptographic operations.
- TinyUSB for low level USB procedures.
- TinyCBOR for CBOR parsing and formatting.
