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

cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(pico_fido C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(pico_fido)

target_sources(pico_fido PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/fido.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/files.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_register.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_authenticate.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cmd_version.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_reset.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_get_info.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_make_credential.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/known_apps.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/cbor_client_pin.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fido/credential.c
        )
set(HSM_DRIVER "hid")
include(pico-hsm-sdk/pico_hsm_sdk_import.cmake)

target_include_directories(pico_fido PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/fido
        )

target_compile_options(pico_fido PUBLIC
    -Wall
    -Werror
    )
string(FIND ${CMAKE_C_COMPILER} ":" COMPILER_COLON)
if (${COMPILER_COLON} GREATER_EQUAL 0)
        target_compile_options(pico_fido PUBLIC
        -Wno-error=use-after-free
        )
endif()

pico_add_extra_outputs(pico_fido)

target_link_libraries(pico_fido PRIVATE pico_hsm_sdk pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc tinyusb_device tinyusb_board)
