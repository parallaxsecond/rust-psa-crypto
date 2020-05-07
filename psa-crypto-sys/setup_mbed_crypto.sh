#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# Copyright 2020 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------

MBED_COMMIT=$1
if [[ -z "$MBED_COMMIT" ]]; then
    >&2 echo "No mbed commit provided."
    exit 1
fi

MBED_GITHUB_URL="https://github.com/ARMmbed/mbedtls"
MBED_ROOT_FOLDER_NAME="mbedtls"
MBED_LIB_FILENAME="libmbedcrypto.a"
MBED_SHIMLIB_DIR="src/c"

# Where to clone the Mbed Crypto library
TEMP_FOLDER=$2
if [[ -z "$TEMP_FOLDER" ]]; then
    >&2 echo "No temporary folder for mbed provided."
    exit 1
fi

# These options refer to CC and AR
OPTIONS="$3 $4"

if [[ -z "$(type git 2> /dev/null)" ]]; then
    >&2 echo "Git not installed."
    exit 1
fi

get_mbed_repo() {
    echo "No mbed-crypto present locally. Cloning."
    git clone $MBED_GITHUB_URL $MBED_ROOT_FOLDER_NAME
    pushd $MBED_ROOT_FOLDER_NAME
    git checkout $MBED_COMMIT
}

setup_mbed_library() {
    echo "Building libmbedcrypto."
    #TODO: explain the bug with SHARED, it is needed for correct linking on some Linux machine
    make SHARED=0 $OPTIONS > /dev/null
}

# Fetch mbed-crypto source code
mkdir -p $TEMP_FOLDER
pushd $TEMP_FOLDER
if [[ -d "$MBED_ROOT_FOLDER_NAME" ]]; then
    pushd $MBED_ROOT_FOLDER_NAME
else
    get_mbed_repo
fi

# Set up lib
if [[ -e "library/$MBED_LIB_FILENAME" ]]; then
    echo "Library is set up."
else
    setup_mbed_library
fi

# Build shimlib
INCLUDE="`pwd`/include"
SRCDIR="$CARGO_MANIFEST_DIR/$MBED_SHIMLIB_DIR"
pushd "$OUT_DIR" || exit 1
#xx Some config may be needed here, and what about cross-compilation?
cc -I"$INCLUDE" -Wall -Werror -O2 -c "$SRCDIR"/shim.c -o shim.o
ar rv libshim.a shim.o
