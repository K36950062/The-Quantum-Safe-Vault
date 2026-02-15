#!/bin/bash
export OQS_INSTALL_PATH="$(pwd)/liboqs/build"
if [ -z "$1" ]; then
    python3 vault.py
else
    python3 "$@"
fi
