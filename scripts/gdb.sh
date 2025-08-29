#!/usr/bin/env bash

PORT=3333

if [[ $# -ge 2 ]]; then
  PORT=$2
fi

arm-none-eabi-gdb -ex "target extended-remote :${PORT}" $1
