#!/bin/sh

set -e

make -C "${1}" CFLAGS="-O1 -fPIE -fPIC" libtap.a
