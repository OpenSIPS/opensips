#!/bin/sh

set -e

. $(dirname $0)/dockerize.sub

make -C "${1}" CFLAGS="-O1 -fPIE -fPIC" libtap.a
