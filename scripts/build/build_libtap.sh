#!/bin/sh

set -e

. $(dirname $0)/dockerize.sub

. $(dirname $0)/build.conf.sub

make -C "${1}" CFLAGS="-O1 -fPIE -fPIC" libtap.a
