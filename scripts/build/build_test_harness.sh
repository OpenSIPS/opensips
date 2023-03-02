#!/bin/sh

set -e

. $(dirname $0)/dockerize.sub

make Makefile.conf
sed -i.bak '/-DCC_O0/d' Makefile.conf
echo 'DEFS+= -I$(shell pwd)/'"${1}" >> Makefile.conf
echo 'LIBS+= -L$(TOP_SRCDIR)/'"${1}" >> Makefile.conf
if [ "${BUILD_OS}" = "ubuntu-22.04" ]
then
  case "${COMPILER}" in
  *-qemu-cross)
    continue
    ;;
  *)
    echo 'DEFS+= -flto' >> Makefile.conf
    echo 'LIBS+= -flto' >> Makefile.conf
    ;;
  esac
fi
sh -x scripts/build/do_build.sh DEFS_EXTRA_OPTS="-DUNIT_TESTS -fPIE -fPIC"
