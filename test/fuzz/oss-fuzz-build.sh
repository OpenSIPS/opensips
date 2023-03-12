#!/bin/bash -eu
# Copyright 2022 OpenSIPS Solutions
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

set -e

MAKE="${MAKE:-"make"}"
SED="${SED:-"sed"}"
LIBS="${LIBS:-"-ldl -lresolv"}"
OUT="${OUT:-"`pwd`"}"
LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:-""}"
CC="${CC:-"cc"}"
CFLAGS="${CFLAGS:-""}"

${MAKE} Makefile.conf

# disable all custom memory allocators, use system malloc instead
${SED} -i '
  s/^#*DEFS+= -DPKG_MALLOC/DEFS+= -DSYSTEM_MALLOC/g
  s/^\(DEFS+= -DUSE_MCAST\)/#\1/g
  s/^\(DEFS+= -DF_MALLOC\)/#\1/g
  s/^\(DEFS+= -DQ_MALLOC\)/#\1/g
  s/^\(DEFS+= -DHP_MALLOC\)/#\1/g
  s/^\(DEFS+= -DDBG_MALLOC\)/#\1/g
  s/^\(DEFS+= -DDBG_MALLOC\)/#\1/g
  s/^#\(DEFS+= -DFUZZ_BUILD\)/\1/g
  ' Makefile.conf

if [ -z "${LIB_FUZZING_ENGINE}" ]
then
  echo 'DEFS+=-DFUZZ_STANDALONE' >> Makefile.conf
fi

ln -sf `pwd`/test/fuzz/fuzz_*.c ./parser/

${MAKE} static

rm -f main.o libopensips.a
ar -cr libopensips.a `find . -name "*.o" | grep -v '/fuzz_.*.o$'`

for fuzn in msg_parser uri_parser csv_parser core_funcs
do
  $CC $CFLAGS $LIB_FUZZING_ENGINE ./parser/fuzz_${fuzn}.o libopensips.a  ${LIBS} -o $OUT/fuzz_${fuzn}
done
