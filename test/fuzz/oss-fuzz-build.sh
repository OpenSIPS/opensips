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

# disable all custom memory allocators, use system malloc instead
sed -i '
  s/^#\?\(DEFS+= -DPKG_MALLOC\)/DEFS+= -DSYSTEM_MALLOC/g
  s/^\(DEFS+= -DUSE_MCAST\)/#\1/g
  s/^\(DEFS+= -DF_MALLOC\)/#\1/g
  s/^\(DEFS+= -DQ_MALLOC\)/#\1/g
  s/^\(DEFS+= -DHP_MALLOC\)/#\1/g
  s/^\(DEFS+= -DDBG_MALLOC\)/#\1/g
  s/^\(DEFS+= -DDBG_MALLOC\)/#\1/g
  s/^#\(DEFS+= -DFUZZ_BUILD\)/\1/g
  ' Makefile.conf.template

# disable update_stat() calls in the parser, since they rely on SHM
sed -i '/update_stat.*bad_URIs/d' parser/parse_uri.c
sed -i '/update_stat.*bad_msg_hdr/d' parser/msg_parser.c

cp ./test/fuzz/fuzz_*.c ./parser/

make static

rm main.o
mkdir objects && find . -name "*.o" -exec cp {} ./objects/ \;
ar -r libopensips.a ./objects/*.o

$CC $CFLAGS $LIB_FUZZING_ENGINE ./parser/fuzz_msg_parser.o ./libopensips.a  -ldl -lresolv -o $OUT/fuzz_msg_parser
$CC $CFLAGS $LIB_FUZZING_ENGINE ./parser/fuzz_uri_parser.o ./libopensips.a  -ldl -lresolv -o $OUT/fuzz_uri_parser
$CC $CFLAGS $LIB_FUZZING_ENGINE ./parser/fuzz_csv_parser.o ./libopensips.a  -ldl -lresolv -o $OUT/fuzz_csv_parser
