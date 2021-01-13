#!/bin/sh

set -e

AR=${AR:-"ar"}
RANLIB=${RANLIB:-"ranlib"}

LINKARGS=""
ARNAME=""
nmfollows=0
for var in "$@"
do
  if [ ${nmfollows} -ne 0 ]
  then
    ARNAME="${var}"
    nmfollows=0
    continue
  fi
  if [ "${var}" != "-o" ]
  then
    LINKARGS="${LINKARGS} ${var}"
    continue
  fi
  nmfollows=1
done

${AR} cr "${ARNAME}" ${LINKARGS}
${RANLIB} "${ARNAME}"
