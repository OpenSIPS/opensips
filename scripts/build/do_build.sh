#!/bin/sh

set -e

. $(dirname $0)/build.conf.sub
. $(dirname $0)/dockerize.sub

EXCLUDE_MODULES="db_oracle osp sngtc cachedb_cassandra cachedb_couchbase \
  cachedb_mongodb auth_jwt event_kafka aaa_diameter launch_darkly http2d \
  snmpstats cachedb_dynamodb event_sqs rtp.io"
if [ ! -z "${EXCLUDE_MODULES_ADD}" ]
then
  EXCLUDE_MODULES="${EXCLUDE_MODULES} ${EXCLUDE_MODULES_ADD}"
fi

MAKE_ENV="FASTER=1 NICER=0"
MAKE_CMD="${MAKE_ENV} make"

if [ ! -z "${ONE_MODULE}" ]
then
  env CC_EXTRA_OPTS="${CC_EXTRA_OPTS:-"-Werror -Wno-atomic-alignment"}" ${MAKE_CMD} \
   -C "modules/${ONE_MODULE}"
else
  env CC_EXTRA_OPTS="${CC_EXTRA_OPTS:-"-Werror -Wno-atomic-alignment"}" ${MAKE_CMD} \
   exclude_modules="${EXCLUDE_MODULES}" "${@}" ${MAKE_TGT:-"all"}
fi
