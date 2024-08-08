#!/bin/sh

set -e

. $(dirname $0)/dockerize.sub

. $(dirname $0)/build.conf.sub

EXCLUDE_MODULES="db_oracle osp sngtc cachedb_cassandra cachedb_couchbase \
  cachedb_mongodb auth_jwt event_kafka aaa_diameter launch_darkly http2d \
  snmpstats cachedb_dynamodb"
if [ ! -z "${EXCLUDE_MODULES_ADD}" ]
then
  EXCLUDE_MODULES="${EXCLUDE_MODULES} ${EXCLUDE_MODULES_ADD}"
fi

CC_EXTRA_OPTS=${CC_EXTRA_OPTS:-"-Werror"} FASTER=1 NICER=0 make \
  exclude_modules="${EXCLUDE_MODULES}" "${@}" ${MAKE_TGT:-"all"}
