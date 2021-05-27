#!/bin/sh

set -e

PKGS=`grep -A 35 packages: .travis.yml  | grep -e '^ *[-]' | awk '{print $2}'`

. $(dirname $0)/build.conf.sub

CC_EXTRA_OPTS=${CC_EXTRA_OPTS:-"-Werror"} FASTER=1 NICER=0 make \
  exclude_modules="db_oracle osp sngtc cachedb_cassandra cachedb_couchbase \
  cachedb_mongodb auth_jwt event_kafka aaa_diameter" ${MAKE_TGT:-"all"}
