#!/bin/sh

set -e

EXCLUDE_MODULES="db_oracle osp sngtc cachedb_cassandra cachedb_couchbase \
  cachedb_mongodb auth_jwt event_kafka aaa_diameter launch_darkly http2d \
  snmpstats cachedb_dynamodb event_sqs db_berkeley"
[ -n "${EXCLUDE_MODULES_ADD}" ] && EXCLUDE_MODULES="${EXCLUDE_MODULES} ${EXCLUDE_MODULES_ADD}"

COV_TAR_NAME=${TAR_NAME:-opensips-coverity.tgz}
COV_DIR=${COV_DIR:-cov-int}
VERSION=${VERSION:-$(grep ^VERSION_ Makefile.defs | head -n 3 | awk '{ r=r s $3;s="." } END{ print r}')}
GIT_REVISION=${GIT_REVISION:-$(test -f .gitrevision && cat .gitrevision || git rev-parse --short HEAD)}

cov-build --dir ${COV_DIR} make -j exclude_modules="${EXCLUDE_MODULES}" "${@}" all
echo "cov-build exited with $?"
tar czf ${COV_TAR_NAME} ${COV_DIR}
rm -rf ${COV_DIR}
[ -n "${COV_TOKEN}" ] && curl --form token=${COV_TOKEN} \
  --form email=razvan@opensips.org \
  --form file=@${COV_TAR_NAME} \
  --form version="${VERSION}" \
  --form description="OpenSIPS ${VERSION} ${GIT_REVISION}" \
  https://scan.coverity.com/builds?project=OpenSIPS%2Fopensips
