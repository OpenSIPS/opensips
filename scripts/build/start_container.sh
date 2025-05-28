#!/bin/sh

set -e

. $(dirname $0)/build.conf.sub

if [ -z "${DOCKR_PLATFORM}" -o -z "${BUILD_OS}" ]
then
  echo "BUILD_OS / DOCKR_PLATFORM is not set" >&2
  exit 1
fi

if ! docker -v 2>/dev/null
then
  ${SUDO} apt-get update
  ${SUDO} apt-get install -y docker.io
fi
docker run --rm --privileged tonistiigi/binfmt:latest -install all
docker run --cidfile /tmp/docker_opensips.cid -d --restart=always \
 --platform linux/${DOCKR_PLATFORM} -v sources:`pwd` "${BUILD_OS}" \
 tail -f /dev/null
