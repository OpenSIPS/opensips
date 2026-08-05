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
  APT_OPTS="-o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::http::Pipeline-Depth=0"
  ${SUDO} apt-get ${APT_OPTS} update
  ${SUDO} apt-get ${APT_OPTS} install -y docker.io
fi
docker run --rm --privileged tonistiigi/binfmt:latest -install all
docker run --cidfile /tmp/docker_opensips.cid -d --restart=always \
 --platform linux/${DOCKR_PLATFORM} -v sources:`pwd` "${BUILD_OS}" \
 tail -f /dev/null
