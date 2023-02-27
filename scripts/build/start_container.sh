#!/bin/sh

set -e

. $(dirname $0)/build.conf.sub

if [ -z "${DOCKR_PLATFORM}" -o -z "${DOCKR_BASE}" ]
then
  echo "DOCKR_BASE / DOCKR_PLATFORM is not set" >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y qemu-user-static
docker run --cidfile /tmp/docker_opensips.cid -d --restart=always --platform linux/${DOCKR_PLATFORM} -v `pwd`:/work ${DOCKR_BASE} sleep infinity
