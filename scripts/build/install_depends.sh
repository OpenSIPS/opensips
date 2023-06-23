#!/bin/sh

set -e

PKGS=""
for pkg in `cat "$(dirname $0)/apt_requirements.txt"`
do
  if [ "${BUILD_OS}" = ubuntu-22.04 -a "${pkg}" = python-dev ]
  then
    pkg="python-dev-is-python3"
  fi
  PKGS="${PKGS} ${pkg}"
done

. $(dirname $0)/build.conf.sub

if [ ! -z "${PRE_INSTALL_CMD}" ]
then
	${PRE_INSTALL_CMD}
fi

sudo apt-get update -y
sudo apt-get -y remove libmemcached11 libpq5
sudo apt-get -y autoremove
sudo apt-get -y --allow-downgrades install ${PKGS}

if [ ! -z "${POST_INSTALL_CMD}" ]
then
	${POST_INSTALL_CMD}
fi
