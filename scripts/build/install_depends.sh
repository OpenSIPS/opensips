#!/bin/sh

set -e

PKGS=""
for pkg in `grep -A 35 packages: .travis.yml  | grep -e '^ *[-]' | awk '{print $2}'`
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
sudo apt-get -y install ${PKGS}

if [ ! -z "${POST_INSTALL_CMD}" ]
then
	${POST_INSTALL_CMD}
fi
