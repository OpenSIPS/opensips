#!/bin/sh

set -e

. $(dirname $0)/dockerize.sub

PKGS="`grep -A 35 packages: .travis.yml  | grep -e '^ *[-]' | awk '{print $2}'`"

. $(dirname $0)/build.conf.sub

_PKGS=""
for pkg in ${PKGS}
do
  if [ "${BUILD_OS}" = ubuntu-22.04 -a "${pkg}" = python-dev ]
  then
    pkg="python-dev-is-python3"
  fi
  _PKGS="${_PKGS} ${pkg}"
done
PKGS="${_PKGS}"

if [ ! -z "${PRE_INSTALL_CMD}" ]
then
	${PRE_INSTALL_CMD}
fi

${SUDO} apt-get update -y
${SUDO} apt-get -y --allow-downgrades install ${PKGS}

if [ ! -z "${POST_INSTALL_CMD}" ]
then
	${POST_INSTALL_CMD}
fi
