#!/bin/sh

set -e

PKGS=$(cat "$(dirname $0)/apt_requirements.txt")
. $(dirname $0)/build.conf.sub
. $(dirname $0)/dockerize.sub

_PKGS=""
for pkg in ${PKGS}
do
  if [ "${BUILD_OS}" = "ubuntu:18.04" -a "${pkg}" = "python-dev-is-python3" ]
  then
    pkg="python3-dev"
  fi
  if [ "${BUILD_OS%:*}" = "debian" -a "${pkg}" = libmysqlclient-dev ]
  then
    pkg="libmariadb-dev"
  fi
  _PKGS="${_PKGS} ${pkg}"
done
PKGS="${_PKGS}"

if [ ! -z "${PRE_INSTALL_CMD}" ]
then
	${PRE_INSTALL_CMD}
fi

# Keep transient repository/network problems from failing the whole build.
# These options are deliberately configured here rather than only in the
# workflows, since this script is also used from Docker builds.
APT_OPTS="-o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::http::Pipeline-Depth=0"

${SUDO} apt-get ${APT_OPTS} update -y
${SUDO} apt-get ${APT_OPTS} -y remove libmemcached11 libpq5
${SUDO} apt-get ${APT_OPTS} -y autoremove

PKGS="$PKGS $(. "$(dirname $0)/apt_requirements_postupdate.sh")"
${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get ${APT_OPTS} -y --allow-downgrades install ${PKGS}

if [ ! -z "${POST_INSTALL_CMD}" ]
then
	${POST_INSTALL_CMD}
fi
