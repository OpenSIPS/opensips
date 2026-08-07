#!/bin/sh

set -e

PKGS=$(cat "$(dirname $0)/apt_requirements.txt")
. $(dirname $0)/build.conf.sub
. $(dirname $0)/dockerize.sub

_PKGS=""
for pkg in ${PKGS}
do
  if [ "${BUILD_OS}" != "ubuntu:18.04" -a "${pkg}" = python3-dev ]
  then
    pkg="python-dev-is-python3"
  fi
  if [ "${BUILD_OS%:*}" = "debian" -a "${pkg}" = libmysqlclient-dev ]
  then
    pkg="libmariadb-dev"
  fi
  _PKGS="${_PKGS} ${pkg}"
done
PKGS="${_PKGS}"

# freeDiameter is not available in Ubuntu 18.04.  The corresponding module is
# excluded from the build for that release as well.
if [ "${BUILD_OS}" = "ubuntu:18.04" ]
then
	PKGS="$(exclude_pkgs libfreediameter-dev)"
fi

# OpenTelemetry is built on Ubuntu 26.04, where its development package is
# available.  Keep it out of older releases where the package is unavailable.
if [ "${BUILD_OS}" = "ubuntu:26.04" ]
then
	PKGS="${PKGS} opentelemetry-cpp-dev"
fi

# CI images contain all compiler variants for their Ubuntu release.  Keep the
# normal compiler selection above for regular builds, while allowing the
# image builder to add its complete compiler package set through the existing
# dependency installation path.
if [ -n "${CI_COMPILER_PACKAGES}" ]
then
	PKGS="${PKGS} ${CI_COMPILER_PACKAGES}"
fi

if [ ! -z "${PRE_INSTALL_CMD}" ]
then
	${PRE_INSTALL_CMD}
fi

# Keep transient repository/network problems from failing the whole build.
# These options are deliberately configured here rather than only in the
# workflows, since this script is also used from Docker builds.
APT_OPTS="-o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::http::Pipeline-Depth=0"

# APT can return success after updating only some repositories.  That leaves
# an incomplete package index and causes packages which do exist to be
# reported as unavailable.  Error-Mode=any makes the update transactional
# from the build's point of view; retry the complete update, not just failed
# individual downloads.
APT_UPDATE_OPTS="${APT_OPTS} -o APT::Update::Error-Mode=any"

apt_update()
{
	i=1
	while [ "$i" -le 3 ]
	do
		if ${SUDO} apt-get ${APT_UPDATE_OPTS} update
		then
			return 0
		fi
		echo "APT update attempt ${i}/3 failed; retrying" >&2
		i=$((i + 1))
		sleep 5
	done
	return 1
}

apt_update

REMOVE_PKGS=""
for pkg in libmemcached11 libpq5
do
	if dpkg-query -W -f='${db:Status-Abbrev}' "${pkg}" 2>/dev/null | grep -q '^ii '
	then
		REMOVE_PKGS="${REMOVE_PKGS} ${pkg}"
	fi
done
if [ -n "${REMOVE_PKGS}" ]
then
		${SUDO} apt-get ${APT_OPTS} -y remove ${REMOVE_PKGS}
fi
${SUDO} apt-get ${APT_OPTS} -y autoremove

PKGS="$PKGS $(. "$(dirname $0)/apt_requirements_postupdate.sh")"
${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get ${APT_OPTS} -y --allow-downgrades install ${PKGS}

if [ ! -z "${POST_INSTALL_CMD}" ]
then
	${POST_INSTALL_CMD}
fi
