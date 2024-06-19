#!/bin/sh

. $(dirname $0)/build.conf.sub

RELEASE="$(lsb_release -cs)"
if [ "${RELEASE}" = "bookworm" ]
then
  RELEASE="jammy"
fi
URL="http://archive.ubuntu.com/ubuntu"

echo "deb $URL $RELEASE main universe
deb $URL $RELEASE-updates main universe
deb $URL $RELEASE-security main universe" | ${SUDO} tee /etc/apt/sources.list > /dev/null
gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 871920D1991BC93C
gpg --export 871920D1991BC93C | ${SUDO} tee /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg > /dev/null
