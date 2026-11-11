#!/bin/sh

. $(dirname $0)/build.conf.sub

RELEASE="$(lsb_release -cs)"
if [ "${RELEASE}" = "bookworm" ]
then
  RELEASE="jammy"
fi
URL="http://archive.ubuntu.com/ubuntu"
KEY="871920D1991BC93C"
KEYFILE="/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg"
KEYRING="/usr/share/keyrings/ubuntu-archive-keyring.gpg"

has_key() {
  [ -s "${1}" ] && gpg --show-keys --with-colons "${1}" 2>/dev/null | \
    grep -q "${KEY}"
}

echo "deb $URL $RELEASE main universe
deb $URL $RELEASE-updates main universe
deb $URL $RELEASE-security main universe" | ${SUDO} tee /etc/apt/sources.list > /dev/null

# Ubuntu images ship the archive key already.  Ask the keyserver only when
# the image has no copy of it, and never replace a good key file with the
# empty output of a failed download: apt then rejects every repository in
# sources.list with NO_PUBKEY.
if has_key "${KEYFILE}"
then
  exit 0
fi
if has_key "${KEYRING}"
then
  ${SUDO} cp "${KEYRING}" "${KEYFILE}"
  ${SUDO} chmod 644 "${KEYFILE}"
  exit 0
fi

i=1
until gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys "${KEY}"
do
  if [ "${i}" -ge 5 ]
  then
    echo "cannot get key ${KEY} from keyserver.ubuntu.com" >&2
    exit 1
  fi
  echo "keyserver attempt ${i}/5 failed; retrying" >&2
  i=$((i + 1))
  sleep 5
done
TMPKEY="$(mktemp)"
gpg --export "${KEY}" > "${TMPKEY}"
if ! has_key "${TMPKEY}"
then
  rm -f "${TMPKEY}"
  echo "key ${KEY} was not exported" >&2
  exit 1
fi
${SUDO} cp "${TMPKEY}" "${KEYFILE}"
${SUDO} chmod 644 "${KEYFILE}"
rm -f "${TMPKEY}"
