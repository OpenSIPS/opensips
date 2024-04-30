#!/bin/sh

# handle package transitions across Ubuntu 20.04 and specific Ubuntu 22.04 arch packaging (e.g. i386)
libodbc_pkg=$(apt-cache --names-only search odbc | awk '{print $1}' | grep -oE "^(libodbc2|libodbcinst2|libodbc1|odbcinst1debian2)$")
[ -z "$libodbc_pkg" ] && libodbc_pkg=$(echo -e "libodbc2\nlibodbcinst2")

cat <<EOF
flex
bison
make
libsqlite3-dev
libsctp-dev
libradcli-dev
libhiredis-dev
odbcinst
$libodbc_pkg
unixodbc
unixodbc-dev
libconfuse-dev
libmysqlclient-dev
libexpat1-dev
libxml2-dev
libpq-dev
zlib1g-dev
libperl-dev
libsnmp-dev
libdb-dev
libldap2-dev
libcurl4-gnutls-dev
libgeoip-dev
libpcre3-dev
libmemcached-dev
libmicrohttpd-dev
librabbitmq-dev
liblua5.1-0-dev
libncurses5-dev
libjson-c-dev
uuid-dev
python-dev
libmaxminddb-dev
patch
EOF
