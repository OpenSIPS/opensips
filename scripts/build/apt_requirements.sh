#!/bin/sh

cat <<EOF
flex
bison
make
libsqlite3-dev
libsctp-dev
libradcli-dev
libhiredis-dev
$(if [ "$BUILD_OS" != "ubuntu-20.04" ]; then echo libodbc2; else echo libodbc1; fi)
odbcinst
$(if [ "$BUILD_OS" != "ubuntu-20.04" ]; then echo libodbcinst2; else echo odbcinst1debian2; fi)
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
