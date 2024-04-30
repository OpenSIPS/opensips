#!/bin/sh

# handle package naming transitions across Ubuntu 20.04 and specific Ubuntu 22.04 arch packaging (e.g. i386)
libodbc_pkg=$(apt-cache --names-only search odbc | awk '{print $1}' | grep -oE "^(libodbc2|libodbcinst2|libodbc1|odbcinst1debian2)$")
[ -z "$libodbc_pkg" ] && libodbc_pkg=$(echo -e "libodbc2\nlibodbcinst2")

cat <<EOF
$libodbc_pkg
EOF
