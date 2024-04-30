#!/bin/sh

# handle package naming transitions across Ubuntu 20.04 and specific Ubuntu 22.04 arch packaging (e.g. i386)
libodbc_pkg=$(apt-cache --names-only search odbc | awk '{print $1}' | grep -oE "^(libodbc2|libodbcinst2|libodbc1|odbcinst1debian2)$" | xargs)
[ -z "$libodbc_pkg" ] && libodbc_pkg="libodbc2 libodbcinst2"

# Output: a space-separated list of packages
echo -n "$libodbc_pkg"
