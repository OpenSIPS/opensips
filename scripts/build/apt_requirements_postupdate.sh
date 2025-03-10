#!/bin/sh
# handle package naming transitions across Ubuntu 20.04
# and GitHub-specific Ubuntu 22.04 multi-arch (e.g. i386, using 20.04 packages)

find_debs() {
  echo -n $(apt-cache --names-only search "$1" | awk '{print $1}' | grep -oE "^($2)$" | xargs)
}

libodbc_debs=$(find_debs odbc "libodbc2|libodbcinst2|libodbc1|odbcinst1debian2")
[ -z "$libodbc_debs" ] && libodbc_debs="libodbc2 libodbcinst2"

python_debs=$(find_debs python "python3-setuptools|python-setuptools")
[ -z "$python_debs" ] && python_debs="python3-setuptools"

# Output: a space-separated list of packages
echo -n "$libodbc_debs $python_debs"
