#!/bin/bash
# runs ../opensips with all command line arguments.
# ommited options are -h -v -C -c -D

# Copyright (C) 2007 1&1 Internet AG
#
# This file is part of opensips, a free SIP server.
#
# opensips is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version
#
# opensips is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

source include/require

if ! (check_opensips); then
	exit 0
fi ;

# the config file
CFG=18.cfg

# setup config
echo -e "log_level=3" > $CFG

# start:
../opensips -f ./$CFG -l 127.0.0.1 -n 0 -rR -v  -E -d -T -N 0 -b 23 -m 42 -w ./  -u $(id -u)  -g $(id -g) -P ./pid.out -G ./pgid.out  > /dev/null 2>&1

ret=$?

sleep 1

# clean up:
killall -9 opensips

rm $CFG
rm pgid.out
rm pid.out

exit $ret
