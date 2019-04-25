#!/bin/bash
# test cfgutils module

# Copyright (C) 2008 1&1 Internet AG
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

if ! (check_netcat && check_opensips); then
	exit 0
fi;

if [ -e core ] ; then
	echo "core file found, not run"
	exit 0
fi;

CFG=33.cfg

cp $CFG $CFG.bak

../opensips -w . -f $CFG > /dev/null
ret=$?

sleep 1

if [ $ret -eq 0 ] ; then
	opensips-cli -x mi check_config_hash |grep "The actual config file hash is identical to the stored one." > /dev/null
	ret=$?
fi;

echo " " >> $CFG
if [ $ret -eq 0 ] ; then
	opensips-cli -x mi check_config_hash |grep "The actual config file hash is identical to the stored one." /dev/null
	ret=$?
fi;

if [ ! $ret -eq 0 ] ; then
	# send a message
	cat register.sip | nc -q 1 -u localhost 5060 > /dev/null
fi;

sleep 1
killall -9 opensips &> /dev/null
ret=$?

if [ $ret -eq 0 ] ; then
	ret=1
else
	ret=0
fi;

if [ ! -e core ] ; then
	ret=1
fi;
rm core
mv $CFG.bak $CFG

exit $ret
