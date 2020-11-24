#!/usr/bin/env bash
# test basic accounting functionality

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

if ! (check_sipp && check_opensips); then
	exit 0
fi ;

CFG="20.cfg"
TMPFILE=`mktemp -t opensips-test.XXXXXXXXXX`

# add an registrar entry to the db;
mysql --show-warnings -B -u opensips --password=opensipsrw -D opensips -e "INSERT INTO location (username,contact,socket,user_agent,cseq,q) VALUES (\"foo\",\"sip:foo@localhost\",\"udp:127.0.0.1:5060\",\"ser_test\",1,-1);"

sipp -sn uas -bg -i localhost -m 1 -f 10 -p 5060 &> /dev/null

../opensips -w . -f $CFG &> $TMPFILE

sipp -sn uac -s foo 127.0.0.1:5059 -i 127.0.0.1 -m 1 -f 10 -p 5061 &> /dev/null

egrep '^ACC:[[:space:]]+transaction[[:space:]]+answered:[[:print:]]*code=200;reason=OK$' $TMPFILE > /dev/null
ret=$?

# cleanup
killall -9 sipp &> /dev/null
killall -9 opensips &> /dev/null
rm $TMPFILE

mysql  --show-warnings -B -u opensips --password=opensipsrw -D opensips -e "DELETE FROM location WHERE ((contact = \"sip:foo@localhost\") and (user_agent = \"ser_test\"));"

exit $ret;
