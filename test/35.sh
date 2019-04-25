#!/bin/bash
# check permissions module functionality

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

if ! (check_sipp && check_opensips); then
	exit 0
fi ;

CFG=35.cfg
SRV=5060
UAS=5070
UAC=5080
IP="127.0.0.31"
MASK=27

# add an registrar entry to the db;
mysql --show-warnings -B -u opensips --password=opensipsrw -D opensips -e "INSERT INTO location (username,contact,socket,user_agent,cseq,q) VALUES (\"foo\",\"sip:foo@localhost:$UAS\",\"udp:127.0.0.1:$UAS\",\"ser_test\",1,-1);"

mysql --show-warnings -B -u opensips --password=opensipsrw -D opensips -e "INSERT INTO address (ip_addr, mask) VALUES ('$IP', '$MASK');"

../opensips -w . -f $CFG &> /dev/null
sipp -sn uas -bg -i localhost -m 10 -f 2 -p $UAS &> /dev/null
sipp -sn uac -s foo 127.0.0.1:$SRV -i localhost -m 10 -f 2 -p $UAC &> /dev/null
ret=$?
mysql --show-warnings -B -u opensips --password=opensipsrw -D opensips -e "DELETE FROM address WHERE (ip_addr='$IP' AND mask='$MASK');"

if [ "$ret" -eq 0 ] ; then
	killall sipp
	IP="127.47.6.254"
	MASK=10
	mysql --show-warnings -B -u opensips --password=opensipsrw -D opensips -e "INSERT INTO address (ip_addr, mask) VALUES ('$IP', '$MASK');"
	
	opensips-cli -x mi address_reload
	#opensips-cli -x mi address_dump

	sipp -sn uas -bg -i localhost -m 10 -f 2 -p $UAS &> /dev/null
	sipp -sn uac -s foo 127.0.0.1:$SRV -i localhost -m 10 -f 2 -p $UAC &> /dev/null
	ret=$?
	mysql --show-warnings -B -u opensips --password=opensipsrw -D opensips -e "DELETE FROM address WHERE (ip_addr='$IP' AND mask='$MASK');"
fi;


# cleanup
killall -9 sipp > /dev/null 2>&1
killall -9 opensips > /dev/null 2>&1

mysql  --show-warnings -B -u opensips --password=opensipsrw -D opensips -e "DELETE FROM location WHERE ((contact = \"sip:foo@localhost:$UAS\") and (user_agent = \"ser_test\"));"

exit $ret;
