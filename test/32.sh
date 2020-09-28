#!/usr/bin/env bash
# database access with fetch_result for usrloc on postgres

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

if ! (check_sipp && check_opensips && check_module "db_postgres"); then
	exit 0
fi ;

CFG=11.cfg

cp $CFG $CFG.bak

echo "loadmodule \"db_postgres/db_postgres.so\"" >> $CFG
echo "modparam(\"usrloc\", \"db_url\", \"postgres://opensips:opensipsrw@localhost/opensips\")" >> $CFG
echo "modparam(\"usrloc\", \"fetch_rows\", 13)" >> $CFG

DOMAIN="local"

COUNTER=0
while [  $COUNTER -lt 139 ]; do
	COUNTER=$(($COUNTER+1))
	PGPASSWORD='opensipsrw' psql -A -t -n -q -h localhost -U opensips opensips -c "insert into location (username, domain, contact, user_agent) values ('foobar-$COUNTER', '$DOMAIN', 'foobar-$COUNTER@$DOMAIN', '___test___');"
done

../opensips -w . -f $CFG > /dev/null
ret=$?

sleep 1
killall -9 opensips

PGPASSWORD='opensipsrw' psql -A -t -n -q -h localhost -U opensips opensips -c "delete from location where user_agent = '___test___'"

mv $CFG.bak $CFG

exit $ret
