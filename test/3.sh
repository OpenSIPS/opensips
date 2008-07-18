#!/bin/bash
# creates a mysql database with opensipsdbctl and deletes it again

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

# Needs a mysql database, the root user password must be given
# in the file 'dbrootpw' in the test directory

if [ ! -f dbrootpw ] ; then
	echo "no root password, not run"
	exit 0
fi ;

source dbrootpw

tmp_name=""$RANDOM"_opensipsdb_tmp"

cd ../scripts

# setup config file
cp opensipsctlrc opensipsctlrc.bak
sed -i "s/# DBENGINE=MYSQL/DBENGINE=MYSQL/g" opensipsctlrc
sed -i "s/# INSTALL_EXTRA_TABLES=ask/INSTALL_EXTRA_TABLES=yes/g" opensipsctlrc
sed -i "s/# INSTALL_PRESENCE_TABLES=ask/INSTALL_PRESENCE_TABLES=yes/g" opensipsctlrc

cp opensipsdbctl opensipsdbctl.bak
sed -i "s/TEST=\"false\"/TEST=\"true\"/g" opensipsdbctl

# set the mysql root password
cp opensipsdbctl.mysql opensipsdbctl.mysql.bak
sed -i "s/#PW=""/PW="$PW"/g" opensipsdbctl.mysql

./opensipsdbctl create $tmp_name > /dev/null
ret=$?

if [ "$ret" -eq 0 ] ; then
	./opensipsdbctl drop $tmp_name > /dev/null
	ret=$?
fi ;

# cleanup
mv opensipsctlrc.bak opensipsctlrc
mv opensipsdbctl.mysql.bak opensipsdbctl.mysql
mv opensipsdbctl.bak opensipsdbctl

cd ../test
exit $ret
