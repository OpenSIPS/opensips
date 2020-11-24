#!/usr/bin/env bash
# do some routing with carrierroute route sets from a config file

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

if ! (check_sipp && check_opensips && check_module "carrierroute"); then
	exit 0
fi ;

CFG=30.cfg


cp $CFG $CFG.bak

# setup config
echo "modparam(\"carrierroute\", \"config_file\", \"`pwd`/../test/carrierroute-2.cfg\")" >> $CFG


../opensips -w . -f $CFG > /dev/null

ret=$?

sleep 1

if [ "$ret" -eq 0 ] ; then
	# the distribution is not perfect
	sipp -sn uas -bg -i localhost -m 12 -p 7000 &> /dev/null
	sipp -sn uas -bg -i localhost -m 12 -p 8000 &> /dev/null
	sipp -sn uac -s 49721123456787 127.0.0.1:5060 -i 127.0.0.1 -m 20 -p 5061 &> /dev/null
	ret=$?
	killall sipp &> /dev/null
fi;

if [ "$ret" -eq 0 ] ; then
	sipp -sn uas -bg -i localhost -m 10 -p 9000 &> /dev/null
	sipp -sn uac -s 49721123456786 127.0.0.1:5060 -i 127.0.0.1 -m 10 -p 5061 &> /dev/null
	ret=$?
fi;

if [ "$ret" -eq 0 ] ; then
	sipp -sn uas -bg -i localhost -m 10 -p 10000 &> /dev/null
	sipp -sn uac -s 49721123456785 127.0.0.1:5060 -i 127.0.0.1 -m 10 -p 5061 &> /dev/null
	ret=$?
fi;

killall -9 opensips
killall -9 sipp

cd ../test

mv $CFG.bak $CFG

exit $ret
