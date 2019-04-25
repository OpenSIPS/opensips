#!/bin/bash
# loads a carrierroute config for loadbalancing from mysql database

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

CFG=13.cfg

if ! (check_opensips && check_module "carrierroute" ); then
	exit 0
fi ;

cp $CFG $CFG.bak

# setup config
echo "loadmodule \"db_mysql/db_mysql.so\"" >> $CFG
echo "modparam(\"carrierroute\", \"config_source\", \"db\")" >> $CFG

# setup database
MYSQL="mysql opensips -u opensips --password=opensipsrw -e"

$MYSQL "insert into route_tree (id, carrier) values ('1', 'carrier1');"
$MYSQL "insert into route_tree (id, carrier) values ('2', 'default');"
$MYSQL "insert into route_tree (id, carrier) values ('3', 'carrier2');"

$MYSQL "insert into carrierroute (id, carrier, domain, scan_prefix, prob, strip, rewrite_host) values ('1','1','0','49','0.5','0','host1.local');"
$MYSQL "insert into carrierroute (id, carrier, domain, scan_prefix, prob, strip, rewrite_host) values ('2','1','0','49','0.5','0','host2.local');"
$MYSQL "insert into carrierroute (id, carrier, domain, scan_prefix, prob, strip, rewrite_host) values ('3','1','0','42','0.3','0','host3.local');"
$MYSQL "insert into carrierroute (id, carrier, domain, scan_prefix, prob, strip, rewrite_host) values ('4','1','0','42','0.7','0','host4.local');"
$MYSQL "insert into carrierroute (id, carrier, domain, scan_prefix, prob, strip, rewrite_host) values ('5','1','0','','0.1','0','host5.local');"
$MYSQL "insert into carrierroute (id, carrier, domain, scan_prefix, prob, strip, rewrite_host) values ('6','1','1','','0.1','0','host5.local');"
$MYSQL "insert into carrierroute (id, carrier, domain, scan_prefix, prob, strip, rewrite_host) values ('7','1','2','','0.1','0','host5.local');"
$MYSQL "insert into carrierroute (id, carrier, domain, scan_prefix, prob, strip, rewrite_host) values ('8','2','0','','1','0','host6.local');"
$MYSQL "insert into carrierroute (id, carrier, domain, scan_prefix, prob, strip, rewrite_host) values ('9','2','1','','1','0','host6.local');"
$MYSQL "insert into carrierroute (id, carrier, domain, scan_prefix, prob, strip, rewrite_host) values ('10','2','2','','1','0','host6.local');"
$MYSQL "insert into carrierroute (id, carrier, domain, scan_prefix, prob, strip, rewrite_host) values ('11','3','0','','1','0','host1.local');"

$MYSQL "insert into carrierfailureroute(id, carrier, domain, scan_prefix, host_name, reply_code, flags,
mask, next_domain) values ('1', '1', '1', '49', 'host1.local', '404', '', '', '2');"
$MYSQL "insert into carrierfailureroute(id, carrier, domain, scan_prefix, host_name, reply_code, flags,
mask, next_domain) values ('2', '1', '1', '49', 'host1.local', '4..', '', '', '3');"
$MYSQL "insert into carrierfailureroute(id, carrier, domain, scan_prefix, host_name, reply_code, flags,
mask, next_domain) values ('3', '2', '1', '49', 'host1.local', '503', '', '', '2');"
$MYSQL "insert into carrierfailureroute(id, carrier, domain, scan_prefix, host_name, reply_code, flags,
mask, next_domain) values ('4', '2', '2', '49', 'host1.local', '5..', '', '', '3');"

../opensips -w . -f $CFG > /dev/null

ret=$?

sleep 1

cd ../scripts

TMPFILE=`mktemp -t opensips-test.XXXXXXXXXX`

if [ "$ret" -eq 0 ] ; then
	opensips-cli -x mi cr_dump_routes > $TMPFILE
	ret=$?
fi ;

if [ "$ret" -eq 0 ] ; then
	tmp=`grep -v "Printing routing information:
Printing tree for carrier carrier1 (1)
Printing tree for domain 0
        42: 70.140 %, 'host4.local': ON, '0', '', '', ''
        42: 30.060 %, 'host3.local': ON, '0', '', '', ''
        49: 50.000 %, 'host2.local': ON, '0', '', '', ''
        49: 50.000 %, 'host1.local': ON, '0', '', '', ''
      NULL: 100.000 %, 'host5.local': ON, '0', '', '', ''
Printing tree for domain 1
      NULL: 100.000 %, 'host5.local': ON, '0', '', '', ''
Printing tree for domain 2
      NULL: 100.000 %, 'host5.local': ON, '0', '', '', ''
Printing tree for carrier default (2)
Printing tree for domain 0
      NULL: 100.000 %, 'host6.local': ON, '0', '', '', ''
Printing tree for domain 1
      NULL: 100.000 %, 'host6.local': ON, '0', '', '', ''
Printing tree for carrier carrier2 (3)
Printing tree for domain 0
      NULL: 100.000 %, 'host1.local': ON, '0', '', '', ''" $TMPFILE`
	if [ "$tmp" = "" ] ; then
		ret=0
	else
		ret=1
	fi ;
fi ;

killall -9 opensips

# cleanup database
$MYSQL "delete from route_tree where id = 1;"
$MYSQL "delete from route_tree where id = 2;"
$MYSQL "delete from route_tree where id = 3;"
$MYSQL "delete from carrierroute where carrier=1;"
$MYSQL "delete from carrierroute where carrier=2;"
$MYSQL "delete from carrierroute where carrier=3;"
$MYSQL "delete from carrierfailureroute where carrier=1;"
$MYSQL "delete from carrierfailureroute where carrier=2;"
$MYSQL "delete from carrierfailureroute where carrier=3;"

cd ../test

mv $CFG.bak $CFG
rm $TMPFILE

exit $ret
