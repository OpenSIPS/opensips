#!/bin/bash
# test basic fifo functionality

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

CFG=4.cfg

# setup config
echo -e "loadmodule \"../modules/mi_fifo/mi_fifo.so\"" > $CFG
echo -e "modparam(\"mi_fifo\", \"fifo_name\", \"/tmp/opensips_fifo\")" >> $CFG

../opensips -w . -f $CFG > /dev/null
ret=$?

cd ../scripts

if [ "$ret" -eq 0 ] ; then
	sleep 1
	opensips-cli -x mi ps > /dev/null
	ret=$?
fi ;

cd ../test

killall -9 opensips

rm -f $CFG

exit $ret
