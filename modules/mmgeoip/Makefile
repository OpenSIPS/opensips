#
#
# WARNING: do not run this directly, it should be run by the master Makefile
#
#
# This file is part of openser, a free SIP server.
#
# openser is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version
#
# openser is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
# USA
#
# History:
# --------
#

include ../../Makefile.defs
auto_gen=
NAME=mmgeoip.so

ifeq ($(GEOIP),)
GEOIP=$(shell if [ -n "`ldconfig -p | grep maxminddb`" ]; then echo "GEOIP2"; \
	elif [ -n "`ldconfig -p | grep libGeoIP`" ];then echo "GEOIPLEGACY"; fi)
endif

ifneq ($(GEOIP), GEOIP2)
ifeq ($(GEOIP), GEOIPLEGACY)
	DEFS+= -DGEOIP
	GEOIP_LIB=-lGeoIP
endif
else
	DEFS+= -DMAXMINDDB
	GEOIP_LIB=-lmaxminddb
endif

ifeq ($(CROSS_COMPILE),)
LIBS=$(GEOIP_LIB)
else
LIBS=-L$(LOCALBASE)/lib $(GEOIP_LIB)
DEFS+=-I$(LOCALBASE)/include
endif

include ../../Makefile.modules
