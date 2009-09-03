# $Id: Makefile 5862 2009-07-15 10:06:05Z andreidragus $
#
# Memcached implementation for memcache API.
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

BUILDER = $(shell which curl-config)
ifeq ($(BUILDER),)
	DEFS +=-I$(LOCALBASE)/include
	BUILDAGENTLIBS =-L$(LOCALBASE)/lib -lcurl

else
	DEFS += $(shell net-snmp-config --cflags)
	BUILDAGENTLIBS = $(shell curl-config --libs)
endif 



include ../../Makefile.defs
auto_gen=
NAME=db_http.so
DEFS+=-I$(LOCALBASE)/include
LIBS=$(BUILDAGENTLIBS)

include ../../Makefile.modules
