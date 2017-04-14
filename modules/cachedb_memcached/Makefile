# $Id: Makefile 5862 2009-07-15 10:06:05Z andreidragus $
#
# Memcached implementation for memcache API.
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=cachedb_memcached.so

ifeq ($(CROSS_COMPILE),)
LIBS=-lmemcached
else
DEFS+=-I$(LOCALBASE)/include
LIBS=-L$(LOCALBASE)/lib -lmemcached
endif

include ../../Makefile.modules
