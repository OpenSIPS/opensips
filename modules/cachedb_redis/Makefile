# $Id: Makefile 6253 2009-10-12 19:00:53Z bogdan_iancu $
#
# Presence Agent
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=cachedb_redis.so

HAVE_REDIS_SSL=$(shell if [ -n "`ldconfig -p | grep hiredis_ssl`" ]; \
	then echo "HAVE_REDIS_SSL"; fi)
ifeq ($(HAVE_REDIS_SSL), HAVE_REDIS_SSL)
	LIBS+=-lhiredis_ssl -lssl -lcrypto
	DEFS+= -DHAVE_REDIS_SSL
endif

ifeq ($(CROSS_COMPILE),)
LIBS+=-lhiredis
else
DEFS+=-I$(LOCALBASE)/include
LIBS=-L$(LOCALBASE)/lib -lhiredis
endif

include ../../Makefile.modules
