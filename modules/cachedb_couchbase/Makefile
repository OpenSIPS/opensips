# $Id: Makefile 6253 2009-10-12 19:00:53Z vladut_paiu $
#
# Couchbase connector
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=cachedb_couchbase.so

ifeq ($(CROSS_COMPILE),)
LIBS=-lcouchbase
else
DEFS+=-I$(LOCALBASE)/include
LIBS=-L$(LOCALBASE)/lib -lcouchbase
endif

include ../../Makefile.modules
