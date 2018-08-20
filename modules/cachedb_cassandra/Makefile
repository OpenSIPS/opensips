# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=cachedb_cassandra.so

ifeq ($(CROSS_COMPILE),)
LIBS=-lcassandra
else
DEFS+=-I$(LOCALBASE)/include
LIBS=-L$(LOCALBASE)/lib -lcassandra
endif

include ../../Makefile.modules
