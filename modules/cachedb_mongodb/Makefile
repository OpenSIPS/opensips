# $Id: Makefile 6253 2009-10-12 19:00:53Z bogdan_iancu $
#
# Presence Agent
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=cachedb_mongodb.so

ifeq ($(CROSS_COMPILE),)
JSON_BUILDER = $(shell \
	if pkg-config --exists json; then \
		echo 'pkg-config json'; \
	fi)
endif

ifeq ($(JSON_BUILDER),)
	DEFS += -I$(LOCALBASE)/include
	LIBS += -L$(LOCALBASE)/lib -ljson
else
	DEFS += $(shell $(JSON_BUILDER) --cflags)
	LIBS += $(shell $(JSON_BUILDER) --libs)
endif

DEFS += -I$(LOCALBASE)/include
LIBS += -L$(LOCALBASE)/lib -lmongoc

include ../../Makefile.modules
