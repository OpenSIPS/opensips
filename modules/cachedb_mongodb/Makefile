#
# MongoDB C client
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=cachedb_mongodb.so

ifeq ($(CROSS_COMPILE),)
JSON_BUILDER = $(shell \
	if pkg-config --exists json; then \
		echo 'pkg-config json'; \
	elif pkg-config --exists json-c; then\
		echo 'pkg-config json-c'; \
	fi)
endif

ifeq ($(JSON_BUILDER),)
	DEFS += -I$(LOCALBASE)/include -I$(SYSBASE)/include
	LIBS += -L$(LOCALBASE)/lib -ljson
else
	DEFS += $(shell $(JSON_BUILDER) --cflags) $(shell pkg-config --cflags libmongoc-1.0)
	LIBS += $(shell $(JSON_BUILDER) --libs) $(shell pkg-config --libs libmongoc-1.0)
endif

#DEFS += -I$(LOCALBASE)/include
#LIBS += -L$(LOCALBASE)/lib

include ../../Makefile.modules
