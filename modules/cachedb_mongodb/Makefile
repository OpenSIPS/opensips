#
# MongoDB C client
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=cachedb_mongodb.so

include ../../lib/json/Makefile.json

ifeq ($(CROSS_COMPILE),)
MONGOC_BUILDER = $(shell \
	if pkg-config --exists libmongoc-1.0; then \
		echo 'pkg-config libmongoc-1.0'; \
	fi)
endif

ifeq ($(MONGOC_BUILDER),)
	DEFS += -I$(SYSBASE)/include/libmongoc-1.0 -I$(SYSBASE)/include/libbson-1.0
	LIBS += -L$(LOCALBASE)/lib -lssl -lcrypto -lrt -lmongoc-1.0 -lbson-1.0
	LIBS += -dl -Bsymbolic
else
	DEFS += $(shell $(MONGOC_BUILDER) --cflags)
	LIBS += $(shell $(MONGOC_BUILDER) --libs)
	LIBS += -dl -Bsymbolic
endif

include ../../Makefile.modules
