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
	DEFS += $(shell $(JSON_BUILDER) --cflags)
	LIBS += $(shell $(JSON_BUILDER) --libs)
endif

ifeq ($(CROSS_COMPILE),)
MONGOC_BUILDER = $(shell \
	if pkg-config --exists libmongoc-1.0; then \
		echo 'pkg-config libmongoc-1.0'; \
	fi)
endif

ifeq ($(MONGOC_BUILDER),)
	DEFS += -I$(SYSBASE)/include/libmongoc-1.0 -I$(SYSBASE)/include/libbson-1.0
	LIBS += -L$(LOCALBASE)/lib -lssl -lcrypto -lrt -lmongoc-1.0 -lbson-1.0
else
	DEFS += $(shell $(MONGOC_BUILDER) --cflags)
	LIBS += $(shell $(MONGOC_BUILDER) --libs)
endif

include ../../Makefile.modules
