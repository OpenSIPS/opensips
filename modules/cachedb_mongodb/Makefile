#
# MongoDB C client
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=cachedb_mongodb.so

include ../../lib/json/Makefile.json
ifeq ($(CROSS_COMPILE),)
MONGOC_BUILDER := $(shell \
	if pkg-config --exists mongoc2; then \
		echo 'pkg-config mongoc2'; \
	elif pkg-config --exists libmongoc-1.0; then \
		echo 'pkg-config libmongoc-1.0'; \
	fi)
endif

ifeq ($(MONGOC_BUILDER),)
	# Keep the existing fallback compatible with current libmongoc installs.
	DEFS += -DHAVE_MONGOC_NEW_HEADERS

include ../../Makefile.openssl

	DEFS += -I$(SYSBASE)/include/libmongoc-1.0 -I$(SYSBASE)/include/libbson-1.0
	LIBS += -L$(LOCALBASE)/lib -lrt -lmongoc-1.0 -lbson-1.0
else
	DEFS += $(shell $(MONGOC_BUILDER) --atleast-version=1.13.0 && \
		echo -DHAVE_MONGOC_NEW_HEADERS)
	DEFS += $(shell $(MONGOC_BUILDER) --cflags)
	LIBS += $(shell $(MONGOC_BUILDER) --libs)
endif

include ../../Makefile.modules
