# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=httpd.so

# set CROSS_COMPILE to true if you want to skip
# the autodetection
# CROSS_COMPILE=true
ifeq ($(CROSS_COMPILE),)
LIBMICROHTTPD_BUILDER=$(shell \
	if pkg-config --exists libmicrohttpd; then \
		echo 'pkg-config libmicrohttpd'; \
	fi)
endif

ifneq ($(LIBMICROHTTPD_BUILDER),)
	DEFS += $(shell $(LIBMICROHTTPD_BUILDER) --cflags)
	LIBS += $(shell $(LIBMICROHTTPD_BUILDER) --libs)
else
	DEFS +=-I$(LOCALBASE)/include
	LIBS +=-L$(LOCALBASE)/lib -lmicrohttpd
endif

DEFS +=-DLIBMICROHTTPD

include ../../Makefile.modules

