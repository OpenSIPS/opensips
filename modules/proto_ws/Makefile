#
# Network WebSocket implementation
#
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=proto_ws.so
LIBS=

#ALLOCATOR_VER = 104
#
## set CROSS_COMPILE to true if you want to skip
## the autodetection
## CROSS_COMPILE=true
#ifeq ($(CROSS_COMPILE),)
#LIBWEBSOCKETS_BUILDER = $(shell \
#	if pkg-config --exists libwebsockets; then \
#		echo 'pkg-config libwebsockets'; \
#	fi)
#endif
#
#ifneq ($(LIBWEBSOCKETS_BUILDER),)
#	DEFS += $(shell $(LIBWEBSOCKETS_BUILDER) --cflags)
#	LIBS += $(shell $(LIBWEBSOCKETS_BUILDER) --libs)
#	LIBWEBSOCKETS_VER = $(shell $(LIBWEBSOCKETS_BUILDER) --modversion)
#else
#	DEFS +=-I$(LOCALBASE)/include
#	LIBS +=-L$(LOCALBASE)/lib -lwebsockets
#	LIBWEBSOCKETS_VER = 1.3
#endif
#
#WEBSOCKETS_VER = $(shell echo $(LIBWEBSOCKETS_VER) | \
#						sed  "s/\.\([0-9]\)\./.0\1./g" | \
#						sed  "s/\.\([0-9]\)\$$/.0\1/g" | \
#						tr -d "." | sed -e "s/^0*//" )
#
#HAVE_ALLOCATOR = $(shell echo $(WEBSOCKETS_VER) $(ALLOCATOR_VER) | \
#			awk '{ if (($$1 >= $$2)) print "-DHAVE_WEBSOCK_ALLOCATOR" }')
#
#ifeq ($(HAVE_ALLOCATOR),)
#$(warning "Your libwebsockets library does not support custom allocators")
#endif
#
#DEFS += $(HAVE_ALLOCATOR)

include ../../Makefile.modules

