# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=http2d.so

_makefile_path := $(lastword $(MAKEFILE_LIST))
MOD_DIR ?= $(shell realpath `dirname $(_makefile_path)`)/modules/http2d

ifneq ($(HTTP2D_USE_SYSTEM),yes)
HTTP2D_LOCALBASE ?= ./lib
ifeq ($(HTTP2D_USE_SHARED),yes)
HTTP2D_LIB_NAME ?= libnghttp2.so
else
HTTP2D_USE_SHARED = no
HTTP2D_LIB_NAME ?= libnghttp2.a
endif
DEPS += lib/lib/$(HTTP2D_LIB_NAME)
else
HTTP2D_LOCALBASE ?= $(LOCALBASE)
endif

DEFS+=-I$(HTTP2D_LOCALBASE)/include
LIBS+=-L$(HTTP2D_LOCALBASE)/lib -lssl -lcrypto -levent -lnghttp2 -levent_openssl

include ../../Makefile.modules

ifneq ($(HTTP2D_USE_SYSTEM),yes)
lib/nghttp2/configure:
	$(Q)cd ./lib/nghttp2 && \
		autoreconf -i && \
		automake && \
		autoconf

lib/nghttp2/Makefile: lib/nghttp2/configure
	$(Q)cd ./lib/nghttp2 && \
		CFLAGS=-fPIC \
		./configure \
			--enable-lib-only \
			--enable-shared=$(HTTP2D_USE_SHARED) \
			--enable-silent-rules \
			--disable-app \
			--disable-failmalloc \
			--prefix=$(MOD_DIR)/lib

lib/lib/libnghttp2.a: lib/nghttp2/Makefile
	$(Q)$(MAKE) -C ./lib/nghttp2 install

clean:	http2d-wolfssl-lib

.PHONY: http2d-wolfssl-lib
http2d-wolfssl-lib:
	-@if [ -f ./lib/nghttp2/Makefile ]; then \
		$(MAKE) -C ./lib/nghttp2 clean; \
	fi;
	-@rm -rf ./lib/lib lib/share lib/include lib/bin \
		./lib/nghttp2/autom4te.cache \
		./lib/nghttp2/configure lib/nghttp2/Makefile
endif
