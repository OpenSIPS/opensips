include ../../Makefile.defs
auto_gen=
NAME=tls_wolfssl.so

DEFS+=-DWOLFSSL_QT

ifeq ($(WOLFSSL_FIPS_ENABLED),)
	LIBS=-L./lib/lib/ -lwolfssl -lm
	DEFS+=-I./lib/include/
	DEPS+=lib/lib/libwolfssl.a

	_makefile_path := $(lastword $(MAKEFILE_LIST))
	MOD_DIR ?= $(shell realpath `dirname $(_makefile_path)`)/modules/tls_wolfssl
else
	ifeq ($(CROSS_COMPILE),)
		SSL_BUILDER=$(shell \
		if pkg-config --exists wolfssl; then \
			echo 'pkg-config wolfssl'; \
		fi)
	endif

	ifneq ($(SSL_BUILDER),)
		DEFS += $(shell $(SSL_BUILDER) --cflags)
		LIBS += $(shell $(SSL_BUILDER) --libs) -lm
	else
		DEFS += -I$(LOCALBASE)/include
		LIBS += -L$(LOCALBASE)/lib -lm
	endif
endif

include ../../Makefile.modules

lib/lib/libwolfssl.a:
ifeq ($(WOLFSSL_FIPS_ENABLED),)
	@cd ./lib/wolfssl; \
	if [ ! -f "configure" ]; then \
		./autogen.sh; \
	fi; \
	if [ ! -f "Makefile" ]; then \
		env -u DEFS -u CFLAGS -u LDFLAGS -u LIBS ./configure \
		--enable-all --disable-fpecc -disable-aligndata --disable-examples \
		--enable-writedup --enable-tlsv10 --disable-shared --enable-static \
		--disable-jni --disable-crl-monitor \
		--prefix=$(MOD_DIR)/lib \
		--exec-prefix=$(MOD_DIR)/lib C_EXTRA_FLAGS="-fPIC" CFLAGS="-DWOLFSSL_STATIC_RSA"; \
	fi;
	@$(MAKE) -C ./lib/wolfssl install
endif

clean:	clean-wolfssl-lib

.PHONY: clean-wolfssl-lib
clean-wolfssl-lib:
ifeq ($(WOLFSSL_FIPS_ENABLED),)
	@if [ -f ./lib/wolfssl/Makefile ]; then \
		$(MAKE) -C ./lib/wolfssl clean; \
	fi;
	@rm -rf ./lib/bin ./lib/include ./lib/lib ./lib/share \
	./lib/wolfssl/Makefile ./lib/wolfssl/configure
endif
