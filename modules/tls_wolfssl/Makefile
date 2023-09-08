include ../../Makefile.defs
auto_gen=
NAME=tls_wolfssl.so

LIBS=-L./lib/lib/ -lwolfssl -lm
DEFS+=-I./lib/include/
DEPS+=lib/lib/libwolfssl.a

_makefile_path := $(lastword $(MAKEFILE_LIST))
MOD_DIR ?= $(shell realpath `dirname $(_makefile_path)`)/modules/tls_wolfssl

include ../../Makefile.modules

lib/wolfssl/configure:
	$(Q)cd ./lib/wolfssl && ./autogen.sh

lib/wolfssl/Makefile: lib/wolfssl/configure
	$(Q)cd ./lib/wolfssl && \
		env -u DEFS -u CFLAGS -u LDFLAGS -u LIBS ./configure \
		--enable-all --disable-fpecc --disable-examples -disable-aligndata \
		--enable-writedup --enable-tlsv10 --disable-shared --enable-static \
		--disable-jni --disable-crl-monitor \
		--prefix=$(MOD_DIR)/lib \
		--exec-prefix=$(MOD_DIR)/lib C_EXTRA_FLAGS="-fPIC" CFLAGS="-DWOLFSSL_STATIC_RSA"; \

lib/lib/libwolfssl.a: lib/wolfssl/Makefile lib/wolfssl/src/internal.c
	$(Q)$(MAKE) -C ./lib/wolfssl install

lib/wolfssl/src/internal.c: lib/patches/wolfssl-internal-memleak-fix.patched

lib/patches/wolfssl-internal-memleak-fix.patched: lib/patches/wolfssl-internal-memleak-fix.patch
	 $(Q)patch -sNR --dry-run lib/wolfssl/src/internal.c $< || \
		 $(Q)patch -N lib/wolfssl/src/internal.c $< && cp $< $@

clean:	clean-wolfssl-lib

.PHONY: clean-wolfssl-lib
clean-wolfssl-lib:
	@if [ -f ./lib/wolfssl/Makefile ]; then \
		$(MAKE) -C ./lib/wolfssl clean; \
	fi;
	@rm -rf ./lib/bin ./lib/include ./lib/lib ./lib/share \
	./lib/wolfssl/Makefile ./lib/wolfssl/configure \
	lib/patches/wolfssl-internal-memleak-fix.patched
