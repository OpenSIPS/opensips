include ../../Makefile.defs
auto_gen=
NAME=tls_wolfssl.so

LIBS += -L./lib/lib/ -lwolfssl -lm
DEFS+=-I./lib/include/
DEPS+=lib/lib/libwolfssl.a

_makefile_path := $(lastword $(MAKEFILE_LIST))
MOD_DIR ?= $(shell realpath `dirname $(_makefile_path)`)/modules/tls_wolfssl

include ../../Makefile.modules

ifneq (,$(findstring -DWOLFSSL_DEBUG_MEMORY,$(DEFS)))
ifeq (,$(findstring -DDBG_MALLOC,$(DEFS)))
$(warning "Memory debugging not enabled - disabling wolfSSL memory debugging")
DEFS := $(filter-out -DWOLFSSL_DEBUG_MEMORY,$(DEFS))
else
WOLFSSL_EXTRA_CFLAGS := -DWOLFSSL_DEBUG_MEMORY
endif
endif

lib/wolfssl/configure:
	$(Q)cd ./lib/wolfssl && ./autogen.sh

lib/wolfssl/Makefile: lib/wolfssl/configure
	$(Q)cd ./lib/wolfssl && \
		env -u DEFS -u CFLAGS -u LDFLAGS -u LIBS ./configure \
		--enable-all --disable-fpecc -disable-aligndata --disable-examples \
		--enable-writedup --enable-tlsv10 --disable-shared --enable-static \
		--disable-jni --disable-crl-monitor \
		--prefix=$(MOD_DIR)/lib \
		--exec-prefix=$(MOD_DIR)/lib \
		C_EXTRA_FLAGS="-fPIC" \
		CFLAGS="-DWOLFSSL_STATIC_RSA -DOPENSSL_EXTRA $(WOLFSSL_EXTRA_CFLAGS)"

PATCHED_FILES = #lib/wolfssl/src/internal.c lib/wolfssl/src/ssl.c

lib/lib/libwolfssl.a: lib/wolfssl/Makefile $(PATCHED_FILES)
	$(Q)$(MAKE) -C ./lib/wolfssl install

#lib/wolfssl/src/internal.c: lib/patches/wolfssl-internal-memleak-fix.patched
#
#lib/patches/wolfssl-internal-memleak-fix.patched: lib/patches/wolfssl-internal-memleak-fix.diff
#	 $(Q)patch -sNR -p1 -d lib/wolfssl --dry-run < $< || patch -N -p1 -d lib/wolfssl  < $< && cp $< $@
#
clean:	clean-wolfssl-lib

.PHONY: clean-wolfssl-lib
clean-wolfssl-lib:
	-@if [ -f ./lib/wolfssl/Makefile ]; then \
		$(MAKE) -C ./lib/wolfssl clean; \
	fi;
#	-@patch -stNR -p1 -d lib/wolfssl < lib/patches/wolfssl-internal-memleak-fix.diff
	-@rm -rf ./lib/bin ./lib/include ./lib/lib ./lib/share \
	./lib/wolfssl/Makefile ./lib/wolfssl/configure \

#	lib/patches/wolfssl-internal-memleak-fix.patched
