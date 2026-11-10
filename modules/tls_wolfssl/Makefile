include ../../Makefile.defs
auto_gen=
NAME=tls_wolfssl.so

LIBS += -L./lib/lib/ -lwolfssl -lm
DEFS+=-I./lib/include/
DEPS+=lib/lib/libwolfssl.a

_makefile_path := $(lastword $(MAKEFILE_LIST))
MOD_DIR ?= $(shell realpath `dirname $(_makefile_path)`)/modules/tls_wolfssl

WOLFSSL_FEATURES = \
	   --enable-opensslextra \
	   --enable-writedup \
	   --enable-tlsv10 \
	   --enable-tls13 \
	   --enable-sni \
	   --enable-session-ticket \
	   --enable-crl \
	   --enable-rsa \
	   --enable-ecc \
	   --enable-dh \
	   --enable-aes \
	   --enable-aesgcm \
	   --enable-sha \
	   --enable-sha256 \
	   --enable-sha384 \
	   --enable-sha512 \
	   --disable-crypttests \
	   --disable-examples \
	   --disable-jni \
	   --disable-dtls \
	   --disable-dtls13 \
	   --disable-quic \
	   --disable-ech \
	   --disable-wolfssh \
	   --disable-ssh \
	   --disable-smime \
	   --disable-pkcs7 \
	   --disable-pkcs11 \
	   --disable-srp \
	   --disable-ocsp \
	   --disable-ocspstapling \
	   --disable-ocspstapling2 \
	   --disable-ocsp-responder \
	   --disable-crl-monitor \
	   --disable-earlydata \
	   --disable-fpecc \
	   --disable-aligndata

WOLFSSL_FLAGS = \
	-DWOLFSSL_STATIC_RSA \
	-DOPENSSL_EXTRA \
	-DKEEP_OUR_CERT

include ../../Makefile.modules

lib/wolfssl/configure:
	$(Q)cd ./lib/wolfssl && ./autogen.sh

lib/wolfssl/Makefile: lib/wolfssl/configure
	$(Q)cd ./lib/wolfssl && \
		env -u DEFS -u CFLAGS -u LDFLAGS -u LIBS ./configure \
		--disable-shared --enable-static $(WOLFSSL_FEATURES) $(WOLFSSL_EXTRA_FEATURES) \
		--prefix=$(MOD_DIR)/lib \
		--exec-prefix=$(MOD_DIR)/lib \
		C_EXTRA_FLAGS="-fPIC" \
		CFLAGS="$(WOLFSSL_FLAGS) $(WOLFSSL_EXTRA_FLAGS)"

lib/lib/libwolfssl.a: lib/wolfssl/Makefile
	$(Q)$(MAKE) -C ./lib/wolfssl install

clean:	clean-wolfssl-lib

.PHONY: clean-wolfssl-lib
clean-wolfssl-lib:
	-@if [ -f ./lib/wolfssl/Makefile ]; then \
		$(MAKE) -C ./lib/wolfssl clean; \
	fi;
	-@rm -rf ./lib/bin ./lib/include ./lib/lib ./lib/share \
	./lib/wolfssl/Makefile ./lib/wolfssl/configure
