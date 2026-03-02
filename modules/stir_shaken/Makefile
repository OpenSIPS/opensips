#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

auto_gen=
NAME=stir_shaken.so

ifneq ($(STIR_SHAKEN_OPENSSL),)
USE_ONLY_CRYPTO=true
include ../../Makefile.openssl
else
# Prefer system wolfSSL. If unavailable, fallback to the local tls_wolfssl
# include/lib paths under LOCALBASE.
ifeq ($(CROSS_COMPILE),)
SS_WOLFSSL_BUILDER := $(shell \
	if pkg-config --exists wolfssl; then \
		echo 'pkg-config wolfssl'; \
	fi)
endif

ifneq ($(SS_WOLFSSL_BUILDER),)
	DEFS += $(shell $(SS_WOLFSSL_BUILDER) --cflags) -DOPENSSL_EXTRA
	LIBS += $(shell $(SS_WOLFSSL_BUILDER) --libs) -lm
else
	DEFS += -I$(LOCALBASE)/include -I$(LOCALBASE)/ssl/include -DOPENSSL_EXTRA
	LIBS += -L$(LOCALBASE)/lib -L$(LOCALBASE)/ssl/lib \
		-L$(LOCALBASE)/lib64 -L$(LOCALBASE)/ssl/lib64 \
		-lwolfssl -lm
endif
endif

include ../../Makefile.modules
