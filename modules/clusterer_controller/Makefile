# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME= clusterer_controller.so

LIBS += -L../tls_wolfssl/lib/lib/ -lwolfssl -lm
DEFS += -I../tls_wolfssl/lib/include/
DEPS += ../tls_wolfssl/lib/lib/libwolfssl.a

# Optional stronger crypto suite: if libsodium (dev) is detected on the build
# host, compile with XChaCha20-Poly1305 + Argon2id instead of AES-256-GCM +
# scrypt.  Distro static libs are usually non-PIC (can't link into a .so), so
# we link libsodium dynamically — target hosts then need the libsodium runtime
# package (e.g. `apt install libsodium23`).  All nodes in a cluster must be
# built the same way (the wire formats are not interoperable).
SODIUM_EXISTS := $(shell pkg-config --exists libsodium 2>/dev/null && echo yes)
ifeq ($(SODIUM_EXISTS),yes)
  DEFS += -DCC_HAVE_SODIUM $(shell pkg-config --cflags libsodium)
  LIBS += $(shell pkg-config --libs libsodium)
  $(info clusterer_controller: libsodium found -> XChaCha20-Poly1305 + Argon2id)
else
  $(info clusterer_controller: libsodium not found -> AES-256-GCM + scrypt)
endif

include ../../Makefile.modules

../tls_wolfssl/lib/lib/libwolfssl.a:
	$(MAKE) -C ../tls_wolfssl lib/lib/libwolfssl.a
