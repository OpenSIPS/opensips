# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME= clusterer_controller.so

# libsodium is a hard requirement: it provides the payload AEAD
# (XChaCha20-Poly1305), the bootstrap KDF (Argon2id), the Noise_NNpsk0 join
# handshake, and X25519 / HKDF-SHA256 / RNG.  It is linked dynamically (distro
# static libs are usually non-PIC), so target hosts need the libsodium runtime
# package (e.g. `apt install libsodium23`).
SODIUM_EXISTS := $(shell pkg-config --exists libsodium 2>/dev/null && echo yes)
ifeq ($(SODIUM_EXISTS),yes)
  DEFS += $(shell pkg-config --cflags libsodium)
  LIBS += $(shell pkg-config --libs libsodium)
  $(info clusterer_controller: libsodium found -> XChaCha20-Poly1305 + Argon2id + Noise_NNpsk0)
else
  $(error clusterer_controller requires libsodium (install libsodium-dev / libsodium-devel))
endif

include ../../Makefile.modules
