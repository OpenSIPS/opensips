# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=clusterer_controller.so
#DEFS+= -DCLUSTERER_DBG
#DEFS+= -DCLUSTERER_EXTRA_BIN_DBG

# Linux only: the controller's timers are timerfds and its multicast socket is
# pinned to its interface with SO_BINDTODEVICE.
# libsodium is a hard requirement: it provides the payload AEAD
# (XChaCha20-Poly1305), the bootstrap KDF (Argon2id), the Noise_NNpsk0 join
# handshake, and X25519 / HKDF-SHA256 / RNG.  It is linked dynamically (distro
# static libs are usually non-PIC), so target hosts need the libsodium runtime
# package (e.g. `apt install libsodium23`).
# As for the tree's other contrib modules with an outside dependency, a host
# that cannot build the module skips it rather than fail the whole build.
ifneq ($(OS),linux)
  CL_CTR_SKIP := it builds on Linux only (timerfd, SO_BINDTODEVICE)
else
  ifeq ($(CROSS_COMPILE),)
  SODIUM_BUILDER := $(shell \
	if pkg-config --exists libsodium 2>/dev/null; then \
		echo 'pkg-config libsodium'; \
	fi)
  endif
  ifneq ($(SODIUM_BUILDER),)
    DEFS += $(shell $(SODIUM_BUILDER) --cflags)
    LIBS += $(shell $(SODIUM_BUILDER) --libs)
  else ifneq (,$(wildcard $(LOCALBASE)/include/sodium.h))
    DEFS += -I$(LOCALBASE)/include
    LIBS += -L$(LOCALBASE)/lib -lsodium
  else ifneq (,$(wildcard $(SYSBASE)/include/sodium.h))
    LIBS += -lsodium
  else
    CL_CTR_SKIP := libsodium not detected (install libsodium-dev / libsodium-devel or set LOCALBASE)
  endif
endif

ifneq ($(CL_CTR_SKIP),)
$(info [skip] clusterer_controller.so - $(CL_CTR_SKIP))
.PHONY: all clean install modules
all clean install modules: ; @true
.DEFAULT: ; @true
else

include ../../Makefile.modules

endif
