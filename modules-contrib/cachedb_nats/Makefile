# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

# External libnats dependency probe (sets NATS_FOUND if available).
include ../nats/Makefile.nats

ifeq ($(NATS_FOUND),)
$(info [skip] cachedb_nats.so — libnats C client not detected (install libnats-dev or set LOCALBASE))
.PHONY: all clean install modules
all clean install modules: ; @true
else

auto_gen=
NAME=cachedb_nats.so


# EVI support for E_NATS_KV_CHANGE events (KV watcher -> OpenSIPS scripts)

LIBS += -lpthread

include ../../Makefile.modules


endif
