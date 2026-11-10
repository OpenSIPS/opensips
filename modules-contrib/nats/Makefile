# WARNING: do not run this directly, it should be run by the master Makefile
#
# nats.so -- the NATS connection pool shared by the NATS modules
# (event_nats, cachedb_nats, cachedb_nats_fts, nats_consumer).  They bind
# its API with load_nats_api() (nats_api.h); one nats.so per OpenSIPS
# process holds the per-process connection state for all of them.

include ../../Makefile.defs

# External libnats dependency probe (sets NATS_FOUND if available).
include ./Makefile.nats

ifeq ($(NATS_FOUND),)
$(info [skip] nats.so — libnats C client not detected (install libnats-dev or set LOCALBASE))
.PHONY: all clean install modules
all clean install modules: ; @true
else

auto_gen=
NAME=nats.so
LIBS += -lpthread

include ../../Makefile.modules

endif
