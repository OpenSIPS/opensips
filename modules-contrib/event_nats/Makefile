# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

# External libnats dependency probe (sets NATS_FOUND if available).
include ../nats/Makefile.nats

ifeq ($(NATS_FOUND),)
$(info [skip] event_nats.so — libnats C client not detected (install libnats-dev or set LOCALBASE))
.PHONY: all clean install modules
all clean install modules: ; @true
else

auto_gen=
NAME=event_nats.so


include ../../Makefile.modules


endif
