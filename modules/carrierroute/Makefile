# $Id$
#
# carrierroute Makefile
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=carrierroute.so

ifeq ($(CROSS_COMPILE),)
CONFUSE_BUILDER = $(shell \
	if which confuse-config >/dev/null 2>/dev/null;then \
		echo 'confuse-config'; \
	elif pkg-config --exists libconfuse; then \
		echo 'pkg-config libconfuse'; \
	fi)
endif

ifeq ($(CONFUSE_BUILDER),)
	DEFS += -I$(LOCALBASE)/include
	LIBS += -L$(LOCALBASE)/lib -lconfuse
else
	DEFS += $(shell $(CONFUSE_BUILDER) --cflags)
	LIBS += $(shell $(CONFUSE_BUILDER) --libs)
endif

include ../../Makefile.modules
