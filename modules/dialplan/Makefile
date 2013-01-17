# $Id$
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=dialplan.so

# set CROSS_COMPILE to true if you want to skip
# the autodetection
# CROSS_COMPILE=true

ifeq ($(CROSS_COMPILE),)
PCRE_BUILDER = $(shell \
	if which pcre-config >/dev/null 2>/dev/null; then \
		echo 'pcre-config'; \
	elif pkg-config --exists libcre; then \
		echo 'pkg-config libpcre'; \
	fi)
endif

ifeq ($(PCRE_BUILDER),)
	DEFS += -I$(SYSBASE)/include \
			-I$(LOCALBASE)/include
	LIBS += -L$(SYSBASE)/lib \
			-L$(LOCALBASE)/lib -lpcre
else
	DEFS += $(shell $(PCRE_BUILDER) --cflags)
	LIBS += $(shell $(PCRE_BUILDER) --libs)
endif

include ../../Makefile.modules
