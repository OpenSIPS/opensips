# $Id$
#
# carrierroute Makefile
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

auto_gen=
NAME=carrierroute.so

HAS_BUILDER = $(shell if which confuse-config >/dev/null 2>/dev/null;then echo YES; fi)

ifeq ($(HAS_BUILDER),YES)
	# use autodetection
	CONFUSEDEFS = $(shell confuse-config --cflags)
	CONFUSELIBS = $(shell confuse-config --libs)
else
	# use standard know paths
	CONFUSEDEFS=-I$(LOCALBASE)/include -I/usr/local/include -I/opt/include \
		-I/usr/sfw/include
	CONFUSELIBS=-L$(LOCALBASE)/lib -L/usr/local/lib -L/usr/sfw/lib \
		-L/opt/lib -lconfuse
endif

DEFS+=$(CONFUSEDEFS)
LIBS=$(CONFUSELIBS)

include ../../Makefile.modules
