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
HAS_PCRECFG=$(shell if which pcre-config >/dev/null 2>/dev/null;then echo YES; fi)
endif

ifeq ($(HAS_PCRECFG),YES)

	# use autodetection
	DEFS += $(shell pcre-config --cflags)
	LIBS = $(shell pcre-config --libs)

else

	DEFS+=-I$(SYSBASE)/include/pcre -I$(LOCALBASE)/include/pcre \
			-I$(LOCALBASE)/include -I/opt/csw/include -I/usr/sfw/include \
			-I/usr/local/include
	LIBS=-I$(LOCALBASE)/lib -L/opt/csw/lib -L/usr/sfw/lib -L/usr/local/lib \
			-lpcre

endif



include ../../Makefile.modules
