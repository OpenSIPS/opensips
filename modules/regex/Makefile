# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=regex.so

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

	DEFS+=-I/usr/include -I/usr/sfw/include -I/usr/local/include -I/opt/csw/include -I$(LOCALBASE)/include
	LIBS=-I/usr/lib -I/usr/sfw/lib -I/usr/local/lib -I/opt/csw/lib -I$(LOCALBASE)/lib -lpcre

endif

include ../../Makefile.modules
