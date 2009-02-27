# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=regex.so

# set CROSS_COMPILE to true if you want to skip
# the autodetection
# CROSS_COMPILE=true

ifeq ($(CROSS_COMPILE),)
PCRECFG=$(shell which pcre-config)
endif

ifneq ($(PCRECFG),)

	# use autodetection
	DEFS += $(shell $(PCRECFG) --cflags)
	LIBS = $(shell $(PCRECFG) --libs)

else

	DEFS+=-I/usr/include -I/usr/sfw/include -I/usr/local/include -I/opt/csw/include -I$(LOCALBASE)/include
	LIBS=-I/usr/lib -I/usr/sfw/lib -I/usr/local/lib -I/opt/csw/lib -I$(LOCALBASE)/lib -lpcre

endif

include ../../Makefile.modules
