# $Id: Makefile 5862 2009-07-15 10:06:05Z andreidragus $
#
# HTTP implementation for DB API.
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

auto_gen=
NAME=db_http.so

ifeq ($(CROSS_COMPILE),)
HAS_BUILDER = $(shell if which curl-config >/dev/null 2>/dev/null;then echo YES; fi)

ifeq ($(HAS_BUILDER),YES)
	# use autodetection
	DEFS += $(shell curl-config --cflags)
	LIBS = $(shell curl-config --libs)
else
	LIBS = -lcurl
endif
else
	# use standard know paths
	DEFS +=-I$(LOCALBASE)/include
	LIBS =-L$(LOCALBASE)/lib -lcurl
endif 

LIBS += -dl -Bsymbolic

include ../../Makefile.modules
