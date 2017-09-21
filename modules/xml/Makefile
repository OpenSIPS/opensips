# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=xml.so

ifeq ($(CROSS_COMPILE),)
LIBS=-lxml2
DEFS+=-I$(SYSBASE)/include/libxml2
else
DEFS+=-I$(SYSBASE)/include/libxml2 -I$(LOCALBASE)/include/libxml2 \
      -I$(LOCALBASE)/include
LIBS=-L$(SYSBASE)/include/lib  -L$(LOCALBASE)/lib -lxml2
endif

include ../../Makefile.modules
