# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=uuid.so

ifeq ($(CROSS_COMPILE),)
LIBS=-luuid
DEFS+=-I$(SYSBASE)/include/uuid
else
DEFS+=-I$(SYSBASE)/include/uuid -I$(LOCALBASE)/include/uuid \
      -I$(LOCALBASE)/include
LIBS=-L$(SYSBASE)/include/lib  -L$(LOCALBASE)/lib -luuid
endif

include ../../Makefile.modules
