# $Id: Makefile 806 2006-04-14 11:00:10Z bogdan_iancu $
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=b2b_logic.so
LIBS= 

DEFS+=-I$(SYSBASE)/include/libxml2 -I$(LOCALBASE)/include/libxml2 \
      -I$(LOCALBASE)/include
LIBS=-L$(SYSBASE)/include/lib  -L$(LOCALBASE)/lib -lxml2

include ../../Makefile.modules
