# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=launch_darkly.so


DEFS+=-I$(LOCALBASE)/include
LIBS+=-L$(LOCALBASE)/lib -l ldserverapi -l curl -l pthread -l m -l pcre

include ../../Makefile.modules

