# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=db_redis.so

# hiredis client library
DEFS+=-I$(LOCALBASE)/include -I$(SYSBASE)/include
LIBS+=-L$(LOCALBASE)/lib -L$(SYSBASE)/lib -lhiredis

include ../../Makefile.modules
