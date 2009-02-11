# $Id$
#
# example module makefile
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=identity.so

DEFS+= -I$(LOCALBASE)/ssl/include -I$(LOCALBASE)/include -I/usr/sfw/include -I/usr/local/ssl/include
LIBS= -L$(LOCALBASE)/lib -L$(LOCALBASE)/ssl/lib -L/usr/sfw/lib -L/usr/local/ssl/lib -lssl  -lcrypto

include ../../Makefile.modules
