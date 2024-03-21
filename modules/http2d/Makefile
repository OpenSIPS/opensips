# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=http2d.so

#DEFS +=-I$(LOCALBASE)/include
LIBS +=-L$(LOCALBASE)/lib -lssl -lcrypto -levent -lnghttp2 -levent_openssl

include ../../Makefile.modules

