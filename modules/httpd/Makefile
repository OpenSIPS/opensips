# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=httpd.so
LIBS=

# set CROSS_COMPILE to true if you want to skip
# the autodetection
# CROSS_COMPILE=true

        # use standard know paths
	DEFS +=-DLIBMICROHTTPD
        DEFS +=-I$(LOCALBASE)/include
        LIBS +=-L$(LOCALBASE)/lib -L/usr/lib -lmicrohttpd

include ../../Makefile.modules

