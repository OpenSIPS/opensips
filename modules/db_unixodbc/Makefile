# $Id$
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=db_unixodbc.so

ifeq ($(CROSS_COMPILE),)
LIBS= -lodbc
else
# sql.h locations (freebsd,openbsd  solaris)
DEFS += -I$(LOCALBASE)/include -I$(LOCALBASE)/include/odbc

# libodbc locations on RH/Suse, Solaris /OpenBSD, FreeBSD
# (Debian does the right thing and puts it in /usr/lib)
LIBS= -L$(LOCALBASE)/lib -lodbc
endif

include ../../Makefile.modules
