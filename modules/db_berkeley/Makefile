# $Id$
#
# example module makefile
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

# extra debug messages
# -DBDB_EXTRA_DEBUG is optional


include ../../Makefile.defs 
auto_gen=
NAME=db_berkeley.so

DEFS +=-I$(LOCALBASE)/include -I$(LOCALBASE)/BerkeleyDB.4.6/include \
	-I$(SYSBASE)/include -I$(LOCALBASE)/include/db46 

IS_BSD= $(shell echo "$(OS)" | sed -e 's/^.*bsd/yes/i' )
ifeq ($(IS_BSD), yes)
	DB_LIB=ldb-4.6
else
	DB_LIB=ldb
endif

LIBS=-L$(LOCALBASE)/lib -L$(SYSBASE)/lib -L$(LOCALBASE)/BerkeleyDB.4.6/lib \
		-$(DB_LIB)

include ../../Makefile.modules
