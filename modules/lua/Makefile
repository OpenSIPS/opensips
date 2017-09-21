# $Id: Makefile,v 1.12 2009/01/20 03:00:05 folays Exp $
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=lua.so

MYSQLCFG=$(shell which mysql_config)
LIB_LUA = $(shell pkg-config --libs lua5.1 2> /dev/null) $(shell pkg-config --libs lua-5.1 2> /dev/null) $(shell pkg-config --libs lua 2>/dev/null)
FLAGS_LUA = $(shell pkg-config --cflags lua5.1 2> /dev/null) $(shell pkg-config --cflags lua-5.1 2> /dev/null) $(shell pkg-config --cflags lua 2>/dev/null)
ifeq (,$(findstring -l,$(LIB_LUA)))
LIB_LUA = -llua
endif
DEFS += $(shell $(MYSQLCFG) --include | sed 's/\(-I.*\)\/mysql/\1/g' ) -I/usr/include/lua5.1/ $(FLAGS_LUA)
LIBS += $(shell $(MYSQLCFG) --libs) -lmemcached $(LIB_LUA)

ifneq ($(CROSS_COMPILE),)
DEFS += -I$(LOCALBASE)/include/memcached
LIBS = -L$(LOCALBASE)/lib $(LIBS)
endif

include ../../Makefile.modules

install_module_custom:
	echo "installing Lua OpenSIPS packages ..."
