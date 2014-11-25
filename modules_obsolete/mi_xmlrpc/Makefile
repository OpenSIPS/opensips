# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=mi_xmlrpc.so
LIBS=

NEW_VERSION_THRESHOLD_UP=10642         # 1.06.42
NEW_VERSION_THRESHOLD_DOWN=10310       # 1.03.10

OLD_VERSION_THRESHOLD_UP=910           # 0.09.10
OLD_VERSION_THRESHOLD_DOWN=901         # 0.09.10

XMLRPC_FORCE_CHARS_VERSION=11200

# set CROSS_COMPILE to true if you want to skip
# the autodetection
# CROSS_COMPILE=true

ifeq ($(CROSS_COMPILE),)
HAS_XMLRPC-C-CONFIG=$(shell if which xmlrpc-c-config >/dev/null 2>/dev/null;then echo YES; fi)
endif

ifeq ($(HAS_XMLRPC-C-CONFIG),YES)
	# get the version
	XMLRPC_VER=$(shell xmlrpc-c-config --version)
else
	# try new version
	XMLRPC_VER=1.03.10
endif


XMLRPC_VERSION=$(shell echo $(XMLRPC_VER) | sed  "s/\.\([0-9]\)\./.0\1./g" | sed  "s/\.\([0-9]\)\$$/.0\1/g" | tr -d "." | sed -e "s/^0*//" )


# check the versions
OLD=$(shell echo $(XMLRPC_VERSION) $(OLD_VERSION_THRESHOLD_UP) $(OLD_VERSION_THRESHOLD_DOWN) | awk '{ if (($$1 <= $$2) && ($$1 >= $$3)) print "yes"}' )
NEW=$(shell echo $(XMLRPC_VERSION) $(NEW_VERSION_THRESHOLD_UP) $(NEW_VERSION_THRESHOLD_DOWN) | awk '{ if (($$1 <= $$2) && ($$1 >= $$3)) print "yes"}' )

FORCE=$(shell echo $(XMLRPC_VERSION) $(XMLRPC_FORCE_CHARS_VERSION) | awk '{ if (($$1 >= $$2)) print "yes"}' ) 


# supported version ?
ifeq ($(OLD),yes)
	DEFS+=-DXMLRPC_OLD_VERSION
else
ifeq ($(NEW),yes)
	# we need filio.h for Solaris
	ifeq ($(OS),solaris)
		DEFS+=-DHAVE_SYS_FILIO_H
	endif
else
$(warning			You are using an unsupported libxmlrpc-c3 \
					 version  ($(XMLRPC_VER)), compile at your own risk!)
endif
endif

ifeq ($(HAS_XMLRPC-C-CONFIG),YES)
	# use autodetection
	MY_DEFS=$(shell xmlrpc-c-config abyss-server --cflags)
	MY_LIBS=$(shell xmlrpc-c-config abyss-server --libs)
else
	# use standard know paths
	MY_DEFS=-I$(LOCALBASE)/include -I$(LOCALBASE)/include/xmlrpc-c \
		-I$(SYSBASE)/include/xmlrpc-c -D_UNIX
	MY_LIBS=-L$(SYSBASE)/lib  -L$(LOCALBASE)/lib -lxmlrpc -lxmlrpc_xmlparse \
		-lxmlrpc_xmltok -lxmlrpc_abyss -lxmlrpc_abyss_server \
		-lxmlrpc_client -lwwwinit -lwwwstream -lwwwxml \
		-lwwwapp -lwwwcache -lwwwcore -lwwwdir -lwwwfile \
		-lwwwftp -lwwwgopher -lwwwhtml -lwwwhttp \
		-lwwwmime -lwwwmux -lwwwnews -lwwwtelnet \
		-lwwwtrans -lwwwzip
endif

ifeq ($(NEW),yes)
	# remove the abyss library - we already have
	# the code in the module
	MY_DEFS+=-D_UNIX
	MY_LIBS:=$(filter-out %xmlrpc_abyss %xmlrpc_server_abyss %pthread, $(MY_LIBS))
else
	# remove from compiling the code we have in the
	# module for abyss server
	exclude_files=$(wildcard abyss_*.c)
endif

ifeq ($(FORCE),yes)
	MY_DEFS+=-DXMLRPC_HAS_FORCE_CHARS
endif



DEFS+=$(MY_DEFS)
LIBS=$(MY_LIBS)


include ../../Makefile.modules

