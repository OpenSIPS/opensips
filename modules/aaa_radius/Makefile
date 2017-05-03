#
# radius module makefile
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=aaa_radius.so

# Find the radius library we shall use
#
ifeq ($(RADIUSCLIENT),)
RADIUSCLIENT=$(shell if [ -n "`ldconfig -p | grep radcli`" ]; then echo "RADCLI"; \
	elif [ -n "`ldconfig -p | grep freeradius`" ]; then echo "FREERADIUS"; \
	elif [ -n "`ldconfig -p | grep radiusclient-ng`" ];then echo "RADIUSCLIENT"; fi)
endif


ifneq ($(RADIUSCLIENT), RADCLI)
ifneq ($(RADIUSCLIENT), FREERADIUS)
ifeq ($(RADIUSCLIENT), RADIUSCLIENT)
	DEFS+= -DRADIUSCLIENT
	RADIUS_LIB=-lradiusclient-ng
	RADIUS_PACKET=libradiusclient-ng-dev
endif
else
	DEFS+= -DFREERADIUS
	RADIUS_LIB=-lfreeradius-client
	RADIUS_PACKET=libfreeradius-client2
endif
else
	DEFS+= -DRADCLI
	RADIUS_LIB=-lradcli
	RADIUS_PACKET=libradcli
endif

ifeq ($(CROSS_COMPILE),)
	BUILDER=$(shell if pkg-config --exists $(RADIUS_PACKET); then \
		echo "pkg-config $(RADIUS_PACKET)"; \
	fi)
else
	DEFS+=-I$(LOCALBASE)/include
	LIBS=-L$(LOCALBASE)/lib $(RADIUS_LIB)
endif

ifneq ($(BUILDER),)
	DEFS+= $(shell $(BULDER) --cflags)
	LIBS+= $(shell $(BULDER) --libs)
else
ifeq ($(CROSS_COMPILE),)
	## we didn't find the packet with pkg-config
	## last chance try it without knowing lib path
	LIBS+= $(RADIUS_LIB)
endif
endif

include ../../Makefile.modules
