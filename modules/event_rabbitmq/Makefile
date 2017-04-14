# $Id: Makefile 5901 2009-07-21 07:45:05Z bogdan_iancu $
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=event_rabbitmq.so

ifeq ($(CROSS_COMPILE),)
RABBITMQ_BUILDER = $(shell \
	if pkg-config --exists librabbitmq; then \
		echo 'pkg-config librabbitmq'; \
	fi)

ifneq ($(RABBITMQ_BUILDER),)
	DEFS += $(shell $(RABBITMQ_BUILDER) --cflags)
	LIBS += $(shell $(RABBITMQ_BUILDER) --libs)
endif
else
	DEFS+=-I$(LOCALBASE)/include
	LIBS=-L$(LOCALBASE)/lib -lrabbitmq
endif

include ../../Makefile.modules

