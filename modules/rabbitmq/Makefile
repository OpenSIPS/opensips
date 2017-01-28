#
# Provides integration with a RabbitMQ Server
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=rabbitmq.so

ifeq ($(CROSS_COMPILE),)
RABBITMQ_BUILDER = $(shell \
	if pkg-config --exists librabbitmq; then \
		echo 'pkg-config librabbitmq'; \
	fi)
endif

ifeq ($(RABBITMQ_BUILDER),)
	DEFS+=-I$(LOCALBASE)/include
	LIBS=-L$(LOCALBASE)/lib -lrabbitmq
else
	DEFS += $(shell $(RABBITMQ_BUILDER) --cflags)
	LIBS += $(shell $(RABBITMQ_BUILDER) --libs)
endif

# make sure travis does not fail this module for older RabbitMQ versions
ifeq ($(CC_NAME),gcc)
DEFS += -Wno-error=cpp
else ifeq ($(CC_NAME),clang)
DEFS += -Wno-\#warnings
#else
DEFS += -Wno-error
endif

include ../../Makefile.modules

