# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=event_kafka.so

ifeq ($(CROSS_COMPILE),)
KAFKA_BUILDER = $(shell \
	if pkg-config --exists rdkafka; then \
		echo 'pkg-config rdkafka'; \
	fi)

ifneq ($(KAFKA_BUILDER),)
	DEFS += $(shell $(KAFKA_BUILDER) --cflags)
	LIBS += $(shell $(KAFKA_BUILDER) --libs)
endif
else
	DEFS+=-I$(LOCALBASE)/include
	LIBS=-L$(LOCALBASE)/lib -lrdkafka
endif

include ../../Makefile.modules

