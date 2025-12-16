# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

NAME=opentelemetry.so

CXX?=g++

# Make sure the C++ object participates in linking and overrides any defaults
# from the shared Makefile logic (which only considers .c sources).
override extra_objs+=opentelemetry.o

# Set WITH_OTEL_CPP=1 to force using a locally provided SDK rooted at
# $(OTEL_CPP_ROOT). By default we try to pick up a system installation via
# pkg-config (opentelemetry_trace, _resources, _common, _api).
WITH_OTEL_CPP?=0
OTEL_CPP_ROOT?=$(CURDIR)/../../../opentelemetry_cpplib
OTEL_CPP_CFLAGS?=
OTEL_CPP_LIBS?=

ifeq ($(WITH_OTEL_CPP),0)
ifneq ($(CROSS_COMPILE),)
else
ifneq ($(shell pkg-config --exists opentelemetry_trace opentelemetry_resources opentelemetry_common opentelemetry_api && echo yes),)
WITH_OTEL_CPP:=1
OTEL_CPP_CFLAGS+=$(shell pkg-config --cflags opentelemetry_trace opentelemetry_resources opentelemetry_common opentelemetry_api)
OTEL_CPP_LIBS+=$(shell pkg-config --libs opentelemetry_trace opentelemetry_resources opentelemetry_logs opentelemetry_metrics opentelemetry_common)
OTEL_CPP_LIBS+=-lopentelemetry_exporter_otlp_http
endif
endif
endif

ifeq ($(WITH_OTEL_CPP),1)
DEFS+=-DHAVE_OPENTELEMETRY_CPP
CXXFLAGS+=-std=c++17 -fpermissive
ifeq ($(strip $(OTEL_CPP_CFLAGS)),)
OTEL_CPP_CFLAGS=-I$(OTEL_CPP_ROOT)/api/include -I$(OTEL_CPP_ROOT)/sdk/include \
	-I$(OTEL_CPP_ROOT)/exporters/include -I$(OTEL_CPP_ROOT)/resource_detectors/include
endif
CXXFLAGS+=$(OTEL_CPP_CFLAGS)
LIBS+=$(OTEL_CPP_LIBS)
endif

include ../../Makefile.modules

opentelemetry.o: opentelemetry.cpp
	$(Q)$(CXX) $(CXXFLAGS) $(DEFS) $(INCLUDE) -fPIC -c $< -o $@
