# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

NAME=opentelemetry.so

CXX?=g++

# Make sure the C++ object participates in linking and overrides any defaults
# from the shared Makefile logic (which only considers .c sources).
override extra_objs+=opentelemetry.o

# Always use the system-installed OpenTelemetry C++ SDK (via pkg-config).
OTEL_CPP_CFLAGS:=$(shell pkg-config --cflags opentelemetry_trace opentelemetry_resources opentelemetry_common opentelemetry_api)
OTEL_CPP_LIBS:=$(shell pkg-config --libs opentelemetry_trace opentelemetry_resources opentelemetry_logs opentelemetry_metrics opentelemetry_common) -lopentelemetry_exporter_otlp_http
ifeq ($(strip $(OTEL_CPP_CFLAGS)$(OTEL_CPP_LIBS)),)
$(error OpenTelemetry C++ SDK not found via pkg-config (opentelemetry_*). Please install the system libraries.)
endif

DEFS+=-DHAVE_OPENTELEMETRY_CPP
CXXFLAGS+=-std=c++17 -fpermissive $(OTEL_CPP_CFLAGS)
LIBS+=$(OTEL_CPP_LIBS)

include ../../Makefile.modules

opentelemetry.o: opentelemetry.cpp
	$(Q)$(CXX) $(CXXFLAGS) $(DEFS) $(INCLUDE) -fPIC -c $< -o $@
