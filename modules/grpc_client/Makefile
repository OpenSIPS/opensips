# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

NAME=grpc_client.so
CXX?=g++

override extra_objs+=grpc_client.o

GRPC_MIN_VERSION:=1.40.0
GRPC_CPP_CFLAGS:=$(shell pkg-config --cflags grpc++)
GRPC_CPP_LIBS:=$(shell pkg-config --libs grpc++)
ifeq ($(strip $(GRPC_CPP_LIBS)),)
$(error gRPC C++ development files not found via pkg-config grpc++)
endif
ifeq ($(shell pkg-config --atleast-version=$(GRPC_MIN_VERSION) grpc++ && echo yes),)
$(error grpc++ >= $(GRPC_MIN_VERSION) is required for GenericStub callback unary calls)
endif

CXXFLAGS+=-std=c++17 -fpermissive \
	-Wno-register \
	-Wno-write-strings \
	-Wno-pointer-arith \
	$(GRPC_CPP_CFLAGS)
LIBS+=$(GRPC_CPP_LIBS)

include ../../Makefile.modules

grpc_client.o: grpc_client.cpp
	$(Q)$(CXX) $(CXXFLAGS) $(DEFS) -DMOD_NAME='$(MOD_NAME)' $(INCLUDE) $(DEBUGSYM) -fPIC -c $< -o $@

clean: clean-grpc-client

.PHONY: clean-grpc-client
clean-grpc-client:
	-@rm -f grpc_client.o
