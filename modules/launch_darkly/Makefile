# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=launch_darkly.so

_makefile_path := $(lastword $(MAKEFILE_LIST))
MOD_DIR ?= $(shell realpath `dirname $(_makefile_path)`)/modules/launch_darkly

ifneq ($(LD_USE_SYSTEM),yes)
LD_LOCALBASE ?= ./lib
ifeq ($(LD_USE_SHARED),yes)
LD_LIB_NAME ?= libldserverapi.so
else
LD_USE_SHARED = no
LD_LIB_NAME ?= libldserverapi.a
endif
DEPS += lib/lib/$(LD_LIB_NAME)
else
LD_LOCALBASE ?= $(LOCALBASE)
endif

DEFS+=-I$(LD_LOCALBASE)/include
LIBS+=-L$(LD_LOCALBASE)/lib -l ldserverapi -l curl -l pthread -l m -l pcre

include ../../Makefile.modules

ifneq ($(LD_USE_SYSTEM),yes)
lib/build/Makefile:
	$(C)cmake \
		-DBUILD_SHARED_LIBS=$(LD_USE_SHARED) \
		-DBUILD_TESTING=Off \
		-DCMAKE_C_FLAGS=-fPIC \
		-DCMAKE_INSTALL_PREFIX=$(MOD_DIR)/lib \
		-S lib/c-server-sdk \
		-B lib/build

lib/lib/$(LD_LIB_NAME): lib/build/Makefile
	$(Q)$(MAKE) -C ./lib/build install

clean: clean-launch-darkly-lib

.PHONY: clean-launch-darkly-lib
clean-launch-darkly-lib:
	-@if [ -f lib/build/Makefile ]; then \
		$(MAKE) -C lib/build clean; \
	fi;
	-@rm -rf lib/build lib/lib
endif
