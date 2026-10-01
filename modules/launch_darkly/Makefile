# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=launch_darkly.so

_makefile_path := $(lastword $(MAKEFILE_LIST))
MOD_DIR ?= $(shell realpath `dirname $(_makefile_path)`)/modules/launch_darkly

ifneq ($(LD_USE_SYSTEM),yes)
LD_LOCALBASE ?= ./lib
LD_LIB_NAME ?= libldserverapi.a
DEPS += lib/lib/$(LD_LIB_NAME)
else
LD_LOCALBASE ?= $(LOCALBASE)
endif

DEFS+=-I$(LD_LOCALBASE)/include
# ldserverapi (built from LaunchDarkly's cpp-sdks, renamed to this legacy name)
# is a static archive built with a C++ toolchain (Boost.JSON/URL/Coroutine +
# OpenSSL, statically linked in) - -lstdc++ is required because this module
# (a .c file) links it in
LIBS+=-L$(LD_LOCALBASE)/lib -Wl,--start-group \
	-l ldserverapi \
	-l boost_json -l boost_url -l boost_coroutine -l boost_context -l boost_thread \
	-l ssl -l crypto \
	-Wl,--end-group -l pthread -l stdc++ -l m

include ../../Makefile.modules

ifneq ($(LD_USE_SYSTEM),yes)
lib/build/Makefile:
	$(C)cmake \
		-DBUILD_TESTING=Off \
		-DLD_BUILD_EXAMPLES=Off \
		-DLD_BUILD_CONTRACT_TESTS=Off \
		-DCMAKE_CXX_FLAGS=-fPIC \
		-DCMAKE_INSTALL_PREFIX=$(MOD_DIR)/lib \
		-S lib/cpp-sdks \
		-B lib/build

lib/lib/$(LD_LIB_NAME): lib/build/Makefile
	$(Q)$(MAKE) -C ./lib/build install
	$(Q)mv $(MOD_DIR)/lib/lib/liblaunchdarkly-cpp-server.a $(MOD_DIR)/lib/lib/$(LD_LIB_NAME)

clean: clean-launch-darkly-lib

.PHONY: clean-launch-darkly-lib
clean-launch-darkly-lib:
	-@if [ -f lib/build/Makefile ]; then \
		$(MAKE) -C lib/build clean; \
	fi;
	-@rm -rf lib/build lib/lib
endif
