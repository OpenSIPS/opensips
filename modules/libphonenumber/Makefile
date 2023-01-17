# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=libphonenumber.so

CXX?=g++
LD?=g++

LIBS=-L$(SYSBASE)/include/lib -L$(LOCALBASE)/lib libphonenumber.o -lphonenumber
DEFS+=-I$(SYSBASE)/include/phonenumbers -I$(LOCALBASE)/include/phonenumbers \
      -I$(LOCALBASE)/include

include ../../Makefile.modules

libphonenumber.o: libphonenumber.cpp libphonenumber.h
	@echo "Compiling $<"
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(C_DEFS) $(DEFS) -c $< -o $@

libphonenumber.so: libphonenumber.o

mod-clean:
	-@rm -f libphonenumber.o

clean clean-modules: mod-clean
