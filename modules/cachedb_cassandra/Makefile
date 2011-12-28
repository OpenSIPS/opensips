include ../../Makefile.defs

auto_gen=
NAME=cachedb_cassandra.so
CXX=g++
LD=g++
LIBS=cachedb_cassandra_dbase.o cassandra_constants.o cassandra_types.o Cassandra.o -L/usr/local/lib -lthrift
CXXFLAGS=$(CFLAGS:-Wno-deprecated option=)
# suppress a TON of warnings
CXXFLAGS+= -Wno-write-strings -Wno-deprecated -Wno-unused-function -Wno-sign-compare -Wno-strict-aliasing

include ../../Makefile.modules

cassandra_constants.o: cassandra_constants.cpp cassandra_constants.h
	@echo "Compiling $<"
	$(Q)$(CXX) $(CXXFLAGS) -I/usr/local/include/thrift -c $< -o $@

cassandra_types.o: cassandra_types.cpp cassandra_types.h
	@echo "Compiling $<"
	$(Q)$(CXX) $(CXXFLAGS) -I/usr/local/include/thrift -c $< -o $@

Cassandra.o: Cassandra.cpp Cassandra.h
	@echo "Compiling $<"
	$(Q)$(CXX) $(CXXFLAGS) -I/usr/local/include/thrift -c $< -o $@

cachedb_cassandra_dbase.o: cachedb_cassandra_dbase.cpp cachedb_cassandra_lib.h cachedb_cassandra_dbase.h
	@echo "Compiling $<"
	$(Q)$(CXX) $(CXXFLAGS) $(DEFS) -I/usr/local/include/thrift -c $< -o $@

cachedb_cassandra.so: cachedb_cassandra_dbase.o cassandra_constants.o cassandra_types.o Cassandra.o
