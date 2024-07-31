#
# Example module
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

misclibs=dynamodb_lib.o
NAME=cachedb_dynamodb.so

LIBS=-laws-cpp-sdk-dynamodb -laws-cpp-sdk-core -lstdc++

include ../../Makefile.modules

dynamodb_lib.o: dynamodb_lib.cpp
	$(Q)g++ -c -fPIC $< -o $@

clean: clean-dynamodb

.PHONY: clean-dynamodb
clean-dynamodb:
	-@rm -f dynamodb_lib.o
