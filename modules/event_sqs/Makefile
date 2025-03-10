#
# Example module
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs

misclibs=sqs_lib.o
NAME=event_sqs.so

LIBS=-laws-cpp-sdk-sqs -laws-cpp-sdk-core -lstdc++

include ../../Makefile.modules

sqs_lib.o: sqs_lib.cpp
	$(Q)g++ -c -fPIC $< -o $@

clean: clean-sqs

.PHONY: clean-sqs
clean-sqs:
	-@rm -f sqs_lib.o