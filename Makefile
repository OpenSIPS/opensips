# Web3 Authentication Module Makefile

include ../../Makefile.defs
auto_gen=
NAME=web3_auth.so

# Include additional source files
EXTRA_SRCS=keccak256.c

DEFS+=-DKAMAILIO_MOD_INTERFACE

LIBS=-lcurl

include ../../Makefile.modules 