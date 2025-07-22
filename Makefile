# Web3 Authentication Extension Module Makefile

include ../../Makefile.defs
auto_gen=
NAME=web3_auth_ext.so

# Include additional source files
EXTRA_SRCS=keccak256.c

DEFS+=-DKAMAILIO_MOD_INTERFACE

LIBS=-lcurl

include ../../Makefile.modules 