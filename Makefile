# Web3 Authentication Extension Module Makefile

include ../../Makefile.defs
auto_gen=
NAME=web3_auth_ext.so

DEFS+=-DKAMAILIO_MOD_INTERFACE

LIBS=-lcurl

include ../../Makefile.modules 