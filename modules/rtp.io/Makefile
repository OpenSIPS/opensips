# rtp.io module makefile

include ../../Makefile.defs

auto_gen=
NAME=rtp.io.so

DEFS+=-I$(LOCALBASE)/include
LIBS += -Wl,--whole-archive $(LOCALBASE)/lib/librtpproxy.a -Wl,--no-whole-archive \
  -lm -lssl -lcrypto `pkg-config --libs --static libsrtp2`

include ../../Makefile.modules
