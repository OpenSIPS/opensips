#
# radius module makefile
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=aaa_radius.so

# Comment the next two line and uncomment the following two if you want
# to enable Radius support
DEFS+= -I$(LOCALBASE)/include
LIBS=-L$(LOCALBASE)/lib $(RADIUS_LIB)

include ../../Makefile.modules
