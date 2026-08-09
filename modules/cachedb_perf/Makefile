# cachedb_perf module
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=cachedb_perf.so

# The clusterer_controller pull transport is compiled only when that module is
# part of this build - the top-level Makefile exports CLUSTERER_CTRL_SUPPORT=1
# in that case (the clusterer module keys off the same hook).  Without it,
# pulls and syncs use the clusterer module's bin links only, and an explicit
# pull_transport=clctr warns and degrades to bin.
ifeq ($(CLUSTERER_CTRL_SUPPORT),1)
DEFS+= -DCLUSTERER_CTRL_SUPPORT
endif

include ../../Makefile.modules
