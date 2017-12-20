# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=freeswitch.so
LIBS+=-lpthread -lm

# Temporary import of the FreeSWITCH ESL library code until packages are out
ESLDIR = esl/src
_SRC=esl.c esl_buffer.c esl_config.c esl_event.c esl_json.c esl_threadmutex.c
extra_sources=$(patsubst %,$(ESLDIR)/%,$(_SRC))

include ../../Makefile.modules
