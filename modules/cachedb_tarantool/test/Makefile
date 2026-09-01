CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -I.. -I../..
LDFLAGS ?= -lpthread

TESTS = test_iproto_msgpuck test_url_parser

all: $(TESTS)

test_iproto_msgpuck: test_iproto_msgpuck.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

test_url_parser: test_url_parser.c ../cachedb_tarantool_dbase.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

test: all
	@echo "Running cachedb_tarantool unit tests..."
	@./test_iproto_msgpuck
	@./test_url_parser
	@echo "All unit tests completed successfully."

clean:
	rm -f $(TESTS) *.o
