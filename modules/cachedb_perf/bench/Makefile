# cachedb_perf design benchmarks - standalone, no OpenSIPS build needed.
# Each program embeds core_hash() verbatim from ../../../hash_func.h.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall
PROGS    = hashtest lookup structs worker expire2 concur wbuf queue warmup hugetlb hugetlb2

all: $(PROGS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

concur wbuf queue: %: %.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

run: all
	@echo "=== 1. hash distribution: is core_hash to blame? ==="; ./hashtest
	@echo; echo "=== 2. lookup cost vs load factor ==="; ./lookup
	@echo; echo "=== 3. index structure shootout ==="; ./structs
	@echo; echo "=== 4. deferred sorting / worker ==="; ./worker
	@echo; echo "=== 5. expiry strategies ==="; ./expire2
	@echo; echo "=== 6. concurrent read path (threads) ==="; ./concur
	@echo; echo "=== 7. write staging buffer ==="; ./wbuf
	@echo; echo "=== 8. queued (producer/consumer) writes ==="; ./queue
	@echo; echo "=== 9. first-touch cost ==="; ./warmup
	@echo; echo "=== 10. huge pages (needs: sysctl -w vm.nr_hugepages=160) ==="; ./hugetlb
	@echo; echo "=== 11. modern routes: base/collapse/madvise/hugetlb/huge1g ==="; ./hugetlb2 base

clean:
	rm -f $(PROGS)

.PHONY: all run clean
