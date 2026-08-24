#!/usr/bin/env python3
"""TEST-ONLY: let the requester put an out-of-spec key on the wire.

A well-behaved node cannot produce the packet this test needs - its own
gate stops it - so the gate is relaxed here, and here only.  The slot copy
is still clamped to the production array size, so the SENDER stays sound
and the only thing under test is what the RECEIVER does with the key.
Nothing else is touched, and the file is restored from git afterwards.
"""
import re, sys

p = "/dn/wt-cp15/modules/cachedb_perf/cachedb_perf.c"
s = open(p).read()

old_gate = """	if (!pcache_pull_enabled(col) || key->len > PCACHE_PULL_MAX_KEY ||
	        col->col_name.len > 63)
		return -1;"""
new_gate = """	if (!pcache_pull_enabled(col) || key->len > 8192 ||
	        col->col_name.len > 63)
		return -1;   /* TEST BUILD: gate relaxed to reach the serve path */"""
assert old_gate in s, "sender gate not found"
s = s.replace(old_gate, new_gate, 1)

old_cp = """	memcpy(sl->key, key->s, key->len);
	sl->klen = key->len;"""
new_cp = """	{   /* TEST BUILD: the wire carries the full key, the slot only what fits */
		int cp = key->len > PCACHE_PULL_MAX_KEY ? PCACHE_PULL_MAX_KEY : key->len;
		memcpy(sl->key, key->s, cp);
		sl->klen = cp;
	}"""
assert old_cp in s, "slot copy not found"
s = s.replace(old_cp, new_cp, 1)

open(p, "w").write(s)
print("relaxed the sender gate (test build only)")
