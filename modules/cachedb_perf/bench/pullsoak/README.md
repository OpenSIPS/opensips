# Cross-node pull soak

Unlike the rest of `bench/`, this is **not a model** — it drives two real
OpenSIPS instances with the real module, over the real clusterer transport,
and asserts on behaviour rather than measuring a number.

```bash
sh rig.sh          # two nodes on loopback, 8 workers each, pull enabled
python3 soak.py    # 12 concurrent threads; prints PASS/FAIL per invariant
```

## Why it exists

Three defects in the pull path were found by *reading* the code, after the
sequential tests had passed 32/32 both before and after the fix:

| defect | why the sequential tests were blind to it |
|---|---|
| the pull lock was held across the table write | no two pulls ever overlapped, so nothing contended |
| negative replies were not deduped by sender | one peer, one reply — a second could not arrive |
| the pull counters were non-atomic | one writer at a time loses nothing |

All three need *concurrency* to show themselves. This soak supplies it: 8
threads pulling, 2 asking for keys that exist nowhere, and 2 rewriting the
same keys the others are pulling — so slots are contended, replies
interleave, and writes race reads on the same buckets.

## What each assertion is actually watching for

| assertion | the regression it catches |
|---|---|
| no thread hung or errored | a lock-ordering deadlock, or a stall from holding a lock across I/O |
| no reply matched to the wrong request | correlation broken — the value carries its own key's index, so a cross-matched reply is a number that does not belong |
| no round came back empty | a false cluster-wide "absent" for keys that demonstrably exist — what a missing per-sender dedupe produces |
| keys that exist nowhere are never invented | the negative path answering positively |
| `stored <= received <= requested` | lost counter updates |
| `pulls_in_flight` back to 0 | slots taken and never released, which ends as silent loss of read repair |
| no crash, no slot exhaustion | the obvious ones |

## Notes

The stored value is the key's own index, and the check is numeric. That is
not a stylistic choice: a quoted string is expanded only in a *function
argument*, never in an assignment or a comparison, so there is no way to
build an expected string in the script and compare against it. Two earlier
attempts to do so reported every value as wrong.

Header values arrive as strings — the loop bounds are cast with `{s.int}` or
the counter never increments and the loop runs to `max_while_loops`.
