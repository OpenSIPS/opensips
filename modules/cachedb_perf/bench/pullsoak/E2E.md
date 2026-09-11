# Blocking versus suspending, end to end

Two nodes, four workers each, and a burst of requests to the node that
does **not** have the state - so every one of them costs a round trip to
the other node.  The same workload runs two ways:

```bash
MODE=sync  sh e2e_rig.sh && python3 e2e_burst.py sync
MODE=async sh e2e_rig.sh && python3 e2e_burst.py async
```

`sync` sets `pull_on_miss` and calls `topology_hiding_match()`, so the
lookup blocks its worker until the cluster answers.  `async` clears
`pull_on_miss` and calls `async(topology_hiding_match(), resume)`, so the
transaction suspends and the worker goes back to work.  Both must be
configured, or the comparison is meaningless: with `pull_on_miss` set,
the ordinary lookup pulls before the asynchronous path ever sees a miss.

## What it shows

On an idle network, **nothing**: 120 requests took 0.044 s blocking and
0.046 s suspending.  A pull takes well under a millisecond there, and
holding a worker for that long costs nothing measurable.  This is worth
knowing - it is why `pull_on_miss` is not dangerous on a quiet LAN, and
why the asynchronous path is not a general speed-up.

Add 100 ms to the peer's replies (`tc qdisc add dev y1 root netem delay
100ms` inside the peer's namespace) and the difference is the whole
point:

| | 60 requests, 4 workers, peer 100 ms away |
|---|---|
| blocking | 1.52 s |
| suspending | 0.31 s |

The blocking figure is arithmetic, not noise: sixty round trips of a
tenth of a second, four at a time, is a second and a half.  The other
path finishes in about one round trip however many requests there are,
because none of them is holding anything while it waits.

## Traps

The key must be exactly `TH_KEY_LEN` characters or the store rejects it
by length, which looks exactly like a lookup that found nothing - an
earlier version of this test generated keys of 15, 16 and 17 characters
and "failed" only for the ones that were not 16.

Clear both caches before each run.  A pull stores what it fetched, so a
second run measures local hits and reports a number that means nothing.
