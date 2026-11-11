# clusterer_controller: measurements

Measured in November 2026 on the pushes of [PR #4074](https://github.com/OpenSIPS/opensips/pull/4074) of 11 November (f2d52f985e) and 12 November (7aa859f038), as each table says. The later changes - the locking of the broadcast receive path, the step-down of a master its members cannot hear, and the removal of the unused messaging channel - were not measured again.

One host (HP BL460c Gen8, 2 x E5-2690 v2, 40 threads), each node an OpenSIPS instance (`-a Q_MALLOC`) in its own network namespace on one bridge, netem on each node's link where noted.


## Forming a cluster

The first version of the module kept clusterer's own link layer for the controller's clusters: every node pings every other node each second, floods link-state changes and can relay messages through other nodes. 32 nodes started together on one virtual machine never formed. With joiners admitted a few at a time, 48 nodes formed in about two minutes, but at 64 the link layer flooded itself and the cluster did not form in any of three runs.

64 and 128 nodes started at once (`-m 64 -M 16`, 2 UDP workers). The first version's runs are from 10 November, same host and rig, with Q_MALLOC_DBG; this module's runs are from 7aa859f038, the one with 1% loss from f2d52f985e:

| Nodes | Version | Network (netem on each node's link) | Formed, runs | Time to form, s | Run length, s | TCP segments sent, all nodes, count |
|---|---|---|---|---|---|---|
| 64 | first version (clusterer's link layer), admission added | none | 0 of 3 | not formed in 380 / not formed in 380 / not formed in 380 | 395 / 396 / 402 | 78212114 / 78947828 / 68573435 |
| 64 | this module | none | 10 of 10 | 132 / 130 / 128 / 130 / 124 / 126 / 134 / 134 / 118 / 118 | 151 to 168 | 28833 to 30027 |
| 128 | this module | none | 3 of 3 | 281 / 268 / 268 | 324 / 311 / 311 | 146199 / 141988 / 143137 |
| 64 | first version (clusterer's link layer), admission added | 5 ms ±3 ms, 1% loss | 0 of 1 | not formed in 380 | 396 | 53430558 |
| 64 | this module | 5 ms ±3 ms, 1% loss | 1 of 1 | 189 | 223 | 34236 |


## Replicating dialogs and contacts

Full sharing over multicast or TCP (`mcast_broadcasts=1` / `0`): sipp sends 100 calls/s (3 s hold, record-routed) and 200 registrations/s, each a new contact, to each of 4 nodes for 60 s; cluster CPU is all OpenSIPS processes over a 40 s window, each arm run twice in ABBA order (`-m 512 -M 32`, 4 UDP and 4 TCP workers).

On these networks (f2d52f985e) every dialog and contact reached every node in every run:

| Nodes | Network (netem on each node's link) | Broadcasts by | Cluster CPU per run, cores | Per loaded node, cores | Per other node, cores | Cluster CPU vs TCP, % | Replicated to every node | Packets resent on request, count | Broadcasts lost, count |
|---|---|---|---|---|---|---|---|---|---|
| 8 | 0.2 ms ±0.1 ms, 0.01% loss | multicast | 3.78 / 3.81 | 0.47 | 0.48 | -23 | all | 99 / 155 | 0 |
| 8 | 0.2 ms ±0.1 ms, 0.01% loss | TCP | 5.02 / 4.84 | 0.69 | 0.54 |  | all | - | - |
| 8 | 1 ms ±0.5 ms, 0.1% loss | multicast | 3.66 / 3.77 | 0.45 | 0.48 | -12 | all | 1196 / 1261 | 0 |
| 8 | 1 ms ±0.5 ms, 0.1% loss | TCP | 4.21 / 4.20 | 0.60 | 0.45 |  | all | - | - |
| 8 | 5 ms ±3 ms, 1% loss | multicast | 3.57 / 3.59 | 0.44 | 0.46 | -3 | all | 16897 / 18449 | 0 |
| 8 | 5 ms ±3 ms, 1% loss | TCP | 3.70 / 3.71 | 0.54 | 0.39 |  | all | - | - |
| 16 | 0.2 ms ±0.1 ms, 0.01% loss | multicast | 11.59 / 11.65 | 0.67 | 0.74 | -19 | all | 290 / 167 | 0 |
| 16 | 0.2 ms ±0.1 ms, 0.01% loss | TCP | 14.27 / 14.57 | 1.20 | 0.80 |  | all | - | - |

The same load with 10% loss and with reordering (7aa859f038):

| Nodes | Network (netem on each node's link) | Broadcasts by | Cluster CPU per run, cores | Dialog creates received of expected, % | Contacts held per node, min..max of 48000 | Packets resent on request, count | Broadcasts lost, count |
|---|---|---|---|---|---|---|---|
| 8 | 1 ms ±0.5 ms, 10% loss | multicast | 2.84 / 2.81 | 100.0 / 100.0 | 48000..48000 / 48000..48000 | 132538 / 134800 | 0 / 0 |
| 8 | 1 ms ±0.5 ms, 10% loss | TCP | 2.87 / 2.86 | 85.5 / 85.3 | 38619..44961 / 40646..43607 | - | - |
| 8 | 1 ms, 3% sent early (reordered) | multicast | 3.80 / 3.81 | 100.0 / 100.0 | 48000..48000 / 48000..48000 | 0 / 0 | 0 / 0 |
| 8 | 1 ms, 3% sent early (reordered) | TCP | 4.96 / 4.86 | 100.0 / 100.0 | 48000..48000 / 48000..48000 | - | - |

At 10% loss each path crosses two lossy links, and TCP's own resending fell behind the replication: a sending node's queue on a BIN connection reached proto_bin's limit (`async_max_postponed_chunks`, 1024 by default), proto_bin then failed the send and marked the connection bad, and closing it discarded everything still queued on it. That is proto_bin's behaviour, which clusterer over TCP shares; the CPU of the two arms cannot be compared there, as the TCP runs replicated less. Under reordering neither arm lost anything or resent a packet, and multicast took 23% less cluster CPU than TCP.
