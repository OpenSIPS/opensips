---
title: "drain Module"
description: "Gracefully remove an OpenSIPS node from service without dropping in-dialog traffic."
---

## Admin Guide

### Overview

The `drain` module provides a runtime traffic-draining state intended for rolling upgrades, Kubernetes termination and planned maintenance.

When draining is enabled, the module marks its own `drain` Status/Report group NOT_READY. This is intentionally a component readiness signal rather than silently changing the OpenSIPS core status. Kubernetes or an external health endpoint should query the `drain` group and remove the node from service before termination. With `auto_reject` enabled, it rejects new initial INVITEs and/or REGISTER requests before the main routing script while allowing in-dialog requests such as ACK, BYE, UPDATE and re-INVITE to continue normally.

Before rejecting a drain-eligible request, the module (both the automatic
pre-script callback and the `drain_reject()` function) checks the TM
transaction table. If the packet is a retransmission of an initial INVITE
or REGISTER that was accepted before drain mode began, TM retransmits the
existing transaction response instead of the drain module generating a new
503. This keeps in-flight transaction semantics intact across the drain
transition.

The module also exposes the remaining work and raises `E_DRAIN_COMPLETE` once
all active and early dialogs are gone and, by default, the TM in-use
transaction count also reaches zero.

### Dependencies

The `sl`, `tm` and `dialog` modules are required. They are declared as module dependencies so OpenSIPS will reject a configuration which cannot provide stateless replies, transaction counters or dialog tracking needed for safe draining.

The remaining work is computed from the `dialog` and `tm` statistics, so the
`dialog` module must keep its `enable_stats` parameter turned on (the
default). The same applies to the `tm` module while `wait_transactions` is
enabled. OpenSIPS refuses to start otherwise, instead of reporting a drain
as complete while calls are still in progress.

### Exported Parameters

#### initial_state (integer)

Start in drain mode. Default: `0`.

#### auto_reject (integer)

Automatically enforce the drain policy in a pre-script request callback. Default: `1`.

#### reject_invites (integer)

Reject initial INVITE requests while draining. Re-INVITEs with a To-tag are not rejected. Default: `1`.

#### reject_registers (integer)

Reject REGISTER requests while draining. Default: `1`.

#### wait_transactions (integer)

Include `tm:inuse_transactions` in the drain-completion condition. Default:
`1`.

Set this to `0` in deployments where periodic stateless/transactional health
traffic or internal housekeeping can continuously create short-lived
transactions and the operational requirement is specifically "all dialogs
finished". The transaction gauge is still exposed in status either way.

#### reply_code (integer)

SIP status code returned for rejected requests. It must be a
final, non-2xx code (300 to 699). Default: `503`.

#### reply_reason (string)

Reason phrase returned for rejected requests. Default: `Service Unavailable`.

### Exported Functions

#### drain_enabled()

Returns `1` while the node is draining and a negative value otherwise.

#### drain_reject()

Applies the configured rejection policy to the current request. This is useful when `auto_reject=0` and the script should decide where drain enforcement occurs.

It returns `1` when the request was consumed by the drain logic - either a
`reply_code` reply was sent, or the request was recognized as a
retransmission of a transaction created before draining started and TM
re-sent its last reply - so the script should stop processing it. It returns
a negative value when the request must be routed normally (not draining, not
covered by the policy, or a transaction already exists for it).

```opensips
route {
	if (drain_reject())
		exit;
	...
}
```

### Exported Statistics

- `drain:draining`
- `drain:rejected_requests`
- `drain:active_dialogs`
- `drain:early_dialogs`
- `drain:inuse_transactions`
- `drain:remaining`

`dialog:active_dialogs` only counts confirmed dialogs: a dialog is moved
from `dialog:early_dialogs` to `dialog:active_dialogs` when it is answered.
`remaining` is therefore the sum of `active_dialogs` and `early_dialogs`,
plus `tm:inuse_transactions` when `wait_transactions` is enabled. Dialogs
which have not yet received any provisional reply are not visible in the
dialog gauges and are only covered through the transaction count.

The dialog and transaction gauges reuse the standard `dialog` and `tm` statistics through module-scoped lookups, so the exported drain gauges cannot accidentally resolve to themselves.

### Exported MI Functions

#### drain:enable

Enable or disable draining:

```bash
opensips-cli -x mi drain:enable enable=1
opensips-cli -x mi drain:enable enable=0
```

The response contains the current drain state, active/early dialog counts, in-use transaction count and the computed `remaining` work gauge.

#### drain:status

Returns the current drain state and remaining work:

```bash
opensips-cli -x mi drain:status
```

### Events

#### E_DRAIN_STATE_CHANGED

Raised whenever drain mode is enabled or disabled.

#### E_DRAIN_COMPLETE

Raised once drain mode is enabled and `drain:remaining` reaches zero. By
default this means `dialog:active_dialogs == 0`,
`dialog:early_dialogs == 0` and `tm:inuse_transactions == 0`. When
`wait_transactions=0`, only the active and early dialog counts gate
completion.

### Example

```opensips
loadmodule "sl.so"
loadmodule "dialog.so"
loadmodule "tm.so"
loadmodule "drain.so"

modparam("drain", "reject_invites", 1)
modparam("drain", "reject_registers", 1)
```

A typical rolling-upgrade sequence is:

1. `opensips-cli -x mi drain:enable enable=1`
2. have the readiness/LB probe treat Status/Report group `drain` as not ready
3. wait for LB removal and `E_DRAIN_COMPLETE`
4. terminate or upgrade the node


### Readiness probe note

The Status/Report group is registered as non-public for mutation: generic
Status/Report setters cannot change drain readiness independently from the
module's actual state. It remains readable through the standard SR MI
interfaces.

For example, a readiness bridge can query the `drain` group and consider the
node ready only while its `Readiness` field is true.
