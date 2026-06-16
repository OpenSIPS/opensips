---
title: "Core Events"
description: "Events are exported by the OpenSIPS core through the Event Interface."
---

Events are exported by the **OpenSIPS** core through the Event Interface.

---

## Threshold limit exceeded

**Event**: E_CORE_THRESHOLD

This event is triggered when a particular action takes longer than a specific threshold. It can be raised when a MySQL or DNS query takes too long, or a SIP message processing goes beyond a specific limit. For more information please see [this](http://lists.opensips.org/pipermail/users/2011-February/016918.html) post.

Parameters:
* **source**: the source of the event: mysql module, core (for DNS or message processing warnings).
* **time**: the number of micro-seconds the limit has been exceeded
* **extra**: extra information, depending on the source of the event

## Private memory threshold exceeded

**Event**: E_CORE_PKG_THRESHOLD

This event is triggered when the private memory usage goes above a threshold limit, specified by the **event_pkg_threshold** the core parameter. It warns external applications about low values of free private memory.

Parameters:
* **usage**: the percentage of private memory usage. Can have values between **event_pkg_threshold** and 100.
* **threshold**: the **event_pkg_threshold** specified in the script.
* **used**: the amount of private memory used.
* **size**: the total amount of private memory.
* **pid**: the pid of the process that raises the event.

> [!IMPORTANT]
>
> > [!NOTE]
> > If the event_pkg_threshold is not specified or 0, then this event is disabled.
>

## Shared memory threshold exceeded

**Event**: E_CORE_SHM_THRESHOLD

This event is triggered when the shared memory usage goes above a threshold limit, specified by the **event_shm_threshold** the core parameter. It warns external applications about low values of free shared memory.

Parameters:
* **usage**: the percentage of private memory usage. Can have values between **event_shm_threshold** and 100.
* **threshold**: the **event_shm_threshold** specified in the script.
* **used**: the amount of private memory used.
* **size**: the total amount of private memory.

> [!IMPORTANT]
>
> > [!NOTE]
> > If the event_shm_threshold is not specified or 0, then this event is disabled.
>
