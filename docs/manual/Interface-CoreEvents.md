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
* **time**: the amount of time (in microseconds) spent by the operation
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

## Process Auto-Scaling (upscale and downscale)

**Event**: E_CORE_PROC_AUTO_SCALE

This event is triggered whenever a new process is created (forked) or a process is terminated due the auto-scaling logic. In order to have this event trigger, the [auto-scaling](https://docs.opensips.org/manual/3-1/script-coreparameters#auto_scaling_profile) must be enabled in your configuration.

Parameters:
* **group_type**: the type/name of the scaling group (UDP/TCP/TIMER).
* **group_filter**: the filter (usually the socket/interface for UDP) of the scaling group.
* **group_load**: the load over the scaling group.
* **scale**: "up" or "down"
* **process_id**: the process ID (at OpenSIPS level) of the scaled (up or down) process.
* **pid**: the PID (OS level) of the scaled (up or down) process.
