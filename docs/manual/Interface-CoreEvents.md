---
title: "Core Events"
description: "Events are exported by the OpenSIPS core through the Event Interface."
---

Events are exported by the **OpenSIPS** core through the Event Interface.

---

## E_CORE_THRESHOLD

Threshold limit exceeded.

This event is triggered when a particular action takes longer than a specific threshold. It can be raised when a MySQL or DNS query takes too long, or a SIP message processing goes beyond a specific limit. For more information please see [this](http://lists.opensips.org/pipermail/users/2011-February/016918.html) post.

Parameters:
* **source**: the source of the event: mysql module, core (for DNS or message processing warnings).
* **time**: the amount of time (in microseconds) spent by the operation
* **extra**: extra information, depending on the source of the event

## E_CORE_PKG_THRESHOLD

Private memory threshold exceeded.

This event is triggered when the private memory usage goes above a threshold limit, specified by the **event_pkg_threshold** the core parameter. It warns external applications about low values of free private memory.

Parameters:
* **usage**: the percentage of private memory usage. Can have values between **event_pkg_threshold** and 100.
* **threshold**: the **event_pkg_threshold** specified in the script.
* **used**: the amount of private memory used.
* **size**: the total amount of private memory.
* **pid**: the pid of the process that raises the event.

> [!NOTE]
> If the event_pkg_threshold is not specified or 0, then this event is disabled.

## E_CORE_SHM_THRESHOLD

Shared memory threshold exceeded.

This event is triggered when the shared memory usage goes above a threshold limit, specified by the **event_shm_threshold** the core parameter. It warns external applications about low values of free shared memory.

Parameters:
* **usage**: the percentage of shared memory usage. Can have values between **event_shm_threshold** and 100.
* **threshold**: the **event_shm_threshold** specified in the script.
* **used**: the amount of shared memory used.
* **size**: the total amount of shared memory.

> [!NOTE]
> If the event_shm_threshold is not specified or 0, then this event is disabled.

## E_CORE_PROC_AUTO_SCALE

Process Auto-Scaling (upscale and downscale).

This event is triggered whenever a new process is created (forked) or a process is terminated due the auto-scaling logic. In order to have this event trigger, the [auto-scaling](https://docs.opensips.org/manual/devel/script-coreparameters#auto_scaling_profile) must be enabled in your configuration.

Parameters:
* **group_type**: the type/name of the scaling group (UDP/TCP/TIMER).
* **group_filter**: the filter (usually the socket/interface for UDP) of the scaling group.
* **group_load**: the load over the scaling group.
* **scale**: "up" or "down"
* **process_id**: the process ID (at OpenSIPS level) of the scaled (up or down) process.
* **pid**: the PID (OS level) of the scaled (up or down) process.

## E_CORE_TCP_DISCONNECT

TCP connection disconnected.

This event is triggered when a TCP connection is terminated/disconnected.

Parameters:
* **src_ip**: the source IP of the TCP connection
* **src_port**: the source PORT of the TCP connection
* **dst_ip**: the destination IP of the TCP connection
* **dst_port**: the destination PORT of the TCP connection
* **proto**: the protocol of the underlying TCP connection ( ie. tcp, tls, ws, wss, etc )

## E_CORE_SR_STATUS_CHANGED

Status/Report status changed.

This event is triggered the status of an SR identifier changes.

Parameters:
* **group**: the name of the SR group
* **identifier**: the name of the SR identifier
* **status**: the new status (as numerical value) of the SR identifier
* **details**: the details/text attached to the new status
* **old_status**: the old status (as numerical value) of the SR identifier

## E_CORE_LOG

Log message produced.

This event is triggered whenever a log message is produced by OpenSIPS. In order to have this event trigger, the [log_event_enabled](https://docs.opensips.org/manual/3-4/script-coreparameters#log_event_enabled) must be enabled in your configuration.

Parameters:
* **time**: time when the log message was produced
* **pid**: the PID of the processes that produced this log message
* **level**: the log level of this message ("DBG", "INFO" etc.)
* **module**: module that produced this log message; absent for logs triggered from the script by the **xlog()** function
* **function**: internal function that produced this log message; absent for logs triggered from the script by the **xlog()** function
* **prefix**: logging prefix, configured via the [log_prefix](https://docs.opensips.org/manual/3-4/script-coreparameters#log_prefix) parameter. This parameter is absent if the parameter is not configured.
* **message**: the actual log message content

## E_PROFILING_PROC

Process profiling event.

This event is generated when the process profiling is activated. It reports different actions that takes place inside the process.

Parameters:
* **sec**: UNIX TIMESTAMP, seconds
* **usec**: micro seconds within the second
* **session**: session ID, to group all events part of a profiling session
* **verb**: profiling action as 'start','enter','exit' and 'end'
* **name**: description of the profiling action
* **type**: the type of the process generating the profiling data
* **depth**: execution depth - 'start' is level 1, each 'enter' increases, each 'exit' decreases.
* **file**: cfg file name or C function where the profiling is done; only set for 'enter' and 'exit'
* **line**: line in the 'file'; only set for 'enter' and 'exit'
* **status**: only for 'exit' and 'end', the status/retcode of the 'name' action (highly depends on its nature)

Example of usage:
```text

{'sec': 1776767469, 'usec': 200446, 'session': 3463978, 'verb': 'start', 'name': 'SIP receiver udp:127.0.0.1:5060', 'type': 1, 'depth': 0}
{'sec': 1776767469, 'usec': 201035, 'session': 3463978, 'verb': 'enter', 'name': 'udp proto reading', 'type': 1, 'depth': 1, 'file': 'handle_io', 'line': 317}
{'sec': 1776767469, 'usec': 201485, 'session': 3463978, 'verb': 'enter', 'name': 'receive_msg', 'type': 1, 'depth': 2, 'file': 'receive_msg', 'line': 120}
{'sec': 1776767469, 'usec': 202558, 'session': 3463978, 'verb': 'enter', 'name': 'request_script', 'type': 1, 'depth': 3, 'file': 'receive_msg', 'line': 235}
{'sec': 1776767469, 'usec': 203201, 'session': 3463978, 'verb': 'exit', 'name': 'request_script', 'type': 1, 'depth': 2, 'file': 'receive_msg', 'line': 237, 'status': 1}
{'sec': 1776767469, 'usec': 203533, 'session': 3463978, 'verb': 'exit', 'name': 'receive_msg', 'type': 1, 'depth': 1, 'file': 'receive_msg', 'line': 316, 'status': 0}
{'sec': 1776767469, 'usec': 203663, 'session': 3463978, 'verb': 'exit', 'name': 'reading done', 'type': 1, 'depth': 0, 'file': 'handle_io', 'line': 324, 'status': 0}
{'sec': 1776767469, 'usec': 203786, 'session': 3463978, 'verb': 'end', 'name': 'SIP receiver udp:127.0.0.1:5060', 'type': 1, 'depth': 0, 'status': 0}

```

## E_PROFILING_SCRIPT

Script profiling event.

Similar to E_PROFILING_PROC but related to script (routes) execution. It uses the same parameters as E_PROFILING_PROC.
