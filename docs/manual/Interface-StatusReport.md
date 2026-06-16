---
title: "Status/Report Interface"
description: "The Status/Report (or SR) is an OpenSIPS framework that allows different components of OpenSIPS (like modules, parts of the core) to publish their status (in..."
---

The **Status/Report** (or **SR**) is an OpenSIPS framework that allows different components of OpenSIPS (like modules, parts of the core) to publish their status (in terms of readiness) and reports (logs) relevant to their activities.   

This framework is intended to be used in operational activities, to check the readiness of OpenSIPS when starting up, to monitor its status at runtime and to trace back its operations via the logs/reports.

## Overview

The base element in the **Status/Report** framework is the *identifier* - an status and some reports may be attached to an identifier. All the identifiers do exist within a **Status/Report** group. So, a group is a set of identifiers - a module or a core may be such groups. For example the *drouting* module publishes the *drouting* group where each routing partition is an *identifier*.   

As there are cases where the group (the modules) do not need multiple identifiers, there is a default *main* identifier - such identifier may be referred only by the name of the group.

The information attached to an identifier is:
* **status** as integer value, translating if the identifier is ready for operation or not; a strict negative value means not-ready, while a strict positive value means it is ready; a zero value is not accepted.
* **status details** is a optional text to the status, providing some human friendly (or details) information in regards to the current status.
* **reports** is a fix-size array (rather a queue discarding the oldest records) of logs produced by the identifier. Each report/log is produced with a timestamp also.

I most of the cases, the status and reports of an identifier are internally produced by the OpenSIPS code - the **Status/Report** interface just gives you access to the status / report information from outside the code, for monitoring purposes.

---

## Scripting functions

The SR Interface provides a script function to check the readiness status of an identifier (or of an entire group), see the [sr_check_status( group, \[identifier\])](https://docs.opensips.org/manual/devel/script-corefunctions#sr_check_status) function.

---

## MI functions

The SR Interface provides multiple functions to check/list the status of one/multiple identifiers and to list their reports:
* [sr_get_status](https://docs.opensips.org/manual/devel/interface-coremi#sr_get_status)
* [sr_list_status](https://docs.opensips.org/manual/devel/interface-coremi#sr_list_status)
* [sr_list_reports](https://docs.opensips.org/manual/devel/interface-coremi#sr_list_reports)
* [sr_list_identifiers](https://docs.opensips.org/manual/devel/interface-coremi#sr_list_identifiers)

---

## Events

The SR framework raises an event each time the status of a Status/Report identifier changes. See the [E_CORE_SR_STATUS_CHANGED event](https://docs.opensips.org/manual/devel/interface-coreevents#E_CORE_SR_STATUS_CHANGED) for more details.

---

## Core identifiers

The OpenSIPS core provides the **core** group, with a "main" (default) identifier. The available status are:
* STATE_NONE (-100) - OpenSIPS just started
* STATE_TERMINATING (-2) - OpenSIPS is shutdown sequence
* STATE_INITIALIZING (-1) - OpenSIPS in startup sequence
* STATE_RUNNING (1) - OpenSIPS fully up and running

Also the **auto-scaling** group is exposed (if auto-scaling feature enabled), where each auto-scaling group is a Status/Report identifier. Each identifier gets reports on the forking or ripping of processes in that auto-scaling group.

---

## Modules identifiers

The OpenSIPS modules may or may not provide their own groups and identifiers. For this you need to check the module's documentation.

---

## Scripting identifiers

The [status_report](../../modules/status_report/README.md) allow the creation of custom SR identifiers from script level. Even more, it is possible to set the status or to publish a report from script for such custom identifiers.
