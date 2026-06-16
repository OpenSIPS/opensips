---
title: "Statistics Interface"
description: "The Statistics Interface is an OpenSIPS interface that provides access to various internal statistics of OpenSIPS. The statistic provide useful information a..."
---

The **Statistics Interface** is an OpenSIPS interface that provides access to various internal statistics of OpenSIPS. The statistic provide useful information about what is going on inside OpenSIPS - this can be used by external applications, for monitoring purposes, load evaluation, realtime integration with other services. The values of statistic variables are exclusively numerical.

---

## Overview

**OpenSIPS** typically provides two types of statistic variables:
* counter like - variables that keep counting things that happened in OpenSIPS, like received requests, processed dialogs, failed DB queries, etc
* computed values - variables that are calculated in realtime, like how much memory is used, the current load, active dialogs, active transactions, etc

The statistic variables are not restart persistent, they all start with a 0 value (the counter like variables). The *counter like* statistics can also be reset (to 0 value) during OpenSIPS runtime.

In OpenSIPS, the statistics variables are grouped in different sets, depending on their purposes or how is providing them. For example, the OpenSIPS core provides the **shmem**, **load**, **net**, etc groups, while each OpenSIPS module provides its own group (typically the group has the same name as the module).

All available statistic variables are listed and documented : statistics provided [by OpenSIPS core](Interface-CoreStatistics.md) or by [OpenSIPS modules](Modules.md) (see the Statistics chapter for each module).

---

## Usage

To get access to the statistics you have to use the [MI interface](Interface-MI.md) which provides (directly from OpenSIPS core) several MI functions for:  
\
**Fetching the value** of a statistic variable, of an entire group of variables or of all variables. The MI [get_statistics](Interface-CoreMI.md) command can be used here:
```bash

   # get one statistic variable, by name
   > opensipsctl fifo get_statistics rcv_requests
   > core:rcv_requests = 3428
   > opensipsctl fifo get_statistics real_used_size 
   > shmem:real_used_size = 2951864

   # get various statistic variables, by list of names
   > opensipsctl fifo get_statistics rcv_requests inuse_transactions
   > core:rcv_requests = 453
   > tm:inuse_transactions = 10

   # get all stats from a group
   > opensipsctl fifo get_statistics shmem:
   > shmem:total_size = 33554432
   > shmem:used_size = 2897024
   > shmem:real_used_size = 2951864
   > shmem:max_used_size = 2952304
   > shmem:free_size = 30602568
   > shmem:fragments = 26

   # get all stats from OpenSIPS
   > opensipsctl fifo get_statistics all
   >...........

```
  

**Reseting the value** of a statistic variable (to 0 value), but only if it is counter-type variable.

> [!IMPORTANT]
> Reseting a computed-value statistic will be ignored and have no effect.

 The MI [reset_statistics](Interface-CoreMI.md) command can be used here:

```bash

   # reset one statistic variable, by name
   > opensipsctl fifo reset_statistics rcv_requests

```
