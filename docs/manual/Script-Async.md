---
title: "Asynchronous Statements"
description: "Asynchronous script operations are one of the key features of OpenSIPS 2.1. The main advantage of using them is the fact that they allow the performance of t..."
---

## Description

Asynchronous script operations are one of the key features of OpenSIPS 2.1. The main advantage of using them is the fact that they allow the performance of the OpenSIPS script to scale with a high number of requests per second even when doing blocking I/O operations such as MySQL queries, exec commands or HTTP requests.

  

Using asynchronous logic over simply forking a high number of children in order to scale (50+ processes) also has the advantage of optimizing the usage of system resources. By requiring less processes to complete the same amount of work in the same amount of time, process context switching is minimized and overall CPU usage is improved. Less processes will also eat up less system memory.

## Module requirements

The asynchronous script logic is based on the transaction module (**tm**) - it must be loaded. The SIP transaction is automatically and transparently created (if not existing yet) when an async operation is started. This transaction contains all necessary information to properly suspend script execution (e.g. it stores the updated SIP message, along with all `$avp` variables).

## Script syntax and usage

Usage is quite straightforward. If your blocking function supports asynchronous mode (read the module documentation for this), then you can just throw it in the following function call:
```text

async(blocking_function(...), resume_route);

```
*Note that resume_route has to be a **[simple route](https://docs.opensips.org/manual/2-1/script-routes#route)***.

  

When a function is called in the asynchronous manner (see below), the script is immediately halted, so any code you write after the async() call will be ignored! The current OpenSIPS worker will launch the asynchronous operation, after which it will continue to process other pending tasks (queued SIP messages, timer jobs or possibly other async operations!). As soon as all data is available, it will run the given resume route and continue processing, with a minimum of idle time.

The return code of the function executed in async mode is available in the very beginning of the resume route in the `$rc` or `$retcode` variable. Also, all the output parameters (variables in function parameters used to carry output values) will be available in resume route.

  

```opensips

route
{
    /* preparation code */
    ...
    async(avp_db_query("SELECT credit FROM users WHERE uid='$avp(uid)'", "$avp(credit)"), resume_credit);
    /* script execution is paused right away! */
}

route [resume_credit]
{
    if ($rc < 0) {
        xlog("error $rc in avp_db_query()\n");
        exit;
    }

    xlog("Credit of user $avp(uid) is $avp(credit)\n");
}

```

  

Data is copied over to the resume route as follows:

  

> [!NOTE]
> Preserved data (still available in resume route)
>
> * **all `$avp` variables**
> * **all changes in current SIP message**


> [!IMPORTANT]
> Ignored data (not available anymore in resume route)
>
> * **all `$var` variables**


## List of async functions

The following functions may also be called asynchronously:

* [avp_db_query](../../modules/avpops/README.md#id294986)
* [rest_get](../../modules/rest_client/README.md#id293741)
* [rest_post](../../modules/rest_client/README.md#id293886)
* [exec](../../modules/exec/README.md#id294052)

The async implementation is not limited to the above functions, but these are the first ones migrated to async support. More I/O related functions will be ported to the async support.
