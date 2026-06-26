---
title: "Asynchronous Statements"
description: "Asynchronous statements are one of the key features of OpenSIPS. One of the main reasons to use them is that they allow the performance of the OpenSIPS s..."
---

## Description

The ability to run various script functions in an asynchronous way is a key performance feature of OpenSIPS. This async handling allows the OpenSIPS script performance to scale with a high number of requests per second even when doing blocking, time consuming I/O operations such as DB queries, exec commands or HTTP queries.

When it comes to scaling, the usage of the asynchronous *suspend-resume* logic instead of forking a large number of processes, has the advantage of optimizing the usage of system resources. By requiring less processes to complete the same amount of work in the same amount of time, process context switching is minimized and overall CPU usage is improved. Less processes will also eat up less system memory.

## async() statement

The **async()** statement of the OpenSIPS script can be used in situations where the script writer both needs to perform blocking I/O and also depends on the result of this operation. Some example scenarios:

* fetch SIP authentication data from a database
* perform an HTTP/REST query and act upon its result
* pause script execution for X seconds
* execute an external script and use its result

Not all the script functions may be executed in combination with the **async()** statement - each OpenSIPS module exposes a dedicated set of script functions to be used in async mode. For this, check the [module's documentation](Modules.md).

### Requirements

The **async()** statement depends on the transaction module ([**TM**](../../modules/tm/README.md)) - it must be loaded. The SIP transaction will be automatically and transparently created when an async operation is started, if necessary. This transaction contains all the necessary information to suspend script execution (e.g. it stores the updated SIP message, along with all `$avp` variables).

### Script syntax and usage

Usage is straightforward: if your blocking function supports asynchronous mode (read the module documentation for this), then you can just throw it in the following function call:
```text

async(blocking_function(...), resume_route [,timeout]);

```
*Note that resume_route must be a **[simple route](Script-Routes.md#route)***.


Because the **async()** statement is *serial with script execution* (see below), the script will be immediately halted when calling it, so any code placed after the async() call will be ignored! The current OpenSIPS worker will launch the asynchronous operation, after which it will continue to process other pending tasks (queued SIP messages, timer jobs or possibly other async operations!). As soon as all data is available, it will run the `resume_route` - thus resuming script execution with a minimum of idle time.

The return code of the function executed in async mode is available in the very beginning of the `resume_route` in the `$rc` or `$retcode` variable. Also, all output parameters (variables in function parameters used to carry output values) will be available in `resume_route`.

The optional 'timeout' parameter is to control for how long the script should wait for the blocking function to complete (independently from its implementation). If the blocking I/O is not completed before the given timeout, the async layer will force the function to complete (with timeout) its I/O and to resume the script.


```c

route
{
    /* preparation code */
    ...
    async( sql_query("SELECT credit FROM users WHERE uid='$avp(uid)'", "$avp(credit)"), resume_credit);
    /* script execution is paused right away! */
}

route [resume_credit]
{
    if ($rc < 0) {
        xlog("error $rc in avp_db_query()\n");
        exit;
    }

    xlog("Credit of user $avp(uid) is $avp(credit)\n");
    ...
    t_relay();
}

```


> [!IMPORTANT]
> Not all variables are preserved after an **async()** execution. Only some are inherited in the `resume_route`:
>
> * **all `$avp` variables**
> * **all changes in current SIP message**


## launch() statement

The **launch()** statement of the OpenSIPS script can be used in situations where the script writer needs to perform blocking I/O, but does not depend on the result of this operation in order to continue the current SIP routing decision flow. Some example scenarios:

* execute an external push notification trigger
* push data into a custom database (e.g. call statistics, CDRs, etc.)
* notify an HTTP service of the occurrence of an event (e.g. SIP traffic pattern, fraud detection, etc.)

Basically, the **launch()** statement acts as a *parallel asynchronous operation* - the I/O operation is only launched from the script, but its execution may happen in parallel in a totally different OpenSIPS process/worker.

The **launch()** statement comes with no additional module dependencies, being provided by the OpenSIPS core.

### Script syntax and usage

Similarly to the **async()** statement, if your blocking function supports asynchronous mode (read the [module's documentation](Modules.md) for this), then you can just throw it in the following function calls:
```c

launch(blocking_function(...));
or
launch(blocking_function(...), report_route);
route[report_route] {}
or
launch(blocking_function(...), report_route, "Something with $var(xx) to be passed to report route");
route[report_route] {
   xlog("received as input the <$param(1)> string\n");
}

```
*Note that report_route must be a **[simple route](Script-Routes.md#route)***.


The **launch()** statement is both asynchronous and parallel with the script execution that follows it (see below). Note how the `report_route` can be omitted, as script execution does not depend on it. This route may be triggered at any of the following points in time:

* right before the next code line following the **launch()** call
* during the routing of the current SIP message
* after the routing of the current SIP message


The return code of the function executed in async mode is available in the very beginning of the `report_route` in the `$rc` or `$retcode` variable. Also, only the output parameters (variables in function parameters used to carry output values) will be available inside this route.


```c

route
{
    /* preparation code */
    ...

    # send a push notification asynchronously, in parallel
    launch(exec("/usr/local/bin/send-google-pn.py"), pn_counter);
    t_relay();
}

route [pn_counter]
{
    if ($rc < 0) {
        xlog("error $rc in pn script!\n");
        update_stat("pn-failure", "1");
        exit;
    }

    update_stat("pn-success", "1");
}

```

> [!IMPORTANT]
> The only data available after a **launch()** execution in the `report_route` is:
>
> * output variables set by the async function
> * the text parameter passed to the **launch()** statement


## Limitations

### Async Engine Compatibility

The async engine is heavily dependent on non-blocking I/O features exposed by the underlying libraries -- a blocking I/O operation, such as an HTTP or an SQL query can only be made asynchronous if the library additionally provides both:

* a non-blocking equivalent of the same, originally blocking function
* after the non-blocking equivalent function is launched, the library must also provide a mechanism to extract a valid Linux file descriptor corresponding to the data transfer operation that has just been launched.  The OpenSIPS async engine will poll on this fd, and will trigger internal state updates each time new data is available.  When the blocking operation is finished, the `resume_route` gets called, and the async operation is finalized.


### TCP Connect Issues

Although they provide async functionality, some libraries only do this for the "transfer" part of the I/O operation, and NOT the initial TCP connect.  Consequently, on some corner-case scenarios (e.g. the TCP connect hangs due to an unresponsive server, an in-between firewall which drops packets instead of rejecting them, etc.) the async operation may actually block!


Examples of modules which are affected by this limitation:

* rest_client - although it reuses TCP connections on further requests, libcurl will block until a TCP connection is established from a given OpenSIPS worker.  Should these TCP connects ever hang, so will the corresponding OpenSIPS worker.

* db_mysql - similar to rest_client: although it reuses DB connections heavily, establishing each connection is a blocking operation, and cannot be made async due to the nature of the library.

**Mitigation**: depending on your specific setup, you may be severely impacted by these blocking TCP connects or hardly at all.  For the former case, we suggest forking external processes responsible for your blocking operations, and invoking them asynchronously, using constructs such as:

```bash
 async(exec("curl my_host", $var(response_body)), resume_route); 
```

or

```text
 async(exec("mysql-query 'SELECT * FROM subscriber...'", $var(result_row)), resume_route); 
```

### Allowed Routes

Since the **async** operations are tightly coupled with the transactional engine, they can only be performed in routes where a SIP transaction is present and is awaiting completion:

* request_route
* onreply_route

On the other hand, the **launch** statement should work from **any route**, as it is not dependent on the underlying SIP transaction.
