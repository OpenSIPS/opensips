---
title: "Types of routes"
description: "Request routing block. It contains a set of actions to be taken for SIP requests."
---

**OpenSIPS** routing logic uses several types of routes. Each type of route is triggered by a certain event and allows you to process a certain type of message (request or reply).

---

## route

Request routing block. It contains a set of actions to be taken for SIP requests.

**Triggered by** : receiving an external request from the network.

**Processing** : the triggering SIP request.

**Type** : initially stateless, may be forced to stateful by using TM functions.

**Default action** : if the request is not either forwarded nor replied, the route will simply discard the request at the end.

The main 'route' block identified by 'route`{...}`' or 'route[0]`{...}`' is executed for each SIP request.

The implicit action after execution of the main route block is to drop the SIP request. To send a reply or forward the request, explicit actions must be called inside the route block.

Example of usage:
```c

    route {
         if(is_method("OPTIONS")) {
            # send reply for each options request
            sl_send_reply(200, "OK");
            exit();
         }
         route(1);
    }
    route[1] {
         # forward according to uri
         forward();
    }

```

Note that if a 'route(X)' is called from a 'branch_route[Y]' then in 'route[X]' is just processed each separate branch instead of all branches together as occurs in main route.

A route can return a set of values, that can later be retrieved from the route's calling context using the [`$return`](https://docs.opensips.org/manual/devel/script-corevar#return) variable.

Example of passing values:
```c

    route {
         route(query);
         xlog("Query returned id $return(0) with $return(1) values\n");
    }
    route[query] {
         # perform a query for information and store the information in $var(id) and $var(values)
         return(1, $var(id), $var(values));
    }

```
Note that the first parameter of the return is always the return code, and cannot be retrieved using the `$return()` variable.

---

## branch_route

Request's branch routing block. It contains a set of actions to be taken for each branch of a SIP request.

**Triggered by** : preparation a new branch (of a request); the branch is well formed, but not yet sent out.

**Processing** : the SIP request (with the branch particularities, like RURI, branch flags)

**Type** : stateful

**Default action** : if the branch is not dropped (via "drop" statement), the branch will be automatically sent out.

It is executed only by TM module after it was armed via t_on_branch("branch_route_index").

Example of usage:
```c

    route {
        lookup("location");
        t_on_branch("1");
        if(!t_relay()) {
            sl_send_reply(500, "Internal Server Error");
        }
    }
    branch_route[1] {
        if($ru=~"10\.10\.10\.10") {
            # discard branches that go to 10.10.10.10
            drop();
        }
    }

```

---

## failure_route

Failed transaction routing block. It contains a set of actions to be taken each transaction that received only negative replies (>=300) for all branches.

**Triggered by** : receiving or generation(internal) of a negative reply that completes the transaction (all branches are terminated with negative replies)

**Processing** : the original SIP request (that was sent out)

**Type** : stateful

**Default action** : if no new branch is generated or no reply is forced over, by default, the winning reply will be sent back to UAC.

The 'failure_route' is executed only by TM module after it was armed via t_on_failure("failure_route_index").

Note that inside the 'failure_route', the request that initiated the transaction is being processed, and not its reply.

Example of usage:
```c

    route {
        lookup("location");
        t_on_failure("1");
        if(!t_relay()) {
            sl_send_reply(500, "Internal Server Error");
        }
    }
    failure_route[1] {
        if(is_method("INVITE")) {
             # call failed - relay to voice mail
             t_relay("udp:voicemail.server.com:5060");
        }
    }

```

---

## onreply_route

Reply routing block. It contains a set of actions to be taken for SIP replies.

**Triggered by** : receiving of a reply from the network

**Processing** : the received reply

**Type** : stateful (if bound to a transaction) or stateless (if global reply route).

**Default action** : if the reply is not dropped (only provisional replies can be), it will be injected and processed by the transaction engine.

There are three types of onreply routes:

* **global** - it catches all replies received by OpenSIPS and does not need any special arming (simple definition is enough) - named 'onreply_route `{...}`' or 'onreply_route[0] `{...}`'. NOTE: this route is not SIP transaction aware (the reply was not matched to the transaction), so no transactional data is available here.

* **per request/transaction** - it catches all received replies belonging to a certain transaction and need to be armed (via "t_on_reply()" ) at request time, in REQUEST ROUTE - named 'onreply_route[N] `{...}`'.

* **per branch** - it catches only the replies that belong to a certain branch from a transaction. It needs to be armed (also via "t_on_reply()" ) at request time, but in BRANCH ROUTE, when a certain outgoing branch is processed - named 'onreply_route[N] `{...}`'.

Certain 'onreply_route' blocks can be executed by TM module for special replies. For this, the 'onreply_route' must be armed for the SIP requests whose replies should be processed within it, via t_on_reply("onreply_route_index").

```c

route {
        $ru = "sip:bob@opensips.org";  # first branch
        $msg.branch = "sip:alice@opensips.org"; # second branch

        t_on_reply("global"); # the "global" reply route
                              # is set the whole transaction
        t_on_branch("1");

        t_relay();
}

branch_route[1] {
        if ($rU=="alice")
                t_on_reply("alice"); # the "alice" reply route
                                      # is set only for second branch
}

onreply_route {
        xlog("OpenSIPS received a reply from $si\n");
}

onreply_route[alice] {
        xlog("received reply on the branch from alice\n");
}

onreply_route[global] {
        if (t_check_status("1[0-9][0-9]")) {
                setflag("PROVISIONAL_REPLY");
                log("provisional reply received\n");
                if (t_check_status("183"))
                        drop;
        }
}

```

---

## error_route

The error route is executed automatically when a parsing error occurs during SIP request processing, or when a script [assert](https://docs.opensips.org/manual/devel/script-corefunctions#assert) fails. It allows the administrator to decide what to do in such error cases.

> [!IMPORTANT]
> as this is triggered ONLY for SIP request, OpenSIPS has to be able to correctly parse the first line of the SIP message. So any syntax error in the first line will NOT trigger this route (as OpenSIPS will not be able to tell if a reply or request).

**Triggered by** : parsing error in "route"

**Processing** : failed request

**Type** : stateless (recommended)

**Default action** : discard request.

In error_route, the following pseudo-variables are available to get access to error details:
* `$(err.class)` - the class of error (now is '1' for parsing errors)
* `$(err.level)` - severity level for the error
* `$(err.info)` - text describing the error
* `$(err.rcode)` - recommended reply code
* `$(err.rreason)` - recommended reply reason phrase

```text

  error_route {
     xlog("--- error route class=$(err.class) level=$(err.level)
            info=$(err.info) rcode=$(err.rcode) rreason=$(err.rreason) ---\n");
     xlog("--- error from [$si:$sp]\n+++++\n$mb\n++++\n");
     sl_send_reply($err.rcode, $err.rreason);
     exit;
  }

```

---

## local_route

The local route is executed automatically when a new SIP request is generated by TM, internally (no UAC side). This is a route intended to be used for message inspection, accounting and for applying last changes on the message headers. Routing and signaling functions are not allowed. 

**Triggered by** : TM generating a brand new request

**Processing** : the new request

**Type** : stateful 

**Default action** : send the request out

```c

  local_route {
     if (is_method("INVITE") && $ru=~"@foreign.com") {
        append_hf("P-hint: foreign request\r\n");
        exit;
     }
     if (is_method("BYE") ) {
        acc_log_request("internally generated BYE");
     }
  }

```

---

## startup_route

The **startup_route** is executed only once when OpenSIPS is started and before the processing of SIP messages begins. This is useful if some initiation actions are needed, like loading some data in the cache, to ease up the future processing. Notice that this route, compared to the others is not triggered at the receipt of a message, so the functions that can be called here must not do processing on the message.

**Triggered** : At startup, before the listener processes are started.

**Processing** : Initializing functions.

```c

  startup_route {
    sql_query_one("SELECT gwlist FROM routing_rules WHERE ruleid = 1", "$avp(gateway_list)");
    cache_store("local", "rule1", "$avp(gateway_list)");
  }

```

---

## timer_route

The **timer_route** is a route executed periodically at a configured interval of time specified next to the name (in seconds). Similar to *startup_route*, this route does not process a SIP message.  Multiple timer routes (possibly at differing running intervals) are allowed.

**Triggered by** : The *timer* worker process.

**Processing** : Functions that do periodic, recurring processing.

> [!NOTE]
> when OpenSIPS starts, each timer_route is **first executed after `<interval>`** seconds!

```c

  timer_route[gw_update, 300] {
    sql_query_one("SELECT gwlist FROM routing_rules WHERE ruleid = 1", "$avp(gateway_list)");
    $shv(gateway_list) = $avp(gateway_list);
  }

```

---

## event_route
The **event_route** is used by the OpenSIPS Event Interface to execute script code when an event is triggered. The name of the route is the event that has to be handled by that route. The route itself is executed asynchronously with regards to the trigger moment.

**Triggered by** : OpenSIPS core when an event with the same name is raised by the Event Interface

**Processing** : the event triggered

**Type** : stateless (recommended)

**Default action** : no script code is executed when the event is raised.

```text

  event_route[E_PIKE_BLOCKED] {
    xlog("The E_PIKE_BLOCKED event was raised\n");
  }

```
