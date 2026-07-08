---
title: "Events Interface"
description: "The Events Interface is an OpenSIPS interface that provides different ways to notify external applications about certain events triggered inside OpenSIPS."
---

The **Events Interface** is an OpenSIPS interface that provides different ways to notify external applications about certain events triggered inside OpenSIPS.

## Overview

In order to notify an external application about OpenSIPS internal events, the **Event Interface** provides the following functions:
* manages exported events
* manages subscriptions from different applications
* exports generic functions to raise an event (regardless the transport protocol used)
* communicates with different transport protocols to send the events

More detailed information about **OpenSIPS Event Interface** can be found in the [Event Interface Tutorial](https://docs.opensips.org/tutorials-eventinterface-1-8).

---

## Events

There are several types of events that can be exported by OpenSIPS:
* **Core events** - internal events that trigger changes of OpenSIPS core/global behavior. A full list of exported core events can be found [here](Interface-CoreEvents.md).
* **Modules events** - events triggered by each module, when loaded. Each module can export zero, one or more events. Details can be found in the [documentation page](Modules.md) of each module.
* **Custom events** - triggered from script using the [raise_event()](Script-CoreFunctions.md#raise_event) command.

---

## Transport Protocols

External applications can be notified about the events triggered using various transport protocols. While the interface itself is provided by OpenSIPS core, each transport protocol is implemented by a separate OpenSIPS module. Multiple transport modules can be loaded simultaneously in order to provide different ways of notifications.

Available transport protocols are :

* [event_datagram](../../modules/event_datagram/README.md) - sends Datagrams over UDP or UNIX sockets
* [event_rabbitmq](../../modules/event_rabbitmq/README.md) - sends an AMQP message to a RabbitMQ server

An external application can subscribe to any of the exported module and can be notified using any of the loaded transport modules/protocols.

---

## Events Subscription

You can subscribe for an event either at startup (using the [subscribe_event()](https://docs.opensips.org/manual/1-9/script-corefunctions#subscribe_event) command in the script) or during runtime, using the [event_subscribe](Interface-CoreMI.md#event_subscribe) MI command.

---

## Examples

In order to configure a RabbbitMQ server to be notified when a custom event is triggered, first you have to subscribe it to the event, using the [subscribe_event()](Script-CoreFunctions.md#subscribe_event) command:

```opensips

    startup_route {
        subscribe_event("E_SCRIPT_CUSTOM_EVENT", "rabbitmq:127.0.0.1/opensips");
    }

```

Then, in order to trigger the event from the script, call the [raise_event()](Script-CoreFunctions.md#raise_event) command when needed:

```opensips

   ....
   raise_event("E_SCRIPT_CUSTOM_EVENT");     # raises an event without any parameters
   ...

```
