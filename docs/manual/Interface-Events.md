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
* sends the event packed in a datagram

---

## Events

There are several types of events that can be exported by OpenSIPS:
* **Core events** - internal events that trigger changes of OpenSIPS core/global behavior. A full list of exported core events can be found [here](Interface-CoreEvents.md).
* **Modules events** - events triggered by each module, when loaded. Each module can export zero, one or more events.
* **Custom events** - triggered from script using the [raise_event()](Script-CoreFunctions.md#raise_event) command.

---

## Transport Protocols

External applications can be notified about the events triggered using various transport protocols. While the interface itself is provided by OpenSIPS core, each transport protocol is implemented by a separate OpenSIPS module. Currently, in this version there is only one transport protocol available (but many others pending):

* [event_datagram](../../modules/event_datagram/README.md) - sends Datagrams over UDP or UNIX sockets

An external application can subscribe to any of the exported module and can be notified using any of the loaded transport modules/protocols.

---

## Events Subscription

Currently, an external application can only subscribe to an event using the [event_subscribe](Interface-CoreMI.md#event_subscribe) MI command.

---

## Examples

In order to configure a RabbbitMQ server to be notified when a custom event is triggered, first you have to subscribe it to the event through MI, by sending a [event_subscribe](Interface-CoreMI.md#event_subscribe) command.

```opensips

    # opensipsctl fifo event_subscribe E_SCRIPT_CUSTOM_EVENT udp:127.0.0.1:8888

```

Then, in order to trigger the event from the script, call the [raise_event()](Script-CoreFunctions.md#raise_event) command when needed:

```opensips

   ....
   raise_event("E_SCRIPT_CUSTOM_EVENT");     # raises an event without any parameters
   ...

```
