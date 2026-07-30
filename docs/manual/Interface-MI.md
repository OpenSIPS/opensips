---
title: "Management Interface"
description: "The Management Interface (or MI) is an OpenSIPS interface that allows external applications to trigger predefined commands inside OpenSIPS."
---

The **Management Interface** (or **MI**) is an OpenSIPS interface that allows external applications to trigger predefined commands inside OpenSIPS. 

## Overview

Such commands typically allows an external app to :
* push data into OpenSIPS (like setting debug level, registering a contact, etc)
* fetch data from OpenSIPS (see registered users, see ongoing calls, get statistics, etc)
* trigger an internal action in OpenSIPS (reloading data, sending a message, etc)

The **MI** commands are provided by the OpenSIPS core (see [full list](Interface-CoreMI.md)) and also by modules (check the commands provided by [each module](Modules.md)).

---

## Protocols

The protocols available in order to connect (from external apps) to the OpenSIPS **MI** are JSON-RPC over several transports and XML-RPC. While the interface itself (tailored around the JSON format) is provided by the OpenSIPS core, each actual transport protocol is provided by a separate OpenSIPS module. You can load multiple MI modules in order to use multiple MI transport protocols at the same time.

The majority of the MI backend modules only provide the transport, while the command parsing and response formatting (as **JSON-RPC**) is done by the OpenSIPS core. The only exceptions are the *mi_html* and *mi_xmlrpc* modules, which use a different format.

The available MI modules are:

### [mi_fifo](../../modules/mi_fifo/README.md)
Provides JSON-RPC transport via a FIFO file; OpenSIPS reads from a predefined FIFO file, where the external apps are writing down the MI commands. As the file is actually as stream of data, there is no restrictions here on the amount of data OpenSIPS may return (when fetching data from OpenSIPS).

### [mi_datagram](../../modules/mi_datagram/README.md)
Provides JSON-RPC transport either via UNIX SOCKETS, or via UDP packets; OpenSIPS listens for MI commands on UDP port(s) or unisock files; The transported data is limited to the size of a Datagram (65K).

### [mi_http](../../modules/mi_http/README.md)
Provides JSON-RPC transport over HTTP. As TCP is used, there is no limit in regards to the amount of transfered data.

### [mi_html](../../modules/mi_html/README.md)
Provides a way of issuing MI commands directly from a web browser via an HTML page. The command's parameters are passed in the URL's query string. Although not conforming to JSON-RPC, the MI responses are still delivered in JSON format within the page.

### [mi_xmlrpc](../../modules/mi_xmlrpc/README.md)
Implements XML-RPC by not only providing an HTTP transport but also by translating between the MI's internal JSON format and XML.

### [mi_script](../../modules/mi_script/README.md)
Provides the ability to run MI commands directly from OpenSIPS' script, returning the result as a JSON string.

All protocols do allow multiple applications (clients) to connect at the same time to the MI interface.

---

## Examples

A few examples of JSON-RPC calls for OpenSIPS:

```bash

# Request with no parameters:
{
  "jsonrpc": "2.0",
  "method": "ps",
  "id": 10
}

# Response:
{
  "jsonrpc":  "2.0",
  "result": {
    "Processes":  [{
        "ID": 0,
        "PID":  9467,
        "Type": "attendant"
      }, {
        "ID": 1,
        "PID":  9468,
        "Type": "HTTPD 127.0.0.1:8008"
      }, {
        "ID": 3,
        "PID":  9470,
        "Type": "time_keeper"
      }, {
        "ID": 4,
        "PID":  9471,
        "Type": "timer"
      }, {
        "ID": 5,
        "PID":  9472,
        "Type": "SIP receiver udp:127.0.0.1:5060 "
      }, {
        "ID": 7,
        "PID":  9483,
        "Type": "Timer handler"
      }, ]
  },
  "id": 10
}

# Request with positional parameters:
{
  "jsonrpc": "2.0",
  "method": "log_level",
  "params": [4, 9472],
  "id": 11
}

# Request with named parameters:
{
  "jsonrpc": "2.0",
  "method": "log_level",
  "params": {
    "level": 4,
    "pid": 9472
  },
  "id": 11
}

# Request with an array type of parameter:
{
  "jsonrpc": "2.0",
  "method": "get_statistics",
  "params": {
    "statistics": ["shmem:", "core:"]
  },
  "id": 11
}

```

A simple example of interacting with OpenSIPS via MI interfaces is the **opensips-cli** utility - it uses FIFO to push MI commands into OpenSIPS:

```bash

    opensips-cli -x mi ps
    opensips-cli -x mi log_level 4 9472

```

Example of sending a JSON-RPC OpenSIPS MI command from the command-line, using *curl*:
```bash

$ curl -X POST localhost:8888/mi -H 'Content-Type: application/json' -d '{"jsonrpc": "2.0", "id": "1", "method": "ps"}'

```
