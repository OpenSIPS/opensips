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

Several protocols are available in order to connect (from external apps) to the OpenSIPS **MI** . While the interface itself is provided by OpenSIPS core, each protocol is provided by a separate OpenSIPS module. You can load multiple MI modules in order to use multiple MI protocols in the same time.

Available protocols are :

* **mi_fifo** - protocol is text oriented (see the syntax in the module documentation), communications is done via a FIFO file; OpenSIPS reads from a predefined FIFO file, where the external apps are writing down the MI commands. As the file is actually as stream of data, there is no restrictions here on the amount of data OpenSIPS may return (when fetching data from OpenSIPS)

* **mi_datagram** - protocol is text oriented, similar for fifo (see the syntax in the module documentation), communication is done either via UNIX SOCKETS , either via UDP packages ; OpenSIPS listens for MI commands on UDP port(s) or unisock files; The transported data is limited to the size of a Datagram (65K).

* **mi_xmlrpc** - protocol is XMLRPC (XML over HTTP). As TCP is used, there is no limit in regards to the amount of transfered data.

All protocols do allow multiple applications (clients) to connect in the same time to the MI interface.

---

## Examples

A simple example of interacting with OpenSIPS via MI interfaces is when using the **opensipsctl** utility - it uses FIFO or XMLRPC protocols to push MI commands into OpenSIPS.

The *'opensipsctl* utility allows you explicitly run an MI command via the FIFO file:

```bash

    opensipsctl fifo _mi_cmd_
    opensipsctl fifo ps
    opensipsctl fifo debug 4

```

or it internally and transparently uses MI command them when providing different or more complex functionalities.

A simple program in Python to trigger to run a MI command in OpenSIPs via XMLRPC protocol:
```python

#!/usr/bin/python
import xmlrpclib
opensips = xmlrpclib.ServerProxy('http://127.0.0.1:8080/RPC2')
print opensips.ps();

```
