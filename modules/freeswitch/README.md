---
title: "freeswitch Module"
description: "The freeswitch module is a C driver for the FreeSWITCH Event Socket Layer interface."
---

## Admin Guide


### Overview


The *"freeswitch"* module is a C driver for the
FreeSWITCH Event Socket Layer interface. It can interact with one or more
FreeSWITCH servers either by issuing commands to them, or by receiving
events from them.


This driver can be seen as a centralized FreeSWITCH ESL connection manager.
OpenSIPS modules may use its API in order to easily establish, reference
and reuse ESL connections.


A FreeSWITCH ESL URL is of the form:
**fs://[username]:password@host[:port]**.
The default ESL port is 8021.


### External Libraries or Applications


The following libraries or applications must be installed before
running OpenSIPS with this module loaded:


- *None*


### Exported Parameters


### Exported Functions


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
