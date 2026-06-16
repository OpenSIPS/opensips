---
title: "Presence_XCAPDiff Module"
description: "The presence_xcapdiff is an OpenSIPS module that adds support for the \"xcap-diff\" event to presence and pua. At the moment, the module just registers the event but doesn't do any event-specific processing. The module will automatically determine if the presence and/or pua ..."
---

## Admin Guide


### Overview


The presence_xcapdiff is an OpenSIPS module that adds support for the
      "xcap-diff" event to presence and pua. At the moment, the module
      just registers the event but doesn't do any event-specific processing.
      The module will automatically determine if the presence and/or pua
      modules are present and if so it will register the xcap-diff event
      with them. This allows the module to automatically offer presence
      or pua related functionality simply based on the presence of the
      aforementioned modules in the OpenSIPS configuration, without any
      need for manual configuration.


Registering the event with pua, allows the XCAP server to publish
      the xcap-event when some modification of a document happens.
      Registering the event with presence allows clients to subscribe
      to the event.


The module is intended to be used with the OpenXCAP server (www.openxcap.org),
      although it doesn't contain any OpenXCAP-specific code and should be usable
      with any XCAP server.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *presence* module - to enable clients to
              subscribe to the xcap-diff event package.
- *pua* module - to be able to publish the
              xcap-diff event when some modification of a document happens.
- *pua_mi* module - to enable pua to publish
              the xcap-diff event using the MI interface. This is needed if
              this module is intended to be used in conjunction with OpenXCAP.


#### External Libraries or Applications


The following libraries or applications must be installed before
        running OpenSIPS with this module loaded:


- *None*.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
