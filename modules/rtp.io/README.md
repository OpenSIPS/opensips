---
title: "RTP.io Module"
description: "The RTP.io module provides an integrated solution for handling RTP traffic within OpenSIPS, enabling RTP relaying and processing directly inside the OpenSIPS process. This eliminates the need for external processes such as RTPProxy, resulting in a more ..."
---

## Admin Guide


### Overview


The RTP.io module provides an integrated solution
            for handling RTP traffic within OpenSIPS, enabling RTP relaying and
            processing directly inside the OpenSIPS process. This eliminates the
            need for external processes such as RTPProxy, resulting in a more
            streamlined, efficient, and manageable system for certain use cases.


The *rtp.io* module starts RTP handling threads in the main
            OpenSIPS process and allows the *rtpproxy* module to access these
            threads via a one-to-one socket pair. This tight integration facilitates efficient
            RTP traffic management within OpenSIPS without relying on external RTP handling
            services.


The module requires RTPProxy version 3.1 or higher, compiled
            with the `--enable-librtpproxy` option to build. It utilizes the
            `librtpproxy` library to manage RTP traffic and interfaces with the
            existing *rtpproxy* module to generate commands, parse responses,
            and process SIP messages.


When the *rtpproxy* module is loaded without arguments and the
            *rtp.io* module is also loaded, the sockets exported by
            *rtp.io* are used automatically in set `0`.
            Alternatively, these sockets can be incorporated into other sets by using the
            `"rtp.io:auto"` moniker.


### Dependencies


### Exported Parameters


#### rtpproxy_args(string)


Command-line parameteres passed down to the embedded RTPProxy
                module upon initialization.  Refer to the RTPProxy
                documentation for the full list.


*Parameter has no default value.*


```opensips title="Set rtpproxy_args parameter"
...
modparam("rtp.io", "rtpproxy_args", "-m 12000 -M 15000 -l 0.0.0.0 -6 /::")
...
```


### Exported Functions
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
