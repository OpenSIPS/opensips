---
title: "tls_wolfssl Module"
description: "This module implements TLS operations using the [wolfSSL](https://www.wolfssl.com/) libarary."
---

## Admin Guide


### Overview


This module implements TLS operations using the
[wolfSSL](https://www.wolfssl.com/) libarary. It provides the primitives
required by the *tls_mgm* module in order to expose a
higher-level API used by TLS-based protocol modules like
*proto_tls* or *proto_wss*.


The *wolfSSL* library is statically-linked and bundled
with this module so no installation or external dependency is required.


### Dependencies


#### Compilation


The following packages must be installed before compiling this module:


- *autoconf*.
- *automake*.
- *libtool*.


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None*.


#### External Libraries or Applications


The following libraries or applications must be installed before
running OpenSIPS with this module loaded:


- *None*.


## Frequently Asked Questions


**Q: Why do I get the following error when compiling the module?**


If you obtained the OpenSIPS sources by cloning the repository from Github,
without using the *--recursive* option for the
*git clone* command, you did not properly fetch the
*wolfSSL* library code, which is included as a git submodule
pointing to the official *wolfSSL* repository.

In order to fetch the *wolfSSL* library code you can run:

```bash
git submodule update --init
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
