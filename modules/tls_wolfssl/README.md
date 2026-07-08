---
title: "tls_wolfssl Module"
description: "This module implements TLS operations using the [wolfSSL](https://www.wolfssl.com/) libarary. It provides the primitives required by the *tls_mgm* module in order to expose a higher-level API used by TLS-based protocol modules like *proto_tls* or *proto_wss*."
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


### Exported Parameters


All these parameters can be used from the opensips.cfg file,
		to configure the behavior of OpenSIPS-TLS.


#### try_use_ktls (integer)


Try to use KTLS for RX and TX ( dependent on Kernel support and loaded modules https://docs.kernel.org/networking/tls-offload.htm )
			If kernel support is not found, or if the cypher attempted to be used is not supported ( only AES-GCM for now ), then SSL operations will continue to be done in user-space.
			IF NIC supports SSL offloading, that can also be enabled without any changes needed to the module https://docs.nvidia.com/doca/sdk/ktls-offloads/index.html


Default value is *0*.


```opensips title="Set try_use_ktls variable"
...
modparam("tls_wolfssl", "try_use_ktls", 1)
...
				
```


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
