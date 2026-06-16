---
title: "tls_openssl Module"
description: "This module implements TLS operations using the [openSSL](https://www.openssl.org/) libarary. It provides the primitives required by the *tls_mgm* module in order to expose a higher-level API used by TLS-based protocol modules like *proto_tls* or *proto_wss* etc."
---

## Admin Guide


### Overview


This module implements TLS operations using the
		[openSSL](https://www.openssl.org/) libarary. It provides the primitives
		required by the *tls_mgm* module in order to expose a
		higher-level API used by TLS-based protocol modules like
		*proto_tls* or *proto_wss* etc.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None*.


#### External Libraries or Applications


OpenSIPS TLS v1.0 support requires the following packages:


- *openssl* or
				*libssl* >= 0.9.6
- *openssl-dev* or
				*libssl-dev*


OpenSIPS TLS v1.1/1.2 support requires the following packages:


- *openssl* or
				*libssl* >= 1.0.1e
- *openssl-dev* or
				*libssl-dev*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
