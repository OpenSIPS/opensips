---
title: "proto_sctp Module"
description: "The **proto_sctp** module is an optional transport module (shared library) which exports the required logic in order to handle SCTP-based communication. (socket initialization and send/recv primitives to be used by higher-level network layers)"
---

## Admin Guide


### Overview


The **proto_sctp** module is an optional transport module (shared library) which
	exports the required logic in order to handle SCTP-based communication. (socket initialization
	and send/recv primitives to be used by higher-level network layers)


Once loaded, you will be able to define *"sctp:"* listeners in your script.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None*.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### sctp_port (integer)


The default port to be used for all SCTP related operation. Be careful
		as the default port impacts both the SIP listening part (if no port is
		defined in the SCTP listeners) and the SIP sending part (if the 
		destination SCTP URI has no explicit port).


If you want to change only the listening port for STP, use the port
		option in the SIP listener defintion.


*Default value is 5060.*


```c title="Set sctp_port parameter"
...
modparam("proto_sctp", "sctp_port", 5070)
...
```


## Frequently Asked Questions


**Q: After switching to OpenSIPS 2.1, I'm getting this error:
				"listeners found for protocol sctp, but no module can handle it"**


You need to load the "proto_sctp" module. In your script, make sure
			you do a **loadmodule "proto_sctp.so"**
			after setting the **[mpath](https://docs.opensips.org/manual/2-1/script-coreparameters#mpath)**.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
