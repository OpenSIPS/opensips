---
title: "proto_udp Module"
description: "The **proto_udp** module is a built-in transport module which exports the required logic in order to handle UDP-based communication. (socket initialization and send/recv primitives to be used by higher-level network layers)"
---

## Admin Guide


### Overview


The **proto_udp** module is a built-in transport module which exports the required
	logic in order to handle UDP-based communication. (socket initialization
	and send/recv primitives to be used by higher-level network layers)


Once loaded, you will be able to define *"udp:"* listeners in your script.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None*.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### udp_port (integer)


The default port to be used for all UDP related operation. Be careful
		as the default port impacts both the SIP listening part (if no port is
		defined in the UDP listeners) and the SIP sending part (if the 
		destination URI has no explicit port).


If you want to change only the listening port for UDP, use the port
		option in the SIP listener defintion.


*Default value is 5060.*


```opensips title="Set udp_port parameter"
...
modparam("proto_udp", "udp_port", 5070)
...
```


## Frequently Asked Questions


**Q: After switching to OpenSIPS 2.1, I'm getting this error:
				"listeners found for protocol udp, but no module can handle it"**


You need to load the "proto_udp" module. In your script, make sure
			you do a **loadmodule "proto_udp.so"** after setting the **[mpath](https://docs.opensips.org/manual/2-1/script-coreparameters#mpath)**.


**Q: I cannot locate "proto_udp.so". Where is it?**


The "proto_udp" and "proto_tcp" modules are simply built into
				the opensips binary by default. They are not available as shared
				libraries, but look like modules for code consistency reasons.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
