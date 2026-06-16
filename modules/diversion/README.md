---
title: "Diversion Module"
description: "The module implements the Diversion extensions as per draft-levy-sip-diversion-08. The diversion extensions are useful in various scenarios involving call forwarding. Typically one needs to communicate the original recipient of the call to the PSTN gateway and this is what the diversio..."
---

## Admin Guide


### Overview


The module implements the Diversion extensions as per 
		draft-levy-sip-diversion-08.  The
		diversion extensions are useful in various scenarios involving call
		forwarding. Typically one needs to communicate the original recipient 
		of the call to the PSTN gateway and this is what the diversion 
		extensions can be used for.


> [!WARNING]
> The draft-levy-sip-diversion-08 is expired!! See
		[IETF I-D tracker](https://datatracker.ietf.org/public/idindex.cgi?command=id_detail&and;id=6002).


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### suffix (string)


The suffix to be appended to the end of the header field. You can use 
		the parameter to specify additional parameters to be added to the 
		header field, see the example.


Default value is "" (empty string).


```c title="suffix usage"
modparam("diversion", "suffix", ";privacy=full")
```


### Exported Functions


#### add_diversion(reason, [uri], [counter])


The function adds a new diversion header field before any other 
		existing Diversion header field in the message (the newly added 
		Diversion header field will become the topmost Diversion header field).
		The inbound (without any modifications done by the
		proxy server) Request-URI will be used as the Diversion URI.


Meaning of the parameters is as follows:


- *reason* (string) - The reason string to be added 
			as the reason parameter
- *uri* (string, optional) - The URI to be added in the header. If missing
			    the unchanged RURI from the original message will be used.
- *counter* (int, optional) - Diversion counter to be added to the header, as defined by the standard.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```c title="add_diversion usage"
...
add_diversion("user-busy");
...
```


### Diversion Example


The following example shows a Diversion header field added to 
			INVITE message. The original INVITE received by the user agent 
			of sip:bob@sip.org is:


```c
INVITE sip:bob@sip.org SIP/2.0
Via: SIP/2.0/UDP 1.2.3.4:5060
From: "mark" <sip:mark@sip.org>;tag=ldgheoihege
To: "Bob" <sip:bob@sip.org>
Call-ID: adgasdkgjhkjha@1.2.3.4
CSeq: 3 INVITE
Contact: <sip:mark@1.2.3.4>
Content-Length: 0
```


The INVITE message is diverted by the user agent 
			of sip:bob@sip.org because the user was talking to someone else 
			and the new destination is sip:alice@sip.org :


```c
INVITE sip:alice@sip.org SIP/2.0
Via: SIP/2.0/UDP 5.6.7.8:5060
Via: SIP/2.0/UDP 1.2.3.4:5060
From: "mark" <sip:mark@sip.org>;tag=ldgheoihege
To: "Bob" <sip:bob@sip.org>
Call-ID: adgasdkgjhkjha@1.2.3.4
CSeq: 3 INVITE
Diversion: <sip:bob@sip.org>;reason=user-busy
Contact: <sip:mark@1.2.3.4>
Content-Length: 0
```


## Developer Guide


According to the specification new Diversion header field should be inserted as the topmost
	Diversion header field in the message, that means before any other existing Diversion header
	field in the message. In addition to that, `add_diversion` function can be called several times and each time
	it should insert the new Diversion header field as the topmost one.


In order to implement this, add_diversion function creates the anchor in data_lump lists as
	a static variable to ensure that the next call of the function will use the same anchor and
	would insert new Diversion headers before the one created in the previous execution. To my
	knowledge this is the only way of inserting the diversion header field before any other
	created in previous runs of the function.


The anchor kept this way is only valid for a single message and we have to invalidate it
	when another message is being processed. For this reason, the function also stores the id of
	the message in another static variable and compares the value of that variable with the id
	of the SIP message being processed. If they differ then the anchor will be invalidated and
	the function creates a new one.


The following code snippet shows the code that invalidates the anchor, new anchor will be
	created when the `anchor` variable is set to 0.


```c
static inline int add_diversion_helper(struct sip_msg* msg, str* s)
{
    static struct lump* anchor = 0;
    static int msg_id = 0;

    if (msg_id != msg->id) {
        msg_id = msg->id;
        anchor = 0;
    }
...
}
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
