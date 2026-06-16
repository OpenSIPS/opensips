---
title: "Presence_MWI Module"
description: "The module does specific handling for notify-subscribe message-summary (message waiting indication) events as specified in RFC 3842. It is used with the general event handling module, presence. It constructs and adds message-summary event to it."
---

## Admin Guide


### Overview


The module does specific handling for notify-subscribe
	      message-summary (message waiting indication) events
	      as specified in RFC 3842.
	      It is used with the general event handling module,
   	      presence. It constructs and adds message-summary event to
  	      it.


The module does not currently implement any authorization
	      rules.  It assumes that publish requests are only issued by
	      a voicemail application and subscribe requests only by
	      the owner of voicemail box.  Authorization can thus
	      be easily done by OpenSIPS configuration file before
	      calling handle_publish() and handle_subscribe()
	      functions.


The module implements a simple check of content type
	      application/simple-message-summary:  Content must start
	      with Messages-Waiting status line followed by zero or
	      more lines that consist of tabs and printable ASCII
	      characters.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *presence*.


#### External Libraries or Applications


None.


### Exported Parameters


None.


### Exported Functions


None to be used in configuration file.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
