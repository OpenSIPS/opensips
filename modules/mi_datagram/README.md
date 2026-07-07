---
title: "mi_datagram Module"
description: "This is a module which provides a UNIX/UDP SOCKET transport layer implementation for the Management Interface."
---

## Admin Guide


### Overview


This is a module which provides a UNIX/UDP SOCKET transport layer 
		implementation for the Management Interface.


### DATAGRAM command syntax


The external commands issued via DATAGRAM interface must follow the
		following syntax:


- *request = first_line (argument '\n')**
- *first_line = ':'command_name':''\n'*
- *argument = (arg_name '::' (arg_value)? ) | (arg_value)*
- *arg_name = not-quoted_string*
- *arg_value = not-quoted_string | '"' string '"'*
- *not-quoted_string = string - {',",\n,\r}*


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### socket_name (string)


The name of a UNIX SOCKET or an IP address. 
		The UNIX datagram or UDP socket will be created using this parameter 
		in order to read the external commands.
		Both IPv4 and IPv6 are supported.


*Default value is NONE.*


```opensips title="Set socket_name parameter"
...
modparam("mi_datagram", "socket_name", "/tmp/opensips.sock")
...
modparam("mi_datagram", "socket_name", "udp:192.168.2.133:8080")
...
```


#### children_count (string)


The number of child processes to be created. Each child process
		will be a datagram server.


*Default value is 1.*


```opensips title="Set children_count parameter"
...
modparam("mi_datagram", "children_count", 3)
...
```


#### unix_socket_mode (integer)


Permission to be used for creating the listening UNIX datagram socket. 
		Not necessary for a UDP socket.
		It follows the UNIX conventions.


*Default value is 0660 (rw-rw----).*


```opensips title="Set unix_socket_mode parameter"
...
modparam("mi_datagram", "unix_socket_mode", 0600)
...
```


#### unix_socket_group (integer) unix_socket_group (string)


Group to be used for creating the listening UNIX socket.


*Default value is the inherited one.*


```opensips title="Set unix_socket_group parameter"
...
modparam("mi_datagram", "unix_socket_group", 0)
modparam("mi_datagram", "unix_socket_group", "root")
...
```


#### unix_socket_user (integer) unix_socket_group (string)


User to be used for creating the listening UNIX socket.


*Default value is the inherited one.*


```opensips title="Set unix_socket_user parameter"
...
modparam("mi_datagram", "unix_socket_user", 0)
modparam("mi_datagram", "unix_socket_user", "root")
...
```


#### socket_timeout (integer)


The reply will expire after trying to sent it for socket_timeout 
		milliseconds.


*Default value is 2000.*


```opensips title="Set socket_timeout parameter"
...
modparam("mi_datagram", "socket_timeout", 2000)
...
```


#### reply_indent (string)


Strings to be used for line indentation. As the MI data structure 
		is tree oriendeted, the depth level will printed as indentation.


*Default value is ""\t" (TAB)".*


```opensips title="Set reply_indent parameter"
...
modparam("mi_datagram", "reply_indent", "    ")
...
```


### Exported Functions


No function exported to be used from configuration file.


### Example


This is an example showing the DATAGRAM format for the 
		"get_statistics dialog: tm:" MI commad:
		response.


```c title="DATAGRAM request"
:get_statistics:\n
dialog:\n
tm:\n
```


## Frequently Asked Questions


**Q: Both UNIX and UDP type of socket can be created 
			simultaneusly?**


This version supports only one kind of socket at a time.
			If there are more than one value set for socket_name the last one
			will take effect.


**Q: Is there a limit in the datagram request's size?**


The maximum length of a datagram request or reply is 65457 bytes.


**Q: Where can I find more about OpenSIPS?**


Take a look at [http://www.opensips.org/](http://www.opensips.org/).


**Q: Where can I post a question about this module?**


First at all check if your question was already answered on one of
			our mailing lists:

E-mails regarding any stable OpenSIPS release should be sent to 
			users@lists.opensips.org and e-mails regarding development versions
			should be sent to devel@lists.opensips.org.

If you want to keep the mail private, send it to 
			users@lists.opensips.org.


**Q: How can I report a bug?**


Please follow the guidelines provided at:
			[https://github.com/OpenSIPS/opensips/issues](https://github.com/OpenSIPS/opensips/issues).


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
