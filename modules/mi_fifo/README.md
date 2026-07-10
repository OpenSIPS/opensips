---
title: "mi_fifo Module"
description: "This is a module which provides a FIFO transport layer implementation for Management Interface."
---

## Admin Guide


### Overview


This is a module which provides a FIFO transport layer 
implementation for Management Interface. It receives the
command over a FIFO file and returns the output through the
reply_fifo specified.


The module checks every 30 seconds if the FIFO file exists,
and if it was deleted, it recreates it. If one wants to force
the fifo file recreation, it should send a SIGHUP signal to
the MI process PID.


### FIFO command syntax


The external commands issued via FIFO interface must follow the
following syntax:


- *request = first_line argument**
- *first_line = ':'command_name':'reply_fifo'\n'*
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


#### fifo_name (string)


The name of the FIFO file to be created for listening and 
reading external commands.


*Default value is NONE.*


```opensips title="Set fifo_name parameter"
...
modparam("mi_fifo", "fifo_name", "/tmp/opensips_fifo")
...
```


#### fifo_mode (integer)


Permission to be used for creating the listening FIFO file. It 
follows the UNIX conventions.


*Default value is 0660 (rw-rw----).*


```opensips title="Set fifo_mode parameter"
...
modparam("mi_fifo", "fifo_mode", 0600)
...
```


#### fifo_group (integer) fifo_group (string)


Group to be used for creating the listening FIFO file.


*Default value is the inherited one.*


```opensips title="Set fifo_group parameter"
...
modparam("mi_fifo", "fifo_group", 0)
modparam("mi_fifo", "fifo_group", "root")
...
```


#### fifo_user (integer) fifo_group (string)


User to be used for creating the listening FIFO file.


*Default value is the inherited one.*


```opensips title="Set fifo_user parameter"
...
modparam("mi_fifo", "fifo_user", 0)
modparam("mi_fifo", "fifo_user", "root")
...
```


#### reply_dir (string)


Directory to be used for creating the reply FIFO files.


*Default value is "/tmp/"*


```opensips title="Set reply_dir parameter"
...
modparam("mi_fifo", "reply_dir", "/home/opensips/tmp/")
...
```


#### reply_indent (string)


Strings to be used for line indentation. As the MI data structure 
is tree oriendeted, the depth level will printed as indentation.


*Default value is ""\t" (TAB)".*


```opensips title="Set reply_indent parameter"
...
modparam("mi_fifo", "reply_indent", "    ")
...
```


### Exported Functions


No function exported to be used from configuration file.


### Example


This is an example showing the FIFO format for the 
"get_statistics dialog: tm:" MI commad:
response.


```c title="FIFO request"
:get_statistics:reply_fifo\n
dialog:\n
tm:\n
\n
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
