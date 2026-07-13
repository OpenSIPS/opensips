---
title: "mi_xmlrpc Module"
description: "This module implements a xmlrpc server that handles xmlrpc requests and generates xmlrpc responses. When a xmlrpc message is received a default method is executed."
---

## Admin Guide


### Overview


This module implements a xmlrpc server that handles xmlrpc requests and
generates xmlrpc responses. When a xmlrpc message is received a default 
method is executed.


At first, it looks up the MI command. If found it parses the called 
procedure's parameters into a MI tree and the command is executed. A 
MI reply tree is returned that is formatted back in xmlrpc. The 
response is built in two ways - like a string that contains the MI 
tree nodes information (name, values and attributes) or like an array 
whose elements are consisted of each MI tree node stored information.


Implementation of mi_xmlrpc module's xmlrpc server is based on Abyss
XML-RPC server.  Current version of Abyss server
"normalizes" CRLF sequence in received XML-RPC strings
to LF character, which makes it impossible to pass CRLF
sequence from xmlrpc client application to OpenSIPS modules,
such as mi_fifo and pua_mi, that accept requests via MI
transport.  To overcome this limitation mi_xmlrpc module
implements a hack that coverts each LFLF sequence in
received XML-RPC strings to CRLF sequence.


### To-do


Features to be added in the future:


- possibility to select the listening IP address
- multiple ports per IP address


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
running OpenSIPS with this module loaded:


- *libxml*.
- *libxmlrpc-c3* version 0.9.10 - 0.9.42. (using other versions may be dangerous and lead to opensips blocking)
- *libxmlrpc-c3-dev* version 0.9.10 - 0.9.42.


If libxmlrpc-c3[-dev] package is not available on your system, you may
check if packages for your OS are not available on the 
"xmlrpc-c"project 
([http://xmlrpc-c.sourceforge.net/](http://xmlrpc-c.sourceforge.net/)). Otherwise you need
to install the library and devel headers from the sources. In both
cases, keep in mind to use the 0.9.10 version!!.


### Exported Parameters


#### port(integer)


The port number used by the XMLRPX server to listen for incoming 
requests.


*The default value is 8080.*
Ports lower than 1024 are not accepted.


```opensips title="Set port parameter"
...
modparam("mi_xmlrpc", "port", 8000)
...
```


#### log_file(string)


A log file to be used by the internal Abyss html server used by the 
XMLRPX library.


*The default values NONE (no logging).*


```opensips title="Set log_file parameter"
...
modparam("mi_xmlrpc", "log_file", "/var/log/abyss.log")
...
```


#### reply_option (integer)


Given the xmlrpc response specifications that a methodResponse can 
contain a single params section with a single param section, there is 
the possibility to choose between a string built response or an 
array built one.


For a 0 value, a single string parameter will be replied (merging the 
whole response). For non-0 value, each line from the response will be 
encoded as an element into an array of strings.


*The default option is a string built response (0).*


```opensips title="Set reply_option parameter"
...
modparam("mi_xmlrpc", "reply_option", 0)
...
```


#### buffer_size (integer)


It specifies the maximum length of the buffer used to write in the MI 
tree node information in order to build the xmlrpc response.


*The default value is 8192.*


```opensips title="Set reply_option parameter"
...
modparam("mi_xmlrpc", "buffer_size", 8192)
...
```


### Exported Functions


No function exported to be used from configuration file.


### Example


This is an example showing the xmlrpc format for the 
"get_statistics dialog: tm:" MI commad:
response.


```c title="XMLRPC request"
POST /RPC2 HTTP/1.0
Host: 127.0.0.1
Connection: close
User-Agent: OpenSIPg XML_RPC Client
Content-Type: text/xml
Content-Length: 1000

<?xml version="1.0" ?>
<methodCall>
   <methodName>get_statistics</methodName>
   <params>
       <param>
           <value><string>dialog:</string></value>
       </param>
       <param>
           <value><string>tm:</string></value>
       </param>
  </params>
</methodCall>
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
