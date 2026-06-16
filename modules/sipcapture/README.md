---
title: "SipCapture Module"
description: "Offer a possibility to store incoming/outgoing SIP messages in database."
---

## Admin Guide


### Overview


Offer a possibility to store incoming/outgoing SIP messages in database.


OpenSIPs can capture SIP messages in three mode


- IPIP encapsulation. (ETHHDR+IPHDR+IPHDR+UDPHDR).
- Monitoring/mirroring port.
- Homer encapsulation protocl mode (HEP v1).


The capturing can be turned on/off using fifo commad.


opensipsctl fifo sip_capture on


opensipsctl fifo sip_capture off


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *database module* - mysql, postrgress,
				dbtext, unixodbc...


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (str)


Database URL.


*Default value is "".*


```c title="Set db_url parameter"
...
modparam("sipcapture", "db_url", "mysql://user:passwd@host/dbname")
...
```


#### table_name (str)


Name of the table's name where to store the SIP messages.


*Default value is "sip_capture".*


```c title="Set sip_capture parameter"
...
modparam("sipcapture", "table_name", "homer_capture")
...
```


#### capture_on (integer)


Parameter to enable/disable capture globaly (on(1)/off(0))


*Default value is "0".*


```c title="Set capture_on parameter"
...
modparam("sipcapture", "capture_on", 1)
...
```


#### hep_capture_on (integer)


Parameter to enable/disable capture of HEP (on(1)/off(0))


*Default value is "0".*


```c title="Set hep_capture_on parameter"
...
modparam("sipcapture", "hep_capture_on", 1)
...
```


#### raw_ipip_capture_on (integer)


Parameter to enable/disable IPIP capturing (on(1)/off(0))


*Default value is "0".*


```c title="Set raw_ipip_capture_on parameter"
...
modparam("sipcapture", "raw_ipip_capture_on", 1)
...
```


#### raw_moni_capture_on (integer)


Parameter to enable/disable monitoring/mirroring port capturing (on(1)/off(0))
		Only one mode on raw socket can be enabled! Monitoring port capturing currently 
		supported only on Linux.


*Default value is "0".*


```c title="Set raw_moni_capture_on parameter"
...
modparam("sipcapture", "raw_moni_capture_on", 1)
...
		
```


#### raw_socket_listen (string)


Parameter indicate an listen IP address of RAW socket for IPIP capturing. 
                You can also define a port/portrange for IPIP/Mirroring mode, to capture 
                SIP messages in specific ports:
		"10.0.0.1:5060" - the source/destination port of the SIP message must be equal 5060
		"10.0.0.1:5060-5090" - the source/destination port of the SIP message must be 
		equal or be between 5060 and 5090.
		The port/portrange must be defined if you are planning to
		use mirroring capture! In this case, the part with IP address will be
                ignored, but to make parser happy, use i.e. 10.0.0.0


*Default value is "".*


```c title="Set raw_socket_listen parameter"
...
modparam("sipcapture", "raw_socket_listen", "10.0.0.1:5060-5090")
...
modparam("sipcapture", "raw_socket_listen", "10.0.0.1:5060")
...
```


#### raw_interface (string)


Name of the interface to bind on the raw socket.


*Default value is "".*


```c title="Set raw_socket_listen parameter"
...
modparam("sipcapture", "raw_interface", "eth0")
...
```


#### raw_sock_children (integer)


Parameter define how much children must be created to listen the raw socket.


*Default value is "1".*


```c title="Set raw_socket_listen parameter"
...
modparam("sipcapture", "raw_sock_children", 6)
...
```


#### promiscuous_on (integer)


Parameter to enable/disable promiscuous mode on the raw socket.
		Linux only.


*Default value is "0".*


```c title="Set promiscuous_on parameter"
...
modparam("sipcapture", "promiscuous_on", 1)
...
```


#### raw_moni_bpf_on (integer)


Activate Linux Socket Filter (LSF based on BPF) on the mirroring interface. 
                The structure is defined in linux/filter.h. The default LSF accept a port/portrange
                from the raw_socket_listen param. Currently LSF supported only on Linux.


*Default value is "0".*


```c title="Set raw_moni_bpf_on parameter"
...
modparam("sipcapture", "raw_moni_bpf_on", 1)
...
```


#### capture_node (str)


Name of the capture node.


*Default value is "homer01".*


```c title="Set capture_node parameter"
...
modparam("sipcapture", "capture_node", "homer03")
...
```


### Exported MI Functions


#### sip_capture


Name: *sip_capture*


Parameters:


- capture_mode : turns on/off SIP message capturing.
			Possible values are:

  - on
  - off
The parameter is optional - if missing, the command will
			return the status of the SIP message capturing (as string 
			"on" or "off" ) without changing
			anything.


MI FIFO Command Format:


```c
		:sip_capture:_reply_fifo_file_
		capture_mode
		_empty_line_
		
```


### Database setup


Before running OpenSIPS with sipcapture, you have to setup the database 
		tables where the module will store the data. For that, if the
		table were not created by the installation script or you choose
		to install everything by yourself you can use the sipcapture-create.sql or 
		the sipcapture-st-create.sql SQL script in the database 
		directories in the opensips/scripts folder as template.
		You can also find the complete database documentation on the
		project webpage, [http://www.opensips.org/html/docs/db/db-schema-devel.html](http://www.opensips.org/html/docs/db/db-schema-devel.html).


### Limitation


1. Only one capturing mode on RAW socket is supported: IPIP or monitoring/mirroring port. 
		   Don't activate both at the same time.
		2. By default MySQL doesn't support INSERT DELAYED for partitioning table. You can patch MySQL 
		  (http://bugs.mysql.com/bug.php?id=50393) or use separate tables (pseudo partitioning)
		3. Mirroring port capturing works only on Linux.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
