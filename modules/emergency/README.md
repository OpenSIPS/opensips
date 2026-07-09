---
title: "Emergency Call Module"
description: "The emergency module provides emergency call treatment for OpenSIPS, following the architecture i2 specification of the American entity NENA. (National Emergency Number Association). The NENA solution routes the emergency call to a closer gateway (ESGW) and this forward the call to a PSAP(call ce..."
---

## Admin Guide


### Overview


The emergency module provides emergency call treatment for OpenSIPS, following the architecture i2 specification of the American entity NENA. (National Emergency Number Association). The NENA solution routes the emergency call to a closer gateway (ESGW) and this forward the call to a PSAP(call center responsible for answering emergency calls) that serves the area of ​​the caller, so this must consider the handling and transport of caller location information in the SIP protocol.

To attend this new need the NENA solution consists of several servers: to determine the location (LIS), to determine the area of emergency treatment depending on location (VPC), validate location stored (VDB), among others. Along with these elements have the SIP Proxy that interface with these servers to route the call. The OpenSIPS can do the functions of these SIP Proxy through this emergency module, may perform the function of a Call Server, Redirect Server and Routing Proxy, depending on the proposed scenario:


- scenario I:  The VSP(Voip Serve Provide) retains control over the processing of emergency calls. The VSP’s Call Server implements the v2 interface that queries the VPC for routing information, with this information selects the proper ESGW, if normal routing fails routes calls via the PSTN using the contingency number(LRO).
- scenario II: The VSP transfers all emergency calls to Routing Proxy provider using the v6 SIP interface. Once done transfer the VSP no longer participates in the call. The Routing Proxy provider implements the v2 interface, queries the VPC for for routing information, and forwards the call.
- scenario III: The VSP requests routing information for the Redirect Server operator, but remains part of the call. The Redirect Server obtains the routing information from the VPC. It returns the call to the VSP’s Call Server with routing information in the SIP Contact Header. The Call Server selects the proper ESGW based on this information.


The emergency module allows the OpenSIPS play the role of a Call Server, a Proxy or Redirect Server Routing within the scenarios presented depending on how it is configured.


1.2. Scenario I: The VSP that originating the call is the same as handle the call and sends the routing information request to the VPC. 

		The emergency module through emergency_call() command  will check if the INVITE received is an emergency call. In this case, the OpenSIPS will get caller location information from specific headers and body in the INVITE. With this information along configuration parameters defined for this module, the opensips implements the v2 interface that queries the VPC for routing information (i.e., ESQK, LRO, and either the ERT or ESGWRI), selects the proper ESGW based on the ESGWRI. When the call ends the OpenSIPS receives BYE request, it warns the VPC for clean your data that is based on the call.	
		The opensips through failure() command  will try to route the calls via the PSTN using a national contingency number(LRO) if normal routing fails.


1.3.Scenario II: The VSP transfers the call to a Routing Server provider

		The emergency module through emergency_call() command  will check if the INVITE received is an emergency call. In this case, it will forward the call to a Routing Proxy that will interface with the VPC and route the call.		
		The OpenSIPS will leave the call, and all the request of this dialog received by the opensips will be forwarded to the Routing Server.

 		OpenSIPS.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *Dialog - Dialoge module.*.
- *RR - Record-Route module.*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
running OpenSIPS with this module loaded:


- *libcurl*.


### Exported Parameters


#### db_url (string)


The database url must be specified.


*Default value is "NULL".*


```opensips title="Setting the db_url parameter"
...
modparam("emergency", "db_url", "mysql://opensips:opensipsrw@localhost/opensips”)
...
		
```


#### db_table_routing (string)


The name of the db table storing routing information to emergency calls.


*Default value is "emergency_routing".*


```opensips title="Setting the db_table_routing parameter"
...
modparam("emergency", "db_table_routing", "emergency_routing")
...
		
```


#### db_table_report (string)


The name of the db table that stores the emergency call report.


*Default value is "emergency_report".*


```opensips title="Setting the db_table_report parameter"
...
modparam("emergency", "db_table_report", "emergency_report")
...
		
```


#### proxy_hole (integer)


This parameter define what role the opensips will take to treat emergency   
   		call:

	    0 – The opensips is the Call Server in scenario I or the Routing Proxy in 
	        scenario II depend on flag_third_enterprise parameter. In this hole the 
	        opensips implements the V2 interface, directly queries the VPC for 
	        ESGWRI/ESQK, selects the proper ESGW given the ESGWRI and routes calls 
	        Via the PSTN using the LRO if routing fails.

	    1 – The opensips is the Call Server in scenario II that sends the INVITE on 
	        emergency call to a Routing Proxy provider. The Routing Proxy provider 
	        implements the V2 interface.

	    2 - The opensips is the Call Server in scenario III that sends the INVITE on 
	 		emergency call to a Redirect Server. The Redirect Server obtains the 
	 		ESGWRI/ESQK from the VPC. It returns the call to the opensips with the 
	 		ESGWRI/ESQK in the header contact in the SIP response. The opensips  
	 		selects the proper ESGW based on the ESGWRI.

	    3 - The opensips is the Redirect Proxy in scenario III that receives the 
	        INVITE on emergency call from Call Server. The Redirect Server obtains 
	        the ESGWRI/ESQK from the VPC and sends in the SIP 3xx response to the 
	        Call Server.


*Default value is "0".*


```opensips title="Setting the proxy_hole parameter"
...
modparam("emergency", "proxy_hole", 0))
...
		
```


#### flag_third_enterprise (integer)


Indicates whether OpenSIPS is the VSP Call Server in Scenario I    
    (flag_third_enterprise = 0) or is the Routing Proxy of a third company in 
    scenario II (flag_third_enterprise = 1).


*Default value is "0".*


```opensips title="Setting the flag_third_enterprise parameter"
...
modparam("emergency", "flag_third_enterprise ", 0)
...
		
```


#### url_vpc (string)


The VPC url that opensips request the routing information to emergency 
   		call. This VPC url has IP:Port format


*Default value is "empty string".*


```opensips title="Setting the url_vpc parameter"
...
modparam("emergency", "url_vpc", “192.168.0.103:5060”)
...
		
```


#### emergency_codes (string)


Local emergency number. Opensips uses this number to recognize a emergency 
   		call beyond the username default defined by RFC-5031 (urn:service.sos.).
   		Along with the number should be given a brief description about this code.        
   		The format is code_number-description. It can register multiple emergency 
   		numbers.


*Default value is "NULLg".*


```opensips title="Setting the emergency_codes parameter"
...
modparam("emergency", "emergency_codes", “911-us emegency code”)
...
		
```


#### vsp_organization_name (string)


The vsp_organization_name is VSP company name’s. VSP is the caller's voice 
   		service provider. This parameter is optional field in the NENA v2 interface
   		(call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the vsp_organization_name parameter"
...
modparam("emergency", "vsp_organization_name", “Exemple provider VSP”)
...
		
```


#### vsp_hostname (string)


The vsp_hostname is VSP hostname’s. VSP is the caller's voice service provider. 
   		This parameter is  mandatory field in the NENA v2 interface(call server - VPC) 
   		in cases where the VSP is not the same entity as the one requesting routing 
   		information over the v2 interface, otherwise it is optional.


*Default value is "NULL".*


```opensips title="Setting the vsp_hostname parameter"
...
modparam("emergency", "vsp_hostname", “exemple_vsp.com”)
...
		
```


#### vsp_nena_id (string)


The nena-id is the NENA administered company identifier (NENA Company ID) 
   		of VSP. VSP is the caller's voice service provider. This parameter is 
   		optional field in the NENA v2 interface(call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the vsp_nena_id parameter"
...
modparam("emergency", "vsp_nena_id", “nena1”)
...
		
```


#### vsp_contact (string)


The contact is a telephone number by which the VSP operator can be reached 
   		24 hours a day, 7 days a week. VSP is the caller's voice service provider. 
   		This parameter is  mandatory field in the NENA v2interface (call server - VPC) 
   		in cases where the VSP is not the same entity the one requesting routing 
   		information over the v2 interface, otherwise it is optional.


*Default value is "NULL".*


```opensips title="Setting the vsp_contact parameter"
...
modparam("emergency", " vsp_contact", “tel:+398348975439823”)
...
		
```


#### vsp_cert_uri (string)


The cert-uri provides a means of directly obtaining the VESA(Valid 
   		Emergency Services Authority) issued certificate for the VSP. VSP is 
   		the caller's voice service provider. This parameter is optional 
   		field in the NENA v2 interface(call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the vsp_cert_uri parameter"
...
modparam("emergency", " vsp_cert_uri",“https://cs34.exam.com/certificate.crt”)
...
		
```


#### vpc_organization_name (string)


The vpc_organization_name is VPC company name’s. VPC is the routing  
    information provider to emengency call. This parameter is optional field in 
    the NENA v2 interface(call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the vpc_organization_name parameter"
...
modparam("emergency", " vpc_organization_name", “Exemple VPC”)
...
		
```


#### vpc_hostname (string)


The vpc_hostname is VSP hostname’s. VPC is the routing information provider 
    to emengency call. This parameter is optional field in the NENA v2 interface 
    (call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the vpc_hostname parameter"
...
modparam("emergency", "vpc_hostname", “exemple_vpc.com”)
...
		
```


#### vpc_nena_id (string)


The vpc_nena-id is the NENA administered company identifier (NENA Company 
    ID) of the VPC. VPC is the routing information provider to emengency call. 
    This parameter is optional field in the NENA v2 interface(call server – VPC).


*Default value is "NULL".*


```opensips title="Setting the vpc_nena_id parameter"
...
modparam("emergency", "vpc_nena_id", “nena2”)
...
		
```


#### vpc_contact (string)


The vpc_contact is a telephone number by which the directly VPC operator 
    can be reached 24 hours a day, 7 days a week. VPC is the routing information 
    provider to emengency call. This parameter is optional field in the NENA v2
    interface(call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the source_contact parameter"
...
modparam("emergency", "vpc_contact", “tel:+398348975439823”)
...
		
```


#### vpc_cert_uri (string)


The vpc_cert_uri_vpc provides a means of directly obtaining the VESA(Valid 
    Emergency Services Authority) issued certificate for the VPC. VPC is the 
    Routing information provider to emengency call. This parameter is optional
    field in the NENA v2 interface(call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the vpc_cert_uri parameter"
...
modparam("emergency", "vpc_cert_uri",“https://cs98.examvpc.com/certificate.crt”)
...
		
```


#### source_organization_name (string)


The source_organization_name is Source company name’s. Source is node 
   		directly requesting emergency call routing from the VPC. This parameter is  
   		optional field in the NENA v2 interface(call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the source_organization_name parameter"
...
modparam("emergency", "source_organization_name", “Exemple Routing Source”)
...
		
```


#### source_hostname (string)


The sorce_hostname is Source hostname’s. Source is node directly requesting 
    emergency call routing from the VPC. This parameter is  mandatory field in 
    the NENA v2 interface(call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the source_hostname parameter"
...
modparam("emergency", "source_hostname", “exemple_source.com”)
...
		
```


#### source_nena_id (string)


The source_nena-id is the NENA administered company identifier (NENA Company 
   		ID) of the source. Source is node directly requesting emergency call routing 
   		from the VPC. This parameter is optional field in the NENA v2 interface
   		(call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the source_nena_id parameter"
...
modparam("emergency", "source_nena_id", “nena3”)
...
		
```


#### source_contact (string)


The source_contact is a telephone number by which the directly source operator 
   		can be reached 24 hours a day, 7 days a week. Source is node directly 
   		requesting emergency call routing from the VPC. This parameter is  mandatory 
   		field in the NENA v2 interface(call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the source_contact parameter"
...
modparam("emergency", "source_contact", “tel:+398348975439823”)
...
		
```


#### source_cert_uri (string)


The source_cert_uri provides a means of directly obtaining the VESA(Valid 
   		Emergency Services Authority) issued certificate for the source. Source is 
   		node directly requesting emergency call routing from the VPC. This parameter 
   		is optional field in the NENA v2 interface(call server - VPC).


*Default value is "NULL".*


```opensips title="Setting the source_cert_uri parameter"
...
modparam("emergency","source_cert_uri",“https://cs67.exsource.com/certificate.crt”
...
		
```


#### timer_interval (interger)


Sets the time interval polling to make the copy in memory of the 
   		db_table_routing.


*Default value is "10".*


```opensips title="Setting the timer_interval parameter"
...
modparam("emergency","timer_interval",20)
...
		
```


#### contingency_hostname (string)


The contingency_hostname is the url of the server que will route the call 
   		to the PSTN using the number of contingency.


*Default value is "NULL".*


```opensips title="Setting the contingency_hostname parameter"
...
modparam("emergency","contingency_hostname",“176.34,29.102:5060”)
...
		
```


#### emergency_call_server (string)


The emergency_call_server is the url of the Routing Proxy/Redirect Server
that will handle  the emergency call in cenario II. Its is mandatory if Opensips 
act as Call Server in scenario II (proxy_hole = 1 and flag_third_enterprise = 0) 
or Call Server in scenario III (proxy_hole = 2).


*Default value is "NULL".*


```opensips title="Setting the emergency_call_server parameter"
...
modparam("emergency","emergency_call_server",“124.78.29.123:5060”)
...
		
```


#### Exported Functions


##### emergency_call()


Checks whether the incoming call is an emergency call, case it is treats, and  
   		routes the call to the destination determined by VPC.

   		The function returns true if is a emergency call and the treat was Ok.


This function can be used from the *REQUEST* routes.


```opensips title="emergency_call() usage"
...
# Example of treat of emergency call

    if (emergency_call()){

        xlog("emergency call\n");
        t_on_failure("emergency_call");
        t_relay();
        exit;

  	}
...
		
```


##### failure()


This function is used when trying to route the emergency call to the 
   		destination specified by the VPC and doesn't work, then uses this function to 
   		make one last attempt for a contingency number.

   		The function returns true if the contingency treat was OK.


This function can be used from the *FAILURE* routes.


```opensips title="failure() usage"
...
# Example od treat of contingency in emergency call

    if (failure()) {
        if (!t_relay()) {
           send_reply("500","Internal Error");
        };
        exit;
    }
...
		
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
