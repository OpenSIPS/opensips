---
title: "AKA Authentication Vector Diameter Module"
description: "This module is an extension to the *AKA_AUTH* module providing a Diameter AKA AV Manager that implements the Multimedia-Auth-Request and Multimedia-Auth-Answer Diameter commands defined in the *Cx* interface of the *ETSI TS 129 229* specifications in order to fetch a set of authentication..."
---

## Admin Guide


### Overview


This module is an extension to the *AKA_AUTH* module
		providing a Diameter AKA AV Manager that implements the Multimedia-Auth-Request
		and Multimedia-Auth-Answer Diameter commands defined in the
		*Cx* interface of the *ETSI TS 129 229*
		specifications in order to fetch a set of authentication vectors and feed
		them in the AKA authentication process.


When the *AKA_AUTH* module needs a new authentication
		vector to do an *aka_challenge()*, it may require this
		module to fetch a set of authentication vectors for the purpose. The module
		packs the query in a *MAR* (Multimedia-Auth-Request)
		command and sends it to an *HSS* Diameter server. When an
		*MAA* (Multimedia-Auth-Answer) command is received in
		response, the corresponding authentication vectors are gathered and fed back
		to the *AUTH_AKA* engine.


It uses the *AAA_Diameter* module to perform the Diameter
		requests. It may run in both a synchronous and asynchronous mode,
		depending on how the *AUTH_AKA* module performs the query.


### Setup


The module requires an *aaa_diameter* connection to an
		*HSS* Diameter server that implements the
		*Cx* interfaces and is able to provide authentication vectors
		through the Multimedia-Auth-Request and Multimedia-Auth-Answer commands.


The format of the command, along with the required fields can be found in the
		*example/aka_av_diameter.dictionary* file located in the
		module's source directory, as well as in the
		[example diameter commands](#diameter_commands_file) section.


*Note:* the module internals uses the AVPs names
		found in the provided dictionary - changing the file may break the behavior
		of the module.


### Dependencies


#### OpenSIPS Modules


The module depends on the following modules (in the other words
			the listed modules must be loaded before this module):


- *auth_aka* -- AKA Authentication
				module that triggers the AKA authentication process
- *aaa_diameter* -- AAA Diameter
				module that implements the Diameter communication to the
				*HSS* Server.


#### External Libraries or Applications


This module does not depend on any external library.


### Exported Parameters


#### aaa_url (string)


This is the url representing the connection to the AAA server.
		*Note:* Currently the module only supports 
		connections to a Diameter server. The path to the AVPs
		configuration file is also required, otherwise the module will
		not start, or not work properly.


```opensips title="aaa_url parameter usage"
modparam("auth_aaa", "aaa_url", "diameter:freeDiameter.conf;extra-avps-file:/etc/freeDiameter/aka_av_diameter.dictionary")
		
```


#### realm (string)


The Realm used in the Origin Diameter commands.


Default value is "diameter.test".


```opensips title="realm parameter usage"
		
modparam("aka_av_diameter", "realm", "scscf.ims.mnc001.mcc001.3gppnetwork.org")
		
```


#### server_uri (string)


The Server-URI used in the Diameter commands.


If it is left empty, the Server-Name will be created by adding "sip:" in front of the realm
		parameter value
		(e.g. "sip:scscf.ims.mnc001.mcc001.3gppnetwork.org").


```opensips title="server_uri parameter usage"
		
modparam("aka_av_diameter", "server_uri", "sip:scscf.ims.mnc001.mcc001.3gppnetwork.org")
		
```


### Diameter Commands File


File that should be provided to the *aaa_diameter* connection.


```c title="Diameter Commands File Example"
VENDOR 10415 TGPP

ATTRIBUTE Public-Identity                     601 string     10415
ATTRIBUTE Server-Name                         602 string     10415
ATTRIBUTE 3GPP-SIP-Number-Auth-Items          607 unsigned32 10415
ATTRIBUTE 3GPP-SIP-Authentication-Scheme      608 utf8string 10415
ATTRIBUTE 3GPP-SIP-Authenticate               609 hexstring  10415
ATTRIBUTE 3GPP-SIP-Authorization              610 hexstring  10415
ATTRIBUTE 3GPP-SIP-Authentication-Context     611 string     10415
ATTRIBUTE 3GPP-SIP-Item-Number                613 unsigned32 10415
ATTRIBUTE Confidentiality-Key                 625 hexstring  10415
ATTRIBUTE Integrity-Key                       626 hexstring  10415


ATTRIBUTE 3GPP-SIP-Auth-Data-Item             612 grouped    10415
{
	3GPP-SIP-Item-Number | OPTIONAL | 1
	3GPP-SIP-Authentication-Scheme | OPTIONAL | 1
	3GPP-SIP-Authenticate | OPTIONAL | 1
	3GPP-SIP-Authorization | OPTIONAL | 1
	3GPP-SIP-Authentication-Context | OPTIONAL | 1
	Confidentiality-Key | OPTIONAL | 1
	Integrity-Key | OPTIONAL | 1
}

APPLICATION-AUTH 16777216/10415 3GPP Cx

REQUEST 303 Multimedia-Auth Request
{
	Session-Id | REQUIRED | 1
	Origin-Host | REQUIRED | 1
	Origin-Realm | REQUIRED | 1
	Destination-Realm | REQUIRED | 1
	Vendor-Specific-Application-Id | REQUIRED | 1
	Auth-Session-State | REQUIRED | 1
	User-Name | REQUIRED | 1
	Public-Identity | REQUIRED | 1
	3GPP-SIP-Number-Auth-Items | REQUIRED | 1
	3GPP-SIP-Auth-Data-Item | REQUIRED | 1
	Server-Name | REQUIRED | 1
}

ANSWER 303 Multimedia-Auth Answer
{
	Session-Id | REQUIRED | 1
	Origin-Host | REQUIRED | 1
	Origin-Realm | REQUIRED | 1
	Destination-Host | OPTIONAL | 1
	Destination-Realm | OPTIONAL | 1
	Vendor-Specific-Application-Id | REQUIRED | 1
	Auth-Session-State | REQUIRED | 1
	User-Name | REQUIRED | 1
	Public-Identity | REQUIRED | 1
	3GPP-SIP-Number-Auth-Items | REQUIRED | 1
	3GPP-SIP-Auth-Data-Item | REQUIRED | 1
	Result-Code | REQUIRED | 1
}
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
