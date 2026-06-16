---
title: "SIP-I Module"
description: "This module offers the possibility of processing ISDN User Part(ISUP) messages encapsulated in SIP. The available operations are: reading and modifying parameters from an ISUP message, removing or adding new optional parameters, adding an ISUP part to a SIP message body. This is done explicitly v..."
---

## Admin Guide


### Overview


This module offers the possibility of processing ISDN User Part(ISUP) messages encapsulated in SIP. The available operations are: reading and modifying parameters from an ISUP message, removing or adding new optional parameters, adding an ISUP part to a SIP message body. This is done explicitly via script pseudovariables and functions.


The supported ISUP message types are only the ones that can be included in a SIP message according to the SIP-I(SIP with encapsulated ISUP) protocol defined by ITU-T.


The format and specification of the ISUP messages and parameters follow the recomandations from ITU-T Rec. Q.763.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### param_subfield_separator (str)


The character to be used as separator in the subname of the *$isup_param* and *$isup_param_str* pseudovariables between the ISUP parameter name and subfield name.


*Default value is "|".*


```c title="Set param_subfield_separator parameter"
...
modparam("sip_i", "param_subfield_separator", ":")
...
```


#### isup_mime_str (str)


The string to be used for the Content-Type header field of the ISUP MIME body when creating a new ISUP part.


*Default value is "application/ISUP;version=itu-t92+".*


```c title="Set isup_mime_str parameter"
...
modparam("sip_i", "isup_mime_str", "application/ISUP;base=itu-t92+;version=itu-t")
...
```


#### default_part_headers (str)


The default set of headers (fully defined, including the header
		termination) to be pushed into the ISUP part together 
		with the *Content-Type* header.


*Default value is "Content-Disposition:signal;handling=optional\r\n".*


```c title="Set default_part_headers parameter"
...
modparam("sip_i", "default_part_headers", "Content-Disposition:signal;handling=required\r\n")
...
```


#### country_code (str)


Country Code that the first part of the number from
			P-Asserted-Identity is tested against when trying to map the
			Calling Party Number ISUP parameter from SIP by default. If there
			is a match, the value assigned to the Nature of Address Indicator
			subfield is *3*(national), otherwise it is
			*4*(international).


*Default value is "+1".*


```c title="Set country_code parameter"
...
modparam("sip_i", "country_code", "+4")
...
```


### Exported Functions


#### add_isup_part([isup_msg_type][,extra_headers])


Adds a new ISUP part to the SIP message body.


With the exception of some ISUP message types(IAM, REL, ACM, CPG, ANM, CON), the newly added part contains a blank ISUP message(i.e. all mandatory parameters zeroed and no optional ones) and all the required parameters should be set through $isup_param. For the previously mentioned message types, the mandatory parameters and some optional ones are automaticaly set to default values according to basic SIP-ISUP interworking rules from ITU-T Rec. Q.1912.5. This only provides a general and simplified mapping from SIP headers and message type (request method, reply code etc.) to ISUP parameters and you should not base your SIP-ISUP interworking only on this.


Meaning of the parameters is as follows:


- *isup_msg_type (string, optional)* - name of the ISUP message to be added, exactly as it appears in ITU-T Rec. Q.763 or an abbreviation(eg. *IAM* for "Initial address").
- *extra_headers (string, string, optional)* - a chunk of fully defined SIP headers (including header terminatior) to be inserted into the ISUP part next to the *Content-Type* header. It overrides the global module parameter *default_part_headers*. If not specified, the *default_part_headers* value will be used.


If *isup_msg_type* is not explicitly provided, it is automatically deduced from the SIP message as follows:


- INVITE - IAM
- BYE - REL
- 180, 183 - ACM
- 4xx, 5xx - REL
- 200 OK INVITE - ANM
- 200 OK BYE - RLC


The abbreviations that can be given as *isup_msg_type* for each ISUP message type are the following:


- Initial address - *IAM*
- Address complete - *ACM*
- Answer - *ANM*
- Connect - *CON*
- Release - *REL*
- Release complete - *RLC*
- Call progress - *CPG*
- Facility reject - *FRJ*
- Facility accepted - *FAA*
- Facility request - *FAR*
- Confusion - *CFN*
- Suspend - *SUS*
- Resume - *RES*
- Subsequent address - *SAM*
- Forward transfer - *FOT*
- User-to-user information - *USR*
- Network resource management - *NRM*
- Facility - *FAC*
- Identification request - *IRQ*
- Identification response - *IRS*
- Loop prevention - *LPR*
- Application transport - *APT*
- Pre-release information - *PRI*


This function can be used from REQUEST_ROUTE,FAILURE_ROUTE,ONREPLY_ROUTE,LOCAL_ROUTE.


```c title="add_isup_part usage"
...
if ($rs == "183") {
	# Encapsulate a CPG
	add_isup_part("Call progress");
	# set desired parameters
	...
}
...
	
```


### Exported Pseudo-Variables


#### $(isup_param(param_name{sep}subfield_name)[byte_index])


The ISUP parameter named *param_name* of a received or newly added ISUP message can be accessed through this read-write variable. For optional parameters, writing to a *param_name* that does not exist in this ISUP message will insert it. Assigning null to this variable will remove the optional parameter from the message or zeroize the parameter in case of a mandatory one.


The format of the subname for `$isup_param` is the following:


- *param_name* - name of the ISUP parameter as it appears in ITU-T Rec. Q.763
- *sep* - separator, whitespaces allowed before/after
- *subfield_name* - name of the subfield of the ISUP parameter as it appears in ITU-T Rec. Q.763


The ISUP parameter can be addressed in different ways:


- entire parameter - by providing as subname for the varaiable only the ISUP parameter name, allowing access to the contents of the entire parameter as: a hex string(similar to a hex "dump") for read/write, a string alias for writing, or an integer value for read/write; when assigning a hex string, the hex value must be preceded by "0x"; when reading, if string aliases are supported for this parameter, an associated integer value will be returned, otherwise a hex string is returned
- at subfield level - by providing as subname for the varaiable the ISUP parameter name and the subfield name, allowing access to the specific subfield as an integer value or string value(eg. telephone number for parameters such as Called Party Number) for read/write or as a string alias for writing
- at byte level - by providing as subname for the variable the ISUP parameter name and an index, allowing access to the byte with the specified index as an integer value


Addressing at entire parameter level as a hex string and at byte level are supported for all the ISUP parameters defined in the ITU-T Rec. Q.763. Addressing at subfield level is supported only for some ISUP parameters and not all of the subfields of a parameter defined in the ITU Recommandation are supported.


String aliases are not available for all parameters or parameter subfields. Also, not all the possible values of a parameter or parameter subfield have a string alias defined.


For more information on supported subfields and aliases check [subfields aliases](#isup_parameter_subfields_and_string_aliases).


```c title="isup_param usage"
...
	$isup_param(Called Party Number | Nature of address indicator) = 3;
	...
	# use a string alias
	$isup_param(Called Party Number | Numbering plan indicator) = "ISDN";
	...
	$isup_param(Called Party Number | Address signal) = "99991234";
	$isup_param(Nature of connection indicators) = "0x01"
	$isup_param(Calling party's category) = 10;
	...
	# use a string alias
	$isup_param(Transmission Medium Requirement) = "speech";
	...
	# access at byte level
	$(isup_param(Forward Call Indicators)[0]) = 96;
	$(isup_param(Forward Call Indicators)[1]) = 1;
...
	
```


#### $isup_param_str(param_name{sep}subfield_name)


The ISUP parameter named *param_name* of a received or newly added ISUP message can also be accessed through this read-only variable. This variable is similar in usage with *$isup_param* except it will return the string alias for the value when possible.


The format of the subname for `$isup_param_str` is the following:


- *param_name* - name of the ISUP parameter as it appears in ITU-T Rec. Q.763
- *sep* - separator, whitespaces allowed before/after
- *subfield_name* - name of the subfield of the ISUP parameter as it appears in ITU-T Rec. Q.763


```c title="isup_param_str usage"
...
	# may print: "NOA is: national"  
	xlog("NOA is: $isup_param_str(Called Party Number|Nature of address indicator)");
	# may print: "CpN is: 99991234"
	xlog("CpN is: $isup_param_str(Called Party Number|Address signal)");
	# may print: "nature of conn: 0x01"
	xlog("nature of conn: $isup_param_str(Nature of connection indicators)");
	# may print: "Cg cat is: ordinary"
	xlog("$isup_param_str(Calling party's category)");
...
	
```


#### $isup_msg_type


Read-only variable, returns the ISUP message type as string.


```c title="isup_msg_type usage"
...
	# may print: "ISUP msg is: IAM"
	xlog("ISUP msg is: $isup_msg_type");
...
	
```


### Exported script transformations


The module also provides a way for accessing the value of ISUP parameters and their subfields from an ISUP message contained in a arbitrary script variable as opposed to directly from the processed SIP (with encapsulated ISUP) message. This is done by aplying a transformation to a script variable containing the ISUP message body. The value of the original variable is not altered and a corresponding integer or string value (representing an ISUP parameter or subfield as the exact value or string alias) is returned.


#### {isup.param,param_name,[subfield_name]}


The result of this transformation is similar to a read access of the `$isup_param` pseudovariable with the exception that byte level access is not provided.


The parameters for the transformation are:


- *param_name* - name of the ISUP parameter as it appears in ITU-T Rec. Q.763
- *subfield_name* - optional, name of the subfield of the ISUP parameter as it appears in ITU-T Rec. Q.763


```c title="isup.param usage"
...
	# for this example, we take the ISUP body from the received SIP-I message
	$var(isup_body) = $(rb[1]);

	# may print: "NOA is: 3"  
	xlog("NOA is: $(var(isup_body){isup.param, Called Party Number, Nature of address indicator})\n");

	# may print: "CpN is: 99991234"  
	xlog("CpN is: $(var(isup_body){isup.param, Called Party Number, Address signal})\n");

	# may print: "Cg cat is: 10"
	xlog("Cg cat is: $(var(isup_body){isup.param, Calling party's category})\n");

	# may print: "nature of conn: 0x01"
	xlog("nature of conn: $(var(isup_body){isup.param, Nature of connection indicators})\n");
...
		
```


#### {isup.param.str,param_name,[subfield_name]}


The result of this transformation is similar to a read access of the `$isup_param_str` pseudovariable with the exception that byte level access is not provided.


The parameters for the transformation are:


- *param_name* - name of the ISUP parameter as it appears in ITU-T Rec. Q.763
- *subfield_name* - optional, name of the subfield of the ISUP parameter as it appears in ITU-T Rec. Q.763


```c title="isup.param.str usage"
...
	# for this example, we take the ISUP body from the received SIP-I message
	$var(isup_body) = $(rb[1]);

	# may print: "NOA is: national"  
	xlog("NOA is: $(var(isup_body){isup.param.str, Called Party Number, Nature of address indicator})\n");

	# may print: "CpN is: 99991234"  
	xlog("CpN is: $(var(isup_body){isup.param.str, Called Party Number, Address signal})\n");

	# may print: "Cg cat is: ordinary"
	xlog("Cg cat is: $(var(isup_body){isup.param.str, Calling party's category})\n");

	# may print: "nature of conn: 0x01"
	xlog("nature of conn: $(var(isup_body){isup.param.str, Nature of connection indicators})\n");
...
		
```


### ISUP parameter subfields and string aliases


The supported subfields for each ISUP parameter and the string aliases for their values are the following:


- Nature of Connection Indicators

  - Satellite indicator

  - *no satellite* - 0
  - *one satellite* - 1
  - *two satellite* - 2
  - Continuity check indicator

  - *not required* - 0
  - *required* - 1
  - *performed* - 2
  - Echo control device indicator

  - *not included* - 0
  - *included* - 1
- Forward Call Indicators

  - National/international call indicator

  - *national* - 0
  - *international* - 1
  - End-to-end method indicator

  - *no method* - 0
  - *pass-along* - 1
  - *SCCP* - 2
  - *pass-along and SCCP* - 3
  - Interworking indicator

  - *no interworking* - 0
  - *interworking* - 1
  - End-to-end information indicator

  - *no end-to-end* - 0
  - *end-to-end* - 1
  - ISDN user part indicator

  - *not all the way* - 0
  - *all the way* - 1
  - ISDN user part preference indicator

  - *preferred* - 0
  - *not required* - 1
  - *required* - 2
  - ISDN access indicator

  - *non-ISDN* - 0
  - *ISDN* - 1
  - SCCP method indicator

  - *no indication* - 0
  - *connectionless* - 1
  - *connection* - 2
  - *connectionless and connection* - 3
- Optional forward call indicators

  - Closed user group call indicator

  - *non-CUG* - 0
  - *outgoing allowed* - 2
  - *outgoing not allowed* - 3
  - Simple segmentation indicator

  - *no additional information* - 0
  - *additional information* - 1
  - Connected line identity request indicator

  - *not requested* - 0
  - *requested* - 1
- Called Party Number

  - Odd/even indicator

  - *even* - 0
  - *odd* - 1
  - Nature of address indicator

  - *subscriber* - 1
  - *unknown* - 2
  - *national* - 3
  - *international* - 4
  - *network-specific* - 5
  - *network routing national* - 6
  - *network routing network-specific* - 7
  - *network routing with CDN* - 8
  - Internal Network Number indicator

  - *allowed* - 0
  - *not allowed* - 1
  - Numbering plan indicator

  - *ISDN* - 1
  - *Data* - 3
  - *Telex* - 4
  - Address signal
- Calling Party Number

  - Odd/even indicator

  - *even* - 0
  - *odd* - 1
  - Nature of address indicator

  - *subscriber* - 1
  - *unknown* - 2
  - *national* - 3
  - *international* - 4
  - Number Incomplete indicator

  - *complete* - 0
  - *incomplete* - 1
  - Numbering plan indicator

  - *ISDN* - 1
  - *Data* - 3
  - *Telex* - 4
  - Address presentation restricted indicator

  - *allowed* - 0
  - *restricted* - 1
  - *not available* - 2
  - *reserved* - 3
  - Screening indicator

  - *user* - 0
  - *network* - 1
  - Address signal
- Backward Call Indicators

  - Charge indicator

  - *no indication* - 0
  - *no charge* - 1
  - Called party's status indicator

  - *no indication* - 0
  - *subscriber free* - 1
  - *connect* - 2
  - Called party's category indicator

  - *no indication* - 0
  - *ordinary subscriber* - 1
  - *payphone* - 2
  - End to End method indicator

  - *no end-to-end* - 0
  - *pass-along* - 1
  - *SCCP* - 2
  - *pass-along and SCCP* - 3
  - Interworking indicator

  - *no interworking* - 0
  - *interworking* - 1
  - End to End information indicator

  - *no end-to-end* - 0
  - *end-to-end* - 1
  - ISDN user part indicator

  - *not all the way* - 0
  - *all the way* - 1
  - Holding indicator

  - *not requested* - 0
  - *requested* - 1
  - ISDN access indicator

  - *non-ISDN* - 0
  - *ISDN* - 1
  - Echo control device indicator

  - *not included* - 0
  - *included* - 1
  - SCCP method indicator

  - *no indication* - 0
  - *connectionless* - 1
  - *connection* - 2
  - *connectionless and connection* - 3
- Optional Backward Call Indicators

  - In-band information indicator

  - *no indication*- 0
  - *available* - 1
  - Call diversion may occur indicator

  - *no indication* - 0
  - *call diversion* - 1
  - Simple segmentation indicator

  - *no additional information* - 0
  - *additional information* - 1
  - MLPP user indicator

  - *no indication* - 0
  - *MLPP user* - 1
- Connected Number

  - Odd/even indicator

  - *even* - 0
  - *odd* - 1
  - Nature of address indicator

  - *subscriber* - 1
  - *unknown* - 2
  - *national* - 3
  - *international* - 4
  - Numbering plan indicator

  - *ISDN* - 1
  - *Data* - 3
  - *Telex* - 4
  - Address presentation restricted indicator

  - *allowed* - 0
  - *restricted* - 1
  - *not available* - 2
  - Screening indicator

  - *user* - 0
  - *network* - 1
  - Address signal
- Original Called Number

  - Odd/even indicator

  - *even* - 0
  - *odd* - 1
  - Nature of address indicator

  - *subscriber* - 1
  - *unknown* - 2
  - *national* - 3
  - *international* - 4
  - Numbering plan indicator

  - *ISDN* - 1
  - *Data* - 3
  - *Telex* - 4
  - Address presentation restricted indicator

  - *allowed* - 0
  - *restricted* - 1
  - *not available* - 2
  - *reserved* - 3
- Redirecting Number - same as *Original Called Number*
- Redirection Number - same as *Called Party Number*
- Redirection information

  - Redirecting indicator

  - *no redirection* - 0
  - *call rerouted* - 1
  - *call rerouted, all information restricted* - 2
  - *call diverted* - 3
  - *Call diverted, all information restricted* - 4
  - *call rerouted, redirection number restricted* - 5
  - *call diversion, redirection number restricted* - 6
  - Original redirection reason

  - *unknown/not available* - 0
  - *user busy* - 1
  - *no reply* - 2
  - *unconditional* - 3
  - Redirection counter

  - 1
  - 2
  - 3
  - 4
  - 5
  - Redirecting reason

  - *unknown/not available* - 0
  - *user busy* - 1
  - *no reply* - 2
  - *unconditional* - 3
  - *deflection alerting* - 4
  - *deflection response* - 5
  - *mobile not reachable* - 6
- Cause Indicators

  - Location

  - *user* - 0
  - *LPN* - 1
  - *LN* - 2
  - *TN* - 3
  - *RLN* - 4
  - *RPN* - 5
  - *INTL* - 7
  - *BI* - 10
  - Coding standard

  - *ITU-T* - 0
  - *ISO/IEC* - 1
  - *national* - 2
  - *location* - 3
  - Cause value
- Subsequent Number

  - Odd/even indicator

  - *even* - 0
  - *odd* - 1
  - Address signal
- Event Information

  - Event indicator

  - *alerting* - 1
  - *progress* - 2
  - *in-band or pattern* - 3
  - *busy* - 4
  - *no reply* - 5
  - *unconditional* - 6
  - Event presentation restricted indicator

  - *no indication* - 0
  - *restricted* - 1
- Calling Party's Category

  - *unknown* - 0
  - *french* - 1
  - *english* - 2
  - *german* - 3
  - *russian* - 4
  - *spanish* - 5
  - *ordinary* - 10
  - *priority* - 11
  - *data* - 12
  - *test* - 13
  - *payphone* - 15
- Transmission Medium Requirement

  - *speech* - 0
  - *64 kbit/s unrestricted* - 2
  - *3.1 kHz audio* - 3
  - *64 kbit/s preferred* - 6
  - *2 x 64 kbit/s* - 7
  - *384 kbit/s* - 8
  - *1536 kbit/s* - 9
  - *1920 kbit/s* - 10


### Mandatory ISUP parameters


The mandatory parameters(According to ITU-T Rec. Q.763) for each supported ISUP message that requires this are the following:


- Initial address

  - Nature of connection indicators
  - Forward call indicators
  - Calling party's category
  - Transmission medium requirement
  - Called party number
- Address complete

  - Backward call indicators
- Connect

  - Backward call indicators
- Release

  - Cause indicators
- Call progress

  - Event information
- Facility reject

  - Facility indicator

  - Cause indicators
- Facility accepted

  - Facility indicator
- Facility request

  - Facility indicator
- Confusion

  - Cause indicators
- Suspend

  - Suspend/resume indicators
- Resume

  - Suspend/resume indicators
- Subsequent address

  - Subsequent number
- User-to-user information

  - User-to-user information
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
