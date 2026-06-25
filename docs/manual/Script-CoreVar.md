---
title: "Core variables"
description: "The OpenSIPS variables can be easily identified in the script as all their names (or notations) starts with the $ sign."
---

**OpenSIPS** provides multiple types of variables to be used in the routing script. The difference between the types of variables comes from:
* *its context* - a variable is attached to a context, like the context of a SIP message, of a SIP transaction or dialog. The variable will be visible all the time within that context (across all the script routes where the context is present)
* *read-write status* - some types of variables are read-only
* *number of values* - some variables may keep multiple values at the same time

The **OpenSIPS** variables can be easily identified in the script as all their names (or notations) starts with the **$** sign.

Syntax:  

The complete syntax for a pseudo variable is: 
`$(`*`<context>`*`name`*`(subname)[index]{transformation}`*`)`

The fields written in italics are optional.
The fields meaning is:
* **name**(mandatory) - the pseudo-variable name(type).  
Ex: var, avp, ru, DLG_status, etc.
* **subname** - the identifier of a certain pv of a given type.  
Ex: hdr(From), avp(name).
* **index** - a pv can store more than one value - it can refer to a list of values. You can access a certain value from the list if you specify its index. You can also specify indexes with negative values, -1 means the last inserted, -2 the value before the previous inserted one.
* **transformation** - a series of processing actions can be applied on pseudo-variable. You can find the whole list of possible transformations [here](Script-Tran.md). The transformations can be cascaded, using the output of one transformation as the input of another.     
* **context** - the context in which the pseudo0variable will be evaluated. Now there are 2 pv contexts: reply and request. The reply context can be used in the failure route to request for the pseudo-variable to be evaluated in the context of the reply message. The request context can be used if in a reply route is desired for the pv to be evaluated in the context of the corresponding request.

Usage examples:
* Only **name**: `$ru`
* **Name** and *'subname*: `$hdr(Contact)`
* **Name** and **index**: `$(ct[0])`
* **Name**, **subname** and **index**: `$(avp(caller_dids)[2])`
* **Context** 
  * `$(<request>ru)` from a reply route will get the Request-URI from the request
  * `$(<reply>hdr(Contact))` context can be used from failure route to access information from the reply 

Types of variables:

* [**script variables**](#script_variables) - as the name says, these variables are strictly bound to the script routes. The variables are visible only in the routing blocks - they are not message or transaction related, but they are process related (script variables will be inherited by script routes executed by the same **OpenSIPS** process).  
Script variables are read write and they can have integer or string values. A script variable can have only a single value. A new assignment (or write operation) will overwrite the existing value.

* [**AVP - Attribute Value Pair**](#avp_variables) - the AVPs are dynamic variables (as name) that can be created - the AVPS are linked to a singular message or transaction (if stateful processing is used). A message or a transaction will initially (when received or created) have an empty list of AVPS attached to it. During the routing script, the script directly or functions called from script may create new AVPS that will automatically attached to the message/transaction. The AVPS will be visible in all routes where any message (reply or request) of the transaction will be processed - branch_route , failure_route, onreply_route (for this last route you need to enable the TM parameter *onreply_avp_mode*).  
AVPs are read write and an existing AVP can be even deleted (removed). An AVP may contain multiple values - a new assignment (or write operation) will add a new value to the AVP; the values are kept in "last added first to be used" order (stack).

* [**pseudo variables**](#pseudo_variables) - pseudo-variables (or PV) provide access to information from the processed SIP message (headers, RURI, transport level info, a.s.o) or from **OpenSIPS** inners (time values, process PID, return code of a function). Depending of what info they provide, the PVs are either bound to the message, either to nothing  (global). Most of the PVs are read-only and only several allow write operations. A PV may return several values or only one, depending of the referred info (if can have multiple values or not).  
Standard PV is read-only and returns a single value (if not otherwise documented).

* [**escape sequences**](#escape_sequences) - escape sequences used to format the strings; they are actually not variables, but rather formatters.

## Script variables

**Naming**: `$var(name)` 

**Hints**:
* if you want to start using a script variable in a route, better initialize it with same value (or reset it), otherwise you may inherit a value from a previous route that was executed by the same process.
* script variables are faster the AVPs, being referenced directly to memory location.
* the value of script variables persists over a **OpenSIPS** process.
* a script value can have only one value.

Example of usage:

```bash

$var(a) = 2;  # sets the value of variable 'a' to integer '2'
$var(a) = "2";  # sets the value of variable 'a' to string '2'
$var(a) = 3 + (7&(~2)); # arithmetic and bitwise operation
$var(a) = "sip:" + $au + "@" + $fd; # compose a value from authentication username and From URI domain

# using a script variable for tests
if( [ $var(a) & 4 ] ) {
  xlog("var a has third bit set\n");
}

```

Setting a variable to NULL is actually initializing the value to integer '0'. Script variables don't have NULL value.

## AVP variables

**Naming**: `$avp(name)` or `$(avp(name)[N])`

When using the index "N" you can force the AVP to return a certain value (the N-th value). If no index is given, the first value will be returned.

**Hints**:
* to enable AVPs in onreply_route, use "modparam("tm", "onreply_avp_mode", 1)"
* if multiple values are used for a single AVP, the values are index in revert order than added
* AVPs are part of the transaction context, so they will be visible everywhere where the transaction is present.
* the value of an AVP can be deleted

Example of usage:
* Transaction persistence example
```c

# enable avps in onreply route
modparam("tm", "onreply_avp_mode", 1)
...
route{
...
$avp(tmp) = $Ts ; # store the current time (at request processing)
...
t_onreply("1");
t_relay();
...
}

onreply_route[1] {
	if (t_check_status("200")) {
		# calculate the setup time
		$var(setup_time) = $Ts - $avp(tmp);
	}
}

```

* Multilple values example
```bash

$avp(demo) = "one";
# we have a single value
$avp(demo) = "two";
# we have two values ("two","one")
$avp(demo) = "three";
# we have three values ("three","two","one")

xlog("accessing values with no index: $avp(demo)\n");
# this will print the first value, which is the last added value -> "three"

xlog("accessing values with no index: $(avp(demo)[2])\n");
# this will print the index 2 value (third one), -> "one"

# remove the last value of the avp; if there is only one value, the AVP itself will be destroyed
$avp(demo) = NULL;

# delete all values and destroy the AVP
avp_delete("$avp(demo)/g");

# delete the value located at a certain index 
$(avp(demo)[1]) = NULL;

#overwrite the value at a certain index
$(avp(demo)[0]) = "zero";

```

The **AVPOPS** module provides a lot of useful functions to operate AVPs (like checking values, pushing values into different other locations, deleting AVPs, etc).

## Pseudo Variables

**Naming**: `$name`

**Hints**:
* the PV tokens can be given as parameters to different script functions and they will be replaced with a value before the execution of the function.
* most of PVs are made available by **OpenSIPS** core, but there are also module exporting PV (to make available info specific to that module) - check the modules documentation.

Predefined (provided by core) PVs are listed in alphabetical order.

### URI in SIP Request's P-Asserted-Identity header - $ai

`$ai` - reference to URI in request's P-Asserted-Identity header (see RFC 3325)

### Authentication Digest URI - $adu

`$adu` - URI from Authorization or Proxy-Authorization header. This URI is used when calculating the HTTP Digest Response.

### Authentication realm - $ar

`$ar` - realm from Authorization or Proxy-Authorization header

### Auth username user - $au

`$au` - user part of username from Authorization or Proxy-Authorization header

### Auth username domain - $ad

`$ad` - domain part of username from Authorization or Proxy-Authorization header

### Auth nonce - $an

`$an` - the nonce from Authorization or Proxy-Authorization header

### Auth response - $auth.resp

`$auth.resp` - the authentication response from Authorization or Proxy-Authorization header

### Auth nonce - $auth.nonce

`$auth.nonce` - the nonce string from Authorization or Proxy-Authorization header

### Auth opaque - $auth.opaque

`$auth.opaque` - the opaque string from Authorization or Proxy-Authorization header

### Auth algorithm - $auth.alg

`$auth.alg` - the algorithm string from Authorization or Proxy-Authorization header

	
### Auth QOP - $auth.qop

`$auth.qop` - the value of qop parameter from Authorization or Proxy-Authorization header

### Auth nonce count (nc) - $auth.nc

`$auth.nc` - the value of nonce count parameter from Authorization or Proxy-Authorization header

### Auth whole username - $aU

`$aU` - whole username from Authorization or Proxy-Authorization header

### Acc username - $Au

`$Au` - username for accounting purposes. It's a selective pseudo variable (inherited from acc module). It returns `$au` if exits or From username otherwise.

### Argument options - $argv

`$argv` - provides access to command line arguments specified with '-o' option.
Examples:
```text

   # for option '-o foo=0'
   xlog("foo is $argv(foo) \n");

```

### Branch - $branch

`$branch` - this variable is used for creating new branches by writing into it the value of a SIP URI.
Examples:
```text

   # creates a new branch
   $branch = "sip:new@doamin.org";
   # print its URI
   xlog("last added branch has URI $(branch(uri)[-1]) \n");

```

### Branch fields - $branch

`$branch()` - this variable provides read/write access to all fields/attributes of an already existing branch (priorly created with append_branch() ). The fields of the branch are:
* uri - the RURI of the branch  (string value)
* duri - destination URI of the branch (outbound proxy of the branch)  (string value)
* q - q value of the branch (int value)
* path - the PATH string for this branch (string value)
* flags - the branch flags of this branch (int value)
* socket - the local socket to be used for relaying this branch (string value)
The variable accepts also index `$(branch(uri)[1])` for accessing a specific branch (multiple branches can be defined at a moment). The index starts from 0 (first branch). If the index is negative, it is considered the n-th branch from the end ( index -1 means the last branch).  

To get all branches, use the * index - `$(branch(uri)[*])`.  

Examples:
```text

   # creates the first branch
   append_branch();
   # creates the second branch
   force_send_socket(udp:192.168.1.10:5060);
   $du = "sip:192.168.2.10";
   append_branch("sip:foo@bar.com","0.5");

   # display branches
   xlog("----- branch 0: $(branch(uri)[0]) , $(branch(q)[0]), $(branch(duri)[0]), $(branch(path)[0]), $(branch(flags)[0]), $(branch(socket)[0]) \n");
   xlog("----- branch 1: $(branch(uri)[1]) , $(branch(q)[1]), $(branch(duri)[1]), $(branch(path)[1]), $(branch(flags)[1]), $(branch(socket)[1]) \n");

   # do some changes over the branches
   $branch(uri) = "sip:user@domain.ro";   # set URI for the first branch
   $(branch(q)[0]) = 1000;  # set to 1.00 for the first branch
   $(branch(socket)[1]) = NULL;  # reset the socket of the second branch
   $branch(duri) = NULL;  # reset the destination URI or the first branch

```

> [!IMPORTANT]
> It is R/W variable (you can assign values to it from routing logic)


### Call-Id - $ci

`$ci` - reference to body of call-id header

### Content-Length - $cl

`$cl` - reference to body of content-length header

### CSeq number - $cs

`$cs` - reference to cseq number from cseq header

### Contact instance - $ct

`$ct` - reference to contact instance/body from the contact header. A contact instance is  display_name + URI + contact_params. As a Contact header may contain multiple Contact instances and a message may contain multiple Contact headers, an index was added to the `$ct` variable:
* `$ct` -first contact instance from message
* `$(ct[n])` - the n-th contact instance form the beginning of message, starting with index 0
* `$(ct[-n])` - the n-th contact instance form the end of the message, starting with index -1 (the last contact instance)

### Fields of a contact instance - $ct.fields

`$ct.fields()` - reference to the fields of a contact instance/body (see above). Supported fields are:
* name - display name
* uri - contact uri
* q  - q param (value only)
* expires - expires param (value only) 
* methods - methods param (value only)
* received - received param (value only)
* params - all params (including names)

Examples:
* `$ct.fields(uri)` - the URI of the first contact instance
* `$(ct.fields(name)[1])` - the display name of the second contact instance

### Content-Type - $cT

`$cT` - reference to body of content-type header

### Domain of destination URI - $dd

`$dd` - reference to domain of destination uri

> [!IMPORTANT]
> It is R/W variable (you can assign values to it from routing logic)


### Diversion header URI - $di

`$di` - reference to Diversion header URI

### Diversion "privacy" parameter - $dip

`$dip` - reference to Diversion header "privacy" parameter value

### Diversion "reason" parameter - $dir

`$dir` - reference to Diversion header "reason" parameter value

### Port of destination URI - $dp

`$dp` - reference to port of destination uri

> [!IMPORTANT]
> It is R/W variable (you can assign values to it from routing logic)


### Transport protocol of destination URI - $dP

`$dP` - reference to transport protocol of destination uri

### Destination set - $ds

`$ds` - reference to destination set

### Destination URI - $du

`$du` - reference to destination uri (outbound proxy to be used for sending the request)
If loose_route() returns TRUE a destination uri is set according to the first Route header.

> [!IMPORTANT]
> It is R/W variable (you can assign values to it from routing logic)


### Error class - $err.class

`$err.class` - the class of error (now is '1' for parsing errors)

### Error level - $err.level

`$err.level` - severity level for the error

### Error info - $err.info

`$err.info` - text describing the error

### Error reply code - $err.rcode

`$err.rcode` - recommended reply code

### Error reply reason - $err.rreason

`$err.rreason` - recommended reply reason phrase

### From URI domain - $fd

`$fd` - reference to domain in URI of 'From' header

### From display name - $fn

`$fn` - reference to display name of 'From' header

### Forced socket - $fs

`$fs` - reference to the forced socket for message sending (if any) in the form proto:ip:port

> [!IMPORTANT]
> It is R/W variable (you can assign values to it routing script)


### From tag - $ft

`$ft` - reference to tag parameter of 'From' header

### From URI - $fu

`$fu` - reference to URI of 'From' header

### From URI username - $fU

`$fU` - reference to username in URI of 'From' header

### SIP message buffer - $mb

`$mb` - reference to SIP message buffer

### Message Flags - $mf

`$mf` - reference to message/transaction flags set for current SIP request

> [!IMPORTANT]
> It is R/W variable (you can assign values to it from routing logic)


### Message Flags in hexadecimal - $mF

`$mF` -reference to message/transaction flags set for current SIP request in hexa

> [!IMPORTANT]
> It is R/W variable (you can assign values to it from routing logic)


### SIP message ID - $mi

`$mi` - reference to SIP message id

### SIP message length - $ml

`$ml` - reference to SIP message length

### Domain in SIP Request's original URI - $od

`$od` - reference to domain in request's original R-URI

### Port of SIP request's original URI - $op

`$op` - reference to port of original R-URI

### Transport protocol of SIP request original URI - $oP

`$oP` - reference to transport protocol of original R-URI

### SIP Request's original URI - $ou

`$ou` - reference to request's original URI

### Username in SIP Request's original URI - $oU

`$oU` - reference to username in request's original URI

### Domain in SIP Request's P-Preferred-Identity header URI - $pd

`$pd` - reference to domain in request's P-Preferred-Identity header URI (see RFC 3325)

### Display Name in SIP Request's P-Preferred-Identity header - $pn

`$pn` - reference to Display Name in request's P-Preferred-Identity header (see RFC 3325)

### Process id - $pp

`$pp` - reference to process id (pid)

### Protocol of received message - $pr
`$pr` or `$proto` - protocol of received message (UDP, TCP, TLS, SCTP)

### User in SIP Request's P-Preferred-Identity header URI - $pU

`$pU` - reference to user in request's P-Preferred-Identity header URI (see RFC 3325)

### URI in SIP Request's P-Preferred-Identity header - $pu

`$pu` - reference to URI in request's P-Preferred-Identity header (see RFC 3325)

### Domain in SIP Request's URI - $rd

`$rd` - reference to domain in request's URI

> [!IMPORTANT]
> It is R/W variable (you can assign values to it routing script)


### Body of request/reply - $rb

`$rb` - reference to message body

### Returned code - $rc

`$rc` - reference to returned code by last invoked function

`$retcode` - same as `$rc`

### Remote-Party-ID header URI - $re

`$re` - reference to Remote-Party-ID header URI

### SIP request's method - $rm

`$rm` - reference to request's method

### SIP request's port - $rp

`$rp` - reference to port of R-URI

> [!IMPORTANT]
> It is R/W variable (you can assign values to it routing script)


### Transport protocol of SIP request URI - $rP

`$rP` - reference to transport protocol of R-URI

### SIP reply's reason - $rr

`$rr` - reference to reply's reason

### SIP reply's status - $rs

`$rs` - reference to reply's status

### Refer-to URI - $rt

`$rt` - reference to URI of refer-to header

### SIP Request's URI - $ru

`$ru` - reference to request's URI

> [!IMPORTANT]
> It is R/W variable (you can assign values to it routing script)


### Username in SIP Request's URI - $rU

`$rU` - reference to username in request's URI

> [!IMPORTANT]
> It is R/W variable (you can assign values to it routing script)


### Q value of the SIP Request's URI - $ru_q

`$ru_q` - reference to q value of the R-URI

> [!IMPORTANT]
> It is R/W variable (you can assign values to it routing script)


### Received IP address - $Ri

`$Ri` - reference to IP address of the interface where the request has been received

### Received port - $Rp

`$Rp` - reference to the port where the message was received

### Script flags - $sf

`$sf` - reference to script flags - decimal output

> [!IMPORTANT]
> It is R/W variable (you can assign values to it from routing logic)


### Script flags - $sF

`$sF` - reference to script flags - hexa output

> [!IMPORTANT]
> It is R/W variable (you can assign values to it from routing logic)


### IP source address - $si

`$si` - reference to IP source address of the message

### Source port - $sp

`$sp` - reference to the source port of the message

### To URI Domain - $td

`$td` - reference to domain in URI of 'To' header

### To display name - $tn

`$tn` - reference to display name of 'To' header

### To tag - $tt

`$tt` - reference to tag parameter of 'To' header

### To URI - $tu

`$tu` - reference to URI of 'To' header

### To URI Username - $tU

`$tU` - reference to username in URI of 'To' header

### Formatted date and time - $time

`$time(format)` - returns the string formatted time according to UNIX date (see: **man date**).

### Branch index - $T_branch_idx

`$T_branch_idx` - the index (starting with 1 for the first branch) of the branch for which is executed the branch_route[]. If used outside of branch_route[] block, the value is '0'. This is exported by TM module.

### String formatted time - $Tf

`$Tf` - reference string formatted time

### Current unix time stamp in seconds - $Ts

`$Ts` - reference to current unix time stamp in seconds

### Current microseconds of the current second - $Tsm

`$Tsm` - reference to current microseconds of the current second

### Startup unix time stamp - $TS

`$TS` - reference to startup unix time stamp

### User agent header - $ua

`$ua` - reference to user agent header field

### SIP Headers - $hdr

`$(hdr(name)[N])` - represents the body of the N-th header identified by 'name'. If [N] is omitted then the body of the first header is printed. The first header is got when N=0, for the second N=1, a.s.o. To print the last header of that type, use -1, no other negative values are supported now. No white spaces are allowed inside the specifier (before `}`, before or after `{`, [, ] symbols). When N='*', all headers of that type are printed.

The module should identify most of compact header names (the ones recognized by **OpenSIPS** which should be all at this moment), if not, the compact form has to be specified explicitly. It is recommended to use dedicated specifiers for headers (e.g., %ua for user agent header), if they are available -- they are faster.

`$(hdrcnt(name))` -- returns number of headers of type given by 'name'. Uses same rules for specifying header names as `$hdr(name)` above. Many headers (e.g., Via, Path, Record-Route) may appear more than once in the message. This variable returns the number of headers of a given type. 

Note that some headers (e.g., Path) may be joined together with commas and appear as a single header line. This variable counts the number of header lines, not header values. 

For message fragment below, `$hdrcnt(Path)` will have value 2 and `$(hdr(Path)[0])` will have value **`<a.com>`**:
```text

    Path: <a.com>
    Path: <b.com>

```

For message fragment below, `$hdrcnt(Path)` will have value 1 and `$(hdr(Path)[0])` will have value **`<a.com>`,`<b.com>`**:
```text

    Path: <a.com>,<b.com>

```

Note that both examples above are semantically equivalent but the variables take on different values.


## Escape Sequences

These sequences are exported, and mainly used, by xlog module to print messages in many colors (foreground and background) using escape sequences. 

### Foreground and background colors - $C

`$C(xy)` - reference to an escape sequence. ¿x¿ represents the foreground color and ¿y¿ represents the background color.

Colors could be:

* x : default color of the terminal
* s : Black
* r : Red
* g : Green
* y : Yellow
* b : Blue
* p : Purple
* c : Cyan
* w : White 

### Examples

A few examples of usage.

```text

...
route {
...
    $avp(uuid)="caller_id";
    $avp(tmp)= $avp(uuid) + ": " + $fu;
    xdbg("$(C(bg))avp(tmp)$(C(xx)) [$avp(tmp)] $(C(br))cseq$(C(xx))=[$hdr(cseq)]\n");
...
}
...

```
