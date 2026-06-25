---
title: "Core Variables"
description: "The OpenSIPS variables can be easily identified in the script as all their names (or notations) start with the $ sign."
---

**OpenSIPS** provides multiple types of variables to be used in the routing script. The difference between the types of variables comes from:
* *its context* - a variable is attached to a context, like the context of a SIP message, of a SIP transaction or dialog. The variable will be visible all the time within that context (across all the script routes where the context is present)
* *read-write status* - some types of variables are read-only
* *number of values* - some variables may keep multiple values at the same time

The **OpenSIPS** variables can be easily identified in the script as all their names (or notations) start with the **$** sign.

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

* [**script variables**](#script_variables) - as the name says, these variables are strictly bound to the script routes.

* [**AVP - Attribute Value Pair**](#avp_variables) - the AVPs are dynamic variables (as name) that can be created and attached to a SIP message or transaction (if stateful processing is used). So, you may see them as transaction level variables.

* [**reference variables**](#reference_variables) - variables to provide access to information from the current context - the current SIP message, transaction, dialog, or from the current process (non SIP information).

* [**escape sequences**](#escape_sequences) - escape sequences used to format the strings; they are actually not variables, but rather formatters.



## Script variables

**Naming**: `$var(name)`

These variables are attached to the script, being persistent to the whole execution of a top route (including all its sub-routes). Once the execution of the top route ended, the script variables are lost, not to be used again. Also, be careful and initialize them when used for the first time (in a top route) as you may inherite garbage.
Script variables are read write and they can have integer or string values.
A script variable can only hold a single value. A new assignment (or write operation) will overwrite the existing value.


**Hints**:
* if you want to start using a script variable in a route, better initialize it with same value (or reset it), otherwise you may inherit a value from a previous route that was executed by the same process.
* a script variable can only hold one value.

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


## AVP variables

**Naming**: `$avp(name)` or `$(avp(name)[N])`

A message or a transaction will initially (when received or created) have an empty list of AVPS attached to it. During the routing script, the script directly or functions called from script may create new AVPS that will automatically attached to the message/transaction. The AVPS will be visible in all routes where any message (reply or request) of the transaction will be processed - `branch_route` , `failure_route`, `onreply_route` (for this last route you need to enable the TM parameter *onreply_avp_mode*).
AVPs are read write and an existing AVP can be even deleted (removed).
An AVP may contain multiple values - a new assignment (or write operation) will add a new value to the AVP; the values are kept in "last added first to be used" order (stack).

When using the index "N" you can force the AVP to return a certain value (the N-th value). If no index is given, the first value will be returned.
A special index **append** is defined to allow you to add a new value at the end of the list (at the bottom of the stack) - `$(avp(name)[append])` = "last value";


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
t_onreply("handle_reply");
t_relay();
...
}

onreply_route[handle_reply] {
	if (t_check_status("200")) {
		# calculate the setup time
		$var(setup_time) = $Ts - $avp(tmp);
	}
}

```

* Multiple values example
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

# remove the first value of the avp (lastly added one); if there is only one value, the AVP itself will be destroyed
$avp(demo) = NULL;

# delete all values and destroy the AVP
$avp(demo) := NULL;

# delete the value located at a certain index 
$(avp(demo)[1]) = NULL;

# overwrite the value at a certain index
$(avp(demo)[0]) = "zero";

```



## Reference Variables

**Naming**: `$name`

They provide access to information from the SIP message/transaction/dialog or OpenSIPS internals.
For example, a reference variable may allow access to the processed SIP message (headers, RURI, transport level info, and so on) or from **OpenSIPS** internals (time values, process PID, return code of a function). Depending of what info they provide, the PVs are either bound to the message, either to nothing  (global).
Most of the reference variables are read-only and only several allow write operations. The reference variables may return several values or only one, depending of the referred info (if can have multiple values or not).  
Standard reference variables are read-only and return a single value (if not otherwise documented).

**Hints**:
* most of reference variables are made available by **OpenSIPS** core, but there are also module exporting such variables (to make available info specific to that module) - check the modules documentation.
* the reference variables are also known as *pseudo-variables* or *PV*. This is an old terminology.

Predefined (provided by core) PVs are listed in alphabetical order:

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

### Auth response  - $auth.resp

`$auth.resp` - the authentication response from Authorization or Proxy-Authorization header

### Auth nonce  - $auth.nonce

`$auth.nonce` - the nonce string from Authorization or Proxy-Authorization header

### Auth cnonce - $auth.cnonce

`$auth.cnonce` - the client nonce string from Authorization or Proxy-Authorization header

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

`$Au` - username for accounting purposes. It's a selective pseudo variable (inherited from acc module). It returns `$au` if it exists or From username otherwise.

### Argument options - $argv

`$argv` - provides access to command line arguments specified with '-o' option.
Examples:
```text

   # for option '-o foo=0'
   xlog("foo is $argv(foo) \n");

```

### Authorize Challenge Algorithm - $challenge.algorithm

`$challenge.algorithm` - the algorithm value taken from the WWW-Authorize or Proxy-Authorize header.

### Authorize Challenge Realm - $challenge.realm

`$challenge.realm` - the realm value taken from the WWW-Authorize or Proxy-Authorize header.

### Authorize Challenge Nonce - $challenge.nonce

`$challenge.nonce` - the nonce value taken from the WWW-Authorize or Proxy-Authorize header.

### Authorize Challenge Opaque - $challenge.opaque

`$challenge.opaque` - the opaque value taken from the WWW-Authorize or Proxy-Authorize header.

### Authorize Challenge QOP - $challenge.qop

`$challenge.qop` - the qop value taken from the WWW-Authorize or Proxy-Authorize header.

### Authorize Challenge IK - $challenge.ik

`$challenge.ik` - the ik value taken from the WWW-Authorize or Proxy-Authorize header.

### Authorize Challenge CK - $challenge.ck

`$challenge.ck` - the ck value taken from the WWW-Authorize or Proxy-Authorize header.

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

### Fields of a contact instance - $ct.fields(field)

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

`$cT` - reference to body of Content-Type header and also the content-type headers inside a multi-part body
* `$cT` - the main Content-Type of the message; the one inside the headers
* `$(cT[n])` - the **n**-th Content-Type inside a multi-part body from the beginning of message, starting with index 0
* `$(cT[-n])` - the **n**-th Content-Type inside a multi-part body from the end of the message, starting with index -1 (the last contact instance)
* `$(cT[*])` - all the Content-Type headers including the main one and the ones from the multi-part body

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

Alias: `$duri`

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

Alias: `$from.domain`

### From display name - $fn

`$fn` - reference to display name of 'From' header

### From tag - $ft

`$ft` - reference to tag parameter of 'From' header

### From URI - $fu

`$fu` - reference to URI of 'From' header

Alias: `$from`

### From URI username - $fU

`$fU` - reference to username in URI of 'From' header

Alias: `$from.user`

### OpenSIPS Log level - $log_level

`$log_level` - changes the log level for the current process ; the log level can be set to a new value (see [possible values](Script-CoreParameters.md#log_level) or it can be reset back to the global log level.
This function is very helpful if you are tracing and debugging only a specific piece of code. 

Example of usage:

```text
log_level= -1 # errors only
.....
{
......
$log_level = 4; # set the debug level of the current process to DBG
uac_replace_from(....);
$log_level = NULL; # reset the log level of the current process to its default level
.......
}
```

### SIP message buffer - $mb

`$mb` - reference to SIP message buffer

### Message Flags - $mf

`$mf` - displays a list with the message/transaction flags set for the current SIP request

### SIP message ID - $mi

`$mi` - reference to SIP message id

### SIP message length - $ml

`$ml` - reference to SIP message length

### Message branch - $msg.branch

`$msg.branch` - similar to [`$branch`](#branch), this variable is used for creating new message branches by writing into it the value of a SIP URI. By reading this variable, you get the SIP URI of the current/last added branch (or of the RURI branch if no additional branch was added so far).
```text

   # creates a new branch
   $msg.branch = "sip:new@domain.org";
   # print its URI
   xlog("last added branch has URI $msg.branch \n");

```

### SIP URI of a message branch - $msg.branch.uri

`$msg.branch.uri` -  gives read / write access over the SIP URI (as string) of an existing message branch. The message branches are created via [append_msg_branch()](Script-CoreFunctions.md#append_branch) core function or by various modules (like "registrar" module). The message branches are consumed by the TM "t_relay()" function (they are converted to TM branches).  

The variable supports indexing - it starts from 0, meaning the RURI (or message) branch. The newly added branches will start from 1. So the branch 0 exists all
the time, there is no need to create it. If no index is specified, the current/last added branch (or of the RURI branch if no additional branch was added so far) will be considered. Negative values are also accepted, meaning indexing from the last branch ( -1 is the latest/higher branch) to the RURI branch. An ***** / ALL index will return the comma separated list with the values from all branches.  

The variable can be used in REQUEST and FAILURE routes.
```text

   # creates a new branch
   $msg.branch = "sip:new@domain.org";
   # change its URI
   $msg.branch.uri = "sip:new_new@domain.org"
   # change its URI of RURI branch
   $(msg.branch.uri[0]) = "sip:new_RURI@domain.org"

```

### Destination URI of a message branch - $msg.branch.duri

`$msg.branch.duri` -  100% similar to [`$msg.branch.uri`](#msg.branch.uri), but operating with the Destination-URI value of the message branch.

### PATH of a message branch - $msg.branch.path

`$msg.branch.path` -  100% similar to [`$msg.branch.uri`](#msg.branch.uri), but operating with the PATH value of the message branch.

### Q of a message branch - $msg.branch.q

`$msg.branch.q` -  100% similar to [`$msg.branch.uri`](#msg.branch.uri), but operating with the Q value of the message branch.

### Flags of a message branch - $msg.branch.flags

`$msg.branch.flags` -  100% similar to [`$msg.branch.uri`](#msg.branch.uri), but operating with list (comma separated) of per-branch flags (which are set for the branch).

### SIP socket of a message branch - $msg.branch.socket

`$msg.branch.socket` -  100% similar to [`$msg.branch.uri`](#msg.branch.uri), but operating with the (forced) socket value of the message branch.

### A flag of a message branch - $msg.branch.flag()

`$msg.branch.flag()` -  similar to [`$msg.branch.uri`](#msg.branch.uri), but operating over a single branch flag (for the current branch).  

The accepted values are 0 for FALSE, positive non-zero for TRUE. The returned values are 0 for FALSE and 1 for TRUE.  

> [!NOTE]
> the */ALL index cannot be used here.

```text

   # creates a new branch
   $msg.branch = "sip:new@domain.org";
   # set the "pstn" named flag for this branch
   $msg.branch.flag(pstn) = 1;
   $msg.branch.flag(foo) = 1;
   # print all the set flags
   xlog("Flags are <$msg.branch.flags>\n");

```

### An attribute of a message branch - $msg.branch.attr()

`$msg.branch.attr()` -  similar to [`$msg.branch.uri`](#msg.branch.uri), but operating over a single branch attribute (attached to the current branch).  

An attribute can have whatever name (no need to be pre-defined) and it can have a single value (at a time), string or integer.  

> [!NOTE]
> the */ALL index cannot be used here.

```text

   # creates a new branch
   $msg.branch = "sip:new@domain.org";
   # set the "pstn" named flag for this branch
   $msg.branch.attr(name) = "one";
   $msg.branch.attr(num) = 5;

```

### Index of the last message branch - $msg.branch.last_idx

`$msg.branch.last_idx` -  returns the index of the last message branch. IF no additional branches were added, it will return 0, the index of the RURI branch. Then the returned value will get incremented with each append_msg_branch().  

### Message flag - $msg.flag

`$msg.flag(flag_name)` - this variable provides read/write access to the value of a single certain message flag (identified by name). The values accepted for writing are 1 (set) and 0 (unset). The returned values are 1/"true" (set) and 0/"false" (unset).
```text

  setflag("X");
  xlog("---- flag value is $msg.flag(X) \n");
  $msg.flag(X) = off;
  xlog("---- flag value is $msg.flag(X) \n");

```

### Message is request  - $msg.is_request

`$msg.is_request` - this variable tells if the current SIP message is a request or not. The returned values are 1/"true" (request) and 0/"false" (reply).
```text

  xlog("---- this message is a request:  $msg.is_request \n");
  if ( $msg.is_request )
    xlog("---- yes, it is a request\n");

```

### Message type - $msg.type

`$msg.type` - this variable returns the type of the current  message. The returned values are "request" (request) or "reply" (reply).
```text

  xlog("---- this message is a SIP $msg.type \n");

```

### Domain in SIP Request's original URI - $od

`$od` - reference to domain in request's original R-URI

### Port of SIP request's original URI - $op

`$op` - reference to port of original R-URI

### Transport protocol of SIP request original URI - $oP

`$oP` - reference to transport protocol of original R-URI

### SIP Request's original URI - $ou

`$ou` - reference to request's original URI

Alias: `$ouri`

### Username in SIP Request's original URI - $oU

`$oU` - reference to username in request's original URI

### Path header - $path

`$path` - reference to the Path header body.

### Route parameter - $param
`$param(idx)` - retrieves the parameters of the route. The index can be an integer, or a pseudo-variable (index starts at 1).  

Example:
```c

   route {
      ...
      $var(debug) = "DBUG:"
      route(PRINT_VAR, $var(debug), "param value");
      ...
   }

   route[PRINT_VAR] {
      $var(index) = 2;
      xlog("$param(1): The parameter value is <$param($var(index))>\n");
   }

```

### Domain in SIP Request's P-Preferred-Identity header URI - $pd

`$pd` - reference to domain in request's P-Preferred-Identity header URI (see RFC 3325)

### Proxy Protocol from transport layer - $proxy_protocol
`$proxy_protocol(field)` - retrieves Proxy Protocol information from the transport layer. Supported fields are: **src_ip**, **src_port**, **dst_ip**, **dst_port**, **af**  

Example:
```text

   route {
      ...
      if ($proxy_protocol(af) != NULL)
          xlog("$proxy_protocol(src_ip):$proxy_protocol(src_port) -> $proxy_protocol(dst_ip):$proxy_protocol(dst_port)\n");
      ...
   }

```

### Display Name in SIP Request's P-Preferred-Identity header - $pn

`$pn` - reference to Display Name in request's P-Preferred-Identity header (see RFC 3325)

### Process id - $pp

`$pp` - reference to process id (pid)

### User in SIP Request's P-Preferred-Identity header URI - $pU

`$pU` - reference to user in request's P-Preferred-Identity header URI (see RFC 3325)

### URI in SIP Request's P-Preferred-Identity header - $pu

`$pu` - reference to URI in request's P-Preferred-Identity header (see RFC 3325)

### Domain in SIP Request's URI - $rd

`$rd` - reference to domain in request's URI

Alias: `$ruri.domain`

> [!IMPORTANT]
> It is R/W variable (you can assign values to it routing script)


### Body of request/reply - $rb

`$rb` - reference to the body or a body part of the SIP message
* `$rb` - the whole body of the message (with all the parts)
* `$(rb[*])` - same as `$rb`
* `$(rb[n])` - the n-th body belonging to a multi-part body from the beginning of message, starting with index 0
* `$(rb[-n])` - the n-th body belonging to a multi-part body from the end of the message, starting with index -1 (the last contact instance)
* `$rb(application/sdp)`   - get the first SDP body part
* `$(rb(application/isup)[-1])`  - get the last ISUP body part

### Returned code - $rc

`$rc` - reference to returned code by last invoked function

`$retcode` - same as `$rc`

### Remote-Party-ID header URI - $re

`$re` - reference to Remote-Party-ID header URI

### Return value - $return

`$return` - Returns the value of the previously executed route.

The variable receives an index, starting with 0, indicating the return value that needs to be read.

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

Alias: `$ruri`

> [!IMPORTANT]
> It is R/W variable (you can assign values to it routing script)


### Username in SIP Request's URI - $rU

`$rU` - reference to username in request's URI

Alias: `$ruri.user`

> [!IMPORTANT]
> It is R/W variable (you can assign values to it routing script)


### Q value of the SIP Request's URI - $ru_q

`$ru_q` - reference to q value of the R-URI

> [!IMPORTANT]
> It is R/W variable (you can assign values to it routing script)


### SDP body - $sdp

`$sdp` - Read/Write reference to the SDP body of the current SIP message

```bash

# READ operation on the SIP msg SDP
$sdp

# WRITE operation (assign a new SDP)
$sdp = $var(rtpengine_sdp);

# READ operation on the SIP reply SDP
$(<reply>sdp)

# WRITE operation (assign a new SDP to SIP reply)
$(<reply>sdp) = $var(rtpengine_sdp);

```

### SDP body line - $sdp.line

`$sdp.line` - Read/Write reference to SDP body lines, with filtering support

```bash

# Fetch the 1st, 2nd, 3rd, etc. attribute line (starting with "a=")
$sdp.line(a=)         # fetch first "a=" line
$sdp.line(a=[0])      # equivalent, "a=" line at index 0
$sdp.line(a=ptime[1]) # "a=ptime" line at index 1
$sdp.line(a=[100])    # will likely yield NULL

# Token-based filtering, inside a line
$sdp.line(m=audio[1])         # m=audio 27292 RTP/AVP 9 8 0 2 102 100 99 101
$sdp.line(m=audio[1]/[0])     # audio
$sdp.line(m=audio[1]/[1])     # 27292
$sdp.line(m=audio[1]/[2])     # RTP/AVP
$sdp.line(m=audio[1]/[10])    # 101
$sdp.line(m=audio[1]/[11])    # NULL
$sdp.line(m=audio[1]/RTP)         # RTP/AVP
$sdp.line(m=audio[1]/RTP\/AVP)    # RTP/AVP
$sdp.line(m=audio[1]/RTP\/AVP[0]) # RTP/AVP
$sdp.line(m=audio[1]/RTP\/AVP[1]) # NULL
$sdp.line(m=audio[1]/RTQ)         # NULL

```

### SDP body line - $sdp.stream

`$sdp.stream` - Read/Write reference to SDP body streams, with filtering support

```bash

# Within a desired stream, you can first filter by line...
$sdp.stream(/a=ptime);         # first “a=ptime” line from Stream #0 ("m=", matching any stream type)
$sdp.stream([1]/a=ptime);      # first “a=ptime” line from Stream #1 ("m=", matching any stream type))
$sdp.stream(audio[1]/a=ptime); # first “a=ptime” line from Audio Stream #1 ("m=audio...")
$sdp.stream(a[1]/a=ptime);     # first “a=ptime” line from Audio Stream #1 ("m=a...")
$sdp.stream(video[1]/a=nortpproxy) = NULL;  # delete entire line starting with "a=nortpproxy" from Video Stream #1
$sdp.stream(v[1]/a=nortpproxy:/[0]) = "yes";   # set first "a=nortpproxy" line "yes" value, in Video Stream #1

# ... and, additionally, by token
$sdp.stream(video[1]/a=fmtp:115/bitrate=) = 48000; # set "bitrate=" to 48000, under "a=fmtp:115" line #0, as part of Video Stream #1
$sdp.stream(video[1]/a=fmtp:115[3]) = NULL; # delete the 4th occurrence (if any) of "a=fmtp:115" line, but only within Video Stream #1
$sdp.stream(video[1]/a=fmtp:115/bitrate=) = 48000; # set "bitrate=" to 48000, under "a=fmtp:115" line #0, as part of Video Stream #1

```

### SDP body session - $sdp.session

`$sdp.session` - Read/Write reference to the SDP body session, with filtering support

```bash

# Within the SDP session (i.e. until the 1st "m=" line), you can first filter by line...
$sdp.session(a=ptime);            # 1st “a=ptime” line at Session level
$sdp.session(a=ptime[0]);         # same as above
$sdp.session(a=ptime[1]);         # 2nd “a=ptime” line at Session level
$sdp.session(a=ptime[0]) = NULL;  # delete 1st “a=ptime” line at Session level

# ... but also filter and edit by token:
$sdp.session(a=rtpmap/telephone-event\/) = "8000";  # Match 1st "a=rtpmap" line which describes telephone-event at Session level, and force bitrate to 8000

```

### SDP stream index - $sdp.stream.idx

`$sdp.stream.idx` - Read-Only reference to the index of the matched SDP stream.  Yields NULL on no-match.

This variable is especially useful in order to match a line having one specific attribute (e.g. "the rtpmap= line for PCMU codec"), then changing a different attribute within the same stream.  Example:

```text

$var(line_idx) = $sdp.stream.idx(video/a=fmtp/packetization-mode=); # locate index of first "a=fmtp" line, containing a packetization-mode= attribute
$var(data) = $sdp.line([$var(line_idx)]); # grab the full line data
... perform processing on that line ...
$sdp.line([$var(line_idx)]) = $var(data); # re-write the line

```

### IP source address - $si

`$si` - reference to IP source address of the message

Alias: `$src_ip`

### Socket inbound - $socket_in / $socket_in(field)

`$socket_in` - read-only variable to get the description (proto:ip:port format) of the inbound socket (used for receiving the message).
  

The variable also offers detailed read-only access to various attributes/sub-fields of the socket, as  `$socket_in()`. The sub-fields of the socket are:
* ip - the IP part of the socket
* port - the port part of the socket
* proto - the name of the protocol of the socket (as "UDP", "TCP", etc)
* advertised_ip - the advertised IP part of the socket (it may be NULL if no advertising is done on this particular socket)
* advertised_port - the advertised port part of the socket (it may be NULL if no advertising is done on this particular socket)
* tag - the socket internal tag/alias 
* anycast - if the socket uses an anycast IP or not (returns 0 if not, 1 if yes)
* af - the address family of the socket's IP. It's value is "INET" if IPv4 or "INET6" if IPv6.
For more details on the meaning of these sub-fields, please also read about the [socket definition](Script-CoreParameters.md#shm_memlog_size).

### Socket outbound - $socket_out / $socket_out(field)

`$socket_out` - read-write variable for reading or changing the outbound socket of the message. Originally (before being written/changed) it will return the same socket description as [`$socket_in`](#socket_in) (the inbound socket will be used as outbound socket also). In addition, it also supports the `forced` sub-field, which returns a socket description only if a socket had been explicitly forced; thus, as opposed to the regular [`$socket_out`](#socket_out), if no socket had explicitly been forced, the variable returns NULL.

  

The variable also offers detailed read-only access to various attributes/sub-fields of the socket, as  `$socket_out()`. **It provides the same sub-fields as the [`$socket_in`](#socket_in) variable.**

```text

   $socket_out = "udp:11.11.11.11:5060";
   xlog("The outbound port is $socket_out(port)\n");

```

### Source port - $sp

`$sp` - reference to the source port of the message

### To URI Domain - $td

`$td` - reference to domain in URI of 'To' header

Alias: `$to.domain`

### To display name - $tn

`$tn` - reference to display name of 'To' header

### To tag - $tt

`$tt` - reference to tag parameter of 'To' header

### To URI - $tu

`$tu` - reference to URI of 'To' header

Alias: `$to`

### To URI Username - $tU

`$tU` - reference to username in URI of 'To' header

Alias: `$to.user`

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

`$(hdr(name)[N])` - represents the body of the N-th header identified by 'name'. If [N] is omitted then the body of the first header is printed. The first header is retrieved when N=0, for the second N=1, and so on. To print the last header of that type, use -1, no other negative values are supported now. No white spaces are allowed inside the specifier (before `}`, before or after `{`, [, ] symbols). When N='*', all headers of that type are printed.

The module should identify most of compact header names (the ones recognized by **OpenSIPS** which should be all at this moment), if not, the compact form has to be specified explicitly. It is recommended to use dedicated specifiers for headers (e.g., %ua for user agent header), if they are available -- they are faster.

`$(hdr_name[N])` - returns the name of the N-th header. The first header name is obtained for N=0, the second for N=1, and so on. To print the last header name use -1, the second-to-last -2 and so on. No white spaces are allowed inside the specifier (before `}`, before or after `{`, [, ] symbols). When N='*', all header names are printed.

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

### Route Name (Full) - $route
`$route` - Access route names of the current route call stack.  Usage examples (assuming a route call stack of "route > route[A] > route[B]"):

* `$route` and `$(route[0])` both return **"route[B]"** (current route)
* `$(route[1])` returns **"route[A]"** (parent route)
* `$(route[2])` returns **"route"** (previous-parent route)
* `$(route[-1])` returns **"route"** (topmost route)
* `$(route[-2])` returns **"route[A]"** (next-topmost route)
* `$(route[-3])` returns **"route[B]"** (next-next-topmost route)
* `$(route[3])` and `$(route[-4])` both return **NULL** (index out of bounds)
* `$(route[*])` returns **"route > route[A] > route[B]"** (entire call stack)

### Route Type - $route.type
`$route.type` - Access the type of the current route.  May be indexed, using positive or negative indexes.

* `$route.type` and `$(route.type[0])` both return current route type
* `$(route.type[1])` returns parent route type
* `$(route.type[-1])` returns topmost route type
* `$(route.type[-2])` returns next-topmost route type

### Route Name - $route.name
`$route.name` - Access the name of the current route.  May be indexed, using positive or negative indexes.

* `$route.name` and `$(route.name[0])` both return current route name
* `$(route.name[1])` returns parent route name
* `$(route.name[-1])` returns topmost route name
* `$(route.name[-2])` returns next-topmost route name

### Current script line and file  - $cfg_line
`$cfg_line` - Holds the current line from the script of the action being executed, useful for logging purposes   

`$cfg_file` - Holds the current name of the cfg file being executed, useful when using multiple scripts via the include statement

### Log level for xlog() - $xlog_level

`$xlog_level` - allows to set /reset the xlog() logging level on per-process bases. Shortly said, you can read the verbosity level for the xlog() calls or you can temporary change the level per process bases.

Example:
```text

xlog("current verbosity is $xlog_level \n");
$xlog_level = L_DBG; # force local xlogging limit to DBG
...
(set of xlogs)
...
$xlog_level = NULL;  # reset to initial value

```

## Escape Sequences

These sequences are exported, and mainly used, by xlog module to print messages in many colors (foreground and background) using escape sequences. 

### Foreground and background colors

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
    xlog("$C(bg)$avp(tmp)$C(xx) [$avp(tmp)] $C(br)$cs$C(xx)=[$hdr(cseq)]\n");
...
}
...

```
