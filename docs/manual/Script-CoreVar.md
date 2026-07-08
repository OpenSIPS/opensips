---
title: "Core variables"
description: "The OpenSIPS variables can be easily identified in the script as all their names (or notations) starts with the $ sign."
---

**OpenSIPS** provides multiple type of variables to be used in the routing script. The difference between the types of variables comes from (1) the visibility of the variable (when it is visible), (2) what the variable is attached to (where the variable resides), (3) read-write status of the variable (some types of the variables are read-only and (4) how multipe values (for the same variable are handled).

The **OpenSIPS** variables can be easily identified in the script as all their names (or notations) starts with the **$** sign.

Types of variables:

* [**script variables**](#script_variables) - as the name says, these variables are strictly bound to the script routes. The variables are visible only in the routing blocks - they are not message or transaction related, but they are process related (script variables will be inherited by script routes executed by the same **OpenSIPS** process).  
Script variables are read write and they can have integer or string values. A script variable can have only a single value. A new assignment (or write operation) will overwrite the existing value.

* [**AVP - Attribute Value Pair**](#avp_variables) - the AVPs are dynamic variables (as name) that can be created - the AVPS are linked to a singular message or transaction (if stateful processing is used). A message or a transaction will initially (when received or created) have an empty list of AVPS attached to it. During the routing script, the script directly or functions called from script may create new AVPS that will automatically attached to the message/transaction. The AVPS will be visible in all routes where any message (reply or request) of the transaction will be processed - branch_route , failure_route, onreply_route (for this last route you need to enable the TM parameter *onreply_avp_mode*).  
AVPs are read write and an existing AVP can be even deleted (removed). An AVP may contain multiple values - a new assignment (or write operation) will add a new value to the AVP; the values are kept in "last added first to be used" order (stack).

* [**pseudo variables**](#pseudo_variables) - pseudo-variables (or PV) provide access to information from the processed SIP message (headers, RURI, transport level info, and so on) or from **OpenSIPS** internals (time values, process PID, return code of a function). Depending of what info they provide, the PVs are either bound to the message, either to nothing  (global). Most of the PVs are read-only and only several allow write operations. A PV may return several values or only one, depending of the referred info (if can have multiple values or not).  
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

```opensips

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

**Naming**: `$avp(id)` or `$(avp(id)[N])`

The 'id' can be:
* "i:number" - AVP name is an integer ID
* "s:string" - AVP name is a string value
* "alias" - the name is an AVP alias (use core parameter "avp_aliases" to define an AVP alias to an AVP name.

When using the index "N" you can force the AVP to return a certain value (the N-th value). If no index is given, the first value will be returned.

**Hints**:
* to enable AVPs in onreply_route, use "modparam("tm", "onreply_avp_mode", 1)"
* if multiple values are used for a single AVP, the values are index in revert order than added
* AVPs are part of the transaction context, so they will be visible everywhere where the transaction is present.
* AVPs with integer IDs are much much faster than the AVPs with string IDs
* AVP aliases are resolved at startup time so they have no impact at runtime
* an AVP can be deleted

Example of usage:
* Transaction persistence example
```opensips

# enable avps in onreply route
modparam("tm", "onreply_avp_mode", 1)
# define "tmp" as alias for "i:17"
avp_aliases="tmp=i:17"
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
```opensips

$avp(i:17) = "one";
# we have a sigle value
$avp(i:17) = "two";
# we have two values ("two","one")
$avp(i:17) = "three";
# we have three values ("three","two","one")

xlog("accessing values with no index: $avp(i:17)\n");
# this will print the first value, which is the last added value -> "three"

xlog("accessing values with no index: $(avp(i:17)[2])\n");
# this will print the index 2 value (third one), -> "one"

# remove the last value of the avp; if there is only one value, the AVP itself will be destroyed
$avp(i:17) = NULL;

# delete all values and destroy the AVP
avp_delete("$avp(i:17)/g");

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

### Auth whole username - $aU

`$aU` - whole username from Authorization or Proxy-Authorization header

### Acc username - $Au

`$Au` - username for accounting purposes. It's a selective pseudo variable (inherited from acc module). It returns `$au` if it exists or From username otherwise.

### Request's first branch - $br

`$br` - reference to request's first branch

> [!IMPORTANT]
> It is R/W variable (you can assign values to it from routing logic)


### Request's all branches - $bR

`$bR` - reference to request's all branches

### Branch flags - $bf

`$bf` - reference to branch flags of branch 0 (RURI) - decimal output

> [!IMPORTANT]
> It is R/W variable (you can assign values to it from routing logic)


### Branch flags - $bF

`$bF` - reference to branch flags of branch 0 (RURI) - hexa output

> [!IMPORTANT]
> It is R/W variable (you can assign values to it from routing logic)


### Call-Id - $ci

`$ci` - reference to body of call-id header

### Content-Length - $cl

`$cl` - reference to body of content-length header

### CSeq - $cs

`$cs` - reference to cseq number from cseq header

### Contact header - $ct

`$ct` - reference to body of contact header

### Content-Type - $cT

`$cT` - reference to body of content-type header

### Domain of destination URI - $dd

`$dd` - reference to domain of destination uri

### Diversion header URI - $di

`$di` - reference to Diversion header URI

### Diversion "privacy" parameter - $dip

`$dip` - reference to Diversion header "privacy" parameter value

### Diversion "reason" parameter - $dir

`$dir` - reference to Diversion header "reason" parameter value

### Port of destination URI - $dp

`$dp` - reference to port of destination uri

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

### Branch index - $T_branch_idx

`$T_branch_idx` - the index (starting with 1 for the first branch) of the branch for which is executed the branch_route[]. If used outside of branch_route[] block, the value is '0'. This is exported by TM module.

### String formatted time - $Tf

`$Tf` - reference string formatted time

### Unix time stamp - $Ts

`$Ts` - reference to unix time stamp

### User agent header - $ua

`$ua` - reference to user agent header field

### SIP Headers - $hdr

`$(hdr(name)[N])` - represents the body of the N-th header identified by 'name'. If [N] is omitted then the body of the first header is printed. The first header is retrieved when N=0, for the second N=1, and so on. To print the last header of that type, use -1, no other negative values are supported now. No white spaces are allowed inside the specifier (before `}`, before or after `{`, [, ] symbols). When N='*', all headers of that type are printed.

The module should identify most of compact header names (the ones recognized by **OpenSIPS** which should be all at this moment), if not, the compact form has to be specified explicitly. It is recommended to use dedicated specifiers for headers (e.g., %ua for user agent header), if they are available -- they are faster.

> [!IMPORTANT]
> It is R/W variable (you can assign values to it routing script)



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

```opensips

...
avp_aliases="uuid=I:50"
...
route {
...
    $avp(uuid)="caller_id";
    $avp(i:20)= $avp(uuid) + ": " + $fu;
    xdbg("$(C(bg))avp(i:20)$(C(xx)) [$avp(i:20)] $(C(br))cseq$(C(xx))=[$hdr(cseq)]\n");
...
}
...

```
