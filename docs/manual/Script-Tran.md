---
title: "Script Transformations"
description: "A Transformation is basically a function that is applied to a variable(script variable, pseudo-variables, AVPS, static strings) to get a special value from i..."
---

A **Transformation** is basically a function that is applied to a variable(script variable, pseudo-variables, AVPS, static strings) to get a special value from it. The value of the original variable is not altered.

Example of using different kind of variables in **OpenSIPS script**:

```bash

# check if username in From header is equal with username in To header
if($fU==$tU) {
   ...
}

# r-uri username based processing
switch($ruri.user) {
   case "1234":
      ...
   break;
   case "5678":
      ...
   break;
   default:
     ...
}

# assign integer value to an AVP
$avp(i:11) = 1;

#assing string value to an AVP
$avp(i:22) = "opensips";

# write ruri in an AVP
$avp(i:33) = $ruri;

# concat "sip:" + From username + "@" + To domain in a script variable x
$var(x) = "sip:" + $fU +"@" + $td;

```

The transformations are intended to facilitate access to different attributes of variables (like strlen of value, parts of value, substrings) or complete different value of variables (encoded in hexa, md5 value, escape/unescape value for DB operations...).

A transformation is represented in between `{` and `}` and follows the name of a variable. When using transformations, the variable name and transformations **must** be enclosed in between `(` and `)`.

Example:

```bash

# the length of From URI ($fu is pseudo-variable for From URI)

$(fu{s.len})

```

Many transformations can be applied in the same time to a variable.

```bash

# the length of escaped 'Test' header body

$(hdr(Test){s.escape.common}{s.len})

```

The transformations can be used anywhere, being considered parts of script variables support -- in xlog, avpops or other modules' functions and parameters, in right side assignment expressions or in comparisons.

> [!IMPORTANT]
> To learn what variables can be used with transformations see [Scripting variables list](Script-CoreVar.md).

## String Transformations
The name of these transformation starts with 's.'. They are intended to apply string operations to variables.

Available transformations in this class:

### {s.len}

Return strlen of variable value

```text

$var(x) = "abc";
if($(var(x){s.len}) == 3)
{
   ...
}

```

### {s.int}

Return integer value of a string-represented number

```text

$var(x) = "1234";
if($(var(x){s.int})==1234) {
  ...
}

```

### {s.md5}

Return md5 over variable value

```text

xlog("MD4 over From username: $(fU{s.md5})");

```

### {s.substr,offset,length}

Return substring starting at offset having size of 'length'. If offset is negative, then it is counted from the end of the value, -1 being the last char. In case of positive value, 0 is first char. Length must be positive, in case of 0, substring to the end of variable value is returned. offset and length can be a varibale as well.

Example:
```text

$var(x) = "abcd";
$(var(x){s.substr,1,0}) = "bcd"

```

### {s.select,index,separator}

Return a field from the value of a variable. The field is selected based on separator and index. The separator must be a character used to identify the fields. Index must be a integer value or a variable. If index is negative, the count of fields starts from end of value, -1 being last field. If index is positive, 0 is the first field.

Example:
```text

$var(x) = "12,34,56";
$(var(x){s.select,1,,}) => "34" ;

$var(x) = "12,34,56";
$(var(x){s.select,-2,,}) => "34"

```

### {s.encode.hexa}

Return encoding in hexa of variable's value

### {s.decode.hexa}

Return decoding from hexa of variable's value

### {s.escape.common}

Return escaped string of variable's value. Characters escaped are ', ",  and 0. Useful when doing DB queries (care should be taken for non Latin character set).

### {s.unescape.common}

Return unescaped string of variable's value. Reverse of above transformation.

### {s.escape.user}

Return escaped string of variable's value, changing to '%hexa' the characters that are not allowed in user part of SIP URI following RFC requirements.

### {s.unescape.user}

Return unescaped string of variable's value, changing '%hexa' to character code. Reverse of above transformation.

### {s.escape.param}

Return escaped string of variable's value, changing to '%hexa' the characters that are not allowed in the param part of SIP URI following RFC requirements.

### {s.unescape.param}

Return unescaped string of variable's value, changing '%hexa' to character code. Reverse of above transformation.

### {s.tolower}

Return string with lower case ASCII letters.

### {s.toupper}

Return string with upper case ASCII letters.

### {s.dec2hex}

Converts a decimal(base 10) number to hexadecimal (in base 16), represented as string.

### {s.hex2dec}

Converts a hexadecimal number (base 16) represented as string to decimal (base 10).

### {s.index}

Searches for one string within another starting at the beginning of the first string. Returns starting index of the string found or -1 if not found.
The optional index specifies the offset to begin the search at in the string. Negative offsets are supported and will wrap.

```bash

$var(strtosearch) = 'onetwothreeone';
$var(str) = 'one';

# Search the string starting at 0 index
$(var(strtosearch){s.index, $var(str)}) # will return 0
$(var(strtosearch){s.index, $var(str), 0}) # Same as above
$(var(strtosearch){s.index, $var(str), 3}) # returns 11

# Negative offset
$(var(strtosearch){s.index, $var(str), -11}) # Same as above

# Negative wrapping offset
$(var(strtosearch){s.index, $var(str), -25}) # Same as above

#Test for existence of string in another
if ($(var(strtosearch){s.index, $var(str)}) >=0)
    xlog("found $var(sstr) in $var(strtosearch)");

```

### {s.rindex}

Searches for one string within another starting at the end of the first string. Returns starting index of the string found or -1 if not found.
The optional index specifies an offset to start the search before, e.g the start of the found string will be before the supplied offset. Negative offsets are supported and will wrap.

```text

$(var(strtosearch){s.rindex, $var(str)}) # will return 11
$(var(strtosearch){s.rindex, $var(str), -3}) # will return 11
$(var(strtosearch){s.rindex, $var(str), 11}) # will return 11
$(var(strtosearch){s.rindex, $var(str), -4}) # will return 0

```

### {s.fill.left}

Fills a string to the left with a char/string until the given final length is reached. The initial string is returned if its length is greater or equal to the given final length.

```text

$var(in) = "485"; (also works for integer PVs)

$(var(in){s.fill.left, 0, 3})    => 485    
$(var(in){s.fill.left, 0, 6})    => 000485
$(var(in){s.fill.left, abc, 8})  => bcabc485

```

> [!NOTE]
> currently optimized for speed. Does not support pseudo-variable parameters or successive "s.fill" cascading.

### {s.fill.right}

Fills a string to the right with a char/string until the given final length is reached. The initial string is returned if its length is greater or equal to the given final length.

```text

$var(in) = 485; (also works for string PVs)

$(var(in){s.fill.right, 0, 3})   => 485
$(var(in){s.fill.right, 0, 6})   => 485000
$(var(in){s.fill.right, abc, 8}) => 485abcab

```

> [!NOTE]
> currently optimized for speed. Does not support pseudo-variable parameters or successive "s.fill" cascading.

## URI Transformations

The name of transformation starts with 'uri.'. The value of the variable is considered to be a SIP URI. This transformation returns parts of SIP URI (see struct sip_uri). If that part is missing, the returned value is an empty string.

Available transformations in this class:

### {uri.user}

Returns the user part of the URI schema.

### {uri.host}

(same as **`{uri.domain}`**)

Returns the domain part of the URI schema.

### {uri.passwd}

Returns the password part of the URI schema.

### {uri.port}

Returns the port of the URI schema.

### {uri.params}

Returns all the URI parameters into a single string.

### {uri.param,name}

Returns the value of URI parameter with name "name"

### {uri.headers}

Returns URI headers.

### {uri.transport}

Returns the value of transport URI parameter.

### {uri.ttl}

Returns the value of ttl URI parameter.

### {uri.uparam}

Returns the value of user URI parameter

### {uri.maddr}

Returns the value of maddr URI parameter.

### {uri.method}

Returns the value of method URI parameter.

### {uri.lr}

Returns the value of lr URI parameter.

### {uri.r2}

Returns the value of r2 URI parameter.

### {uri.schema}

Returns the schema part of the given URI.

## VIA Transformations

These transformations parse Via headers and all starts with `via.`. The value of the variable is considered to be a SIP Via header. This transformation returns parts of the via header (see struct via_body). If the requested part is missing, the returned value is an empty string. Transformation will fail (with script error) if variable holding the Via header is empty. Unless otherwise specified in descriptions below, the result of transform is a string (not an integer).

Examples:
```text
$var(upstreamtransport) = $(hdr(Via)[1]{via.transport}{s.tolower});
$var(upstreamip) = $(hdr(Via)[1]{via.param,received});
$var(clientport) = $(hdr(Via)[-1]{via.param,rport});
```

Available transformations in this class:

### {via.name}

Returns the `protocol-name` (of RFC3261 BNF), generally `SIP`.

### {via.version}

Returns the `protocol-version` (of RFC3261 BNF), generally `2.0`.

### {via.transport}

Returns the `transport` (of RFC3261 BNF), e.g., `UDP`, `TCP`, `TLS`. This is the transport protocol used to send the request message.

### {via.host}

(same as `{via.domain}`)

Returns the `host` portion of the `sent-by` (of RFC3261 BNF). Typically this is the IP address of the sender of the request message, and is the address to which the response will be sent.

### {via.port}

Returns the `port` portion of the `sent-by` (of RFC3261 BNF). Typically this is the IP port of the sender of the request message, and is the address to which the response will be sent. Result of transform is valid as both integer and string.

### {via.comment}

The comment associated with the via header. The `struct via_body` contains this field, but it isn't clear that RFC3261 allows Via headers to have comments (see text at top of page 221, and the BNF doesn't explicit allow comment within Via). The comment is the text enclosed within parens.

### {via.params}

Returns all the Via headers parameters (`via-param` of RFC3261 BNF) as single string. Result can be processed using the `{param.*}` transforms. This is essentially everything after the host and port.

### {via.param,name}

Returns the value of Via header parameter with name `name`. Typical parameters include `branch`, `rport` and `received`.

### {via.branch}

Returns the value of the branch parameter in the VIA header.

### {via.received}

Returns the value of the received parameter in the VIA header, if any.

### {via.rport}

Returns the value of the rport parameter in the VIA header, if any.

## Parameters List Transformations

The name of the transformation starts with "param.". The value of the variable is considered to be a string like name1=value1;name2=value2;...". The transformations returns the value for a specific parameter, or the name of a parameter at a specific index.

Available transformations in this class:

### {param.value,name}

Returns the value of parameter 'name'

Example:
```text

"a=1;b=2;c=3"{param.value,c} = "3"

```

'name' can be a variable

### {param.exist,name}

Returns 1 if the parameter `name` exists (with or without value), else 0. Returned value is both string and integer. `name` can be variable. This can be used to test existence of parameters that do not have values.

Example:
```text

"a=0;b=2;ob;c=3"{param.exist,ob};         # returns 1
"a=0;b=2;ob;c=3"{param.exist,a};          # returns 1
"a=0;b=2;ob;c=3"{param.exist,foo};        # returns 0

```

### {param.valueat,index}

Returns the value of parameter at position give by 'index' (0-based index)

Example:
```text

"a=1;b=2;c=3"{param.valueat,1} = "2"

```

'index' can be a variable

### {param.name,index}

Returns the name of parameter at position 'index'.

Example:
```text

"a=1;b=2;c=3"{param.name,1} = "b"

```

### {param.count}

Returns the number of parameters in the list.

Example:
```text

"a=1;b=2;c=3"{param.count} = 3

```

## Name-address Transformations

The name of the transformation starts with 'nameaddr.'. The value of the variable is considered to be a string like '[display_name] uri'. The transformations returns the value for a specific field.

Available transformations in this class:

### {nameaddr.name}

Returns the value of display name

Example:
```text

'"test" <sip:test@opensips.org>' {nameaddr.name} = "test"

```

### {nameaddr.uri}

Returns the value of URI

Example:
```text

'"test" <sip:test@opensips.org>' {nameaddr.uri} = sip:test@opensips.org

```

### {nameaddr.len}

Returns the length of the entire name-addr part from the value.

### {nameaddr.param,param_name}

Returns the value of the parameter with name param_name.
Example:
```text

'"test" <sip:test@opensips.org>;tag=dat43h' {nameaddr.param,tag} = dat43h

```

### {nameaddr.params}

Returns all the parameters and their corresponding values.
Example:
```text

'"test" <sip:test@opensips.org>;tag=dat43h;private=yes' {nameaddr.params} = "tag=dat43h;private=yes"

```

## IP Transformations

The name of the transformation starts with 'ip.'. Available transformations in this class:

### {ip.pton}

Returns a binary representation of a string represented IP.
Example:
```text

"192.168.2.134" {ip.pton} returns a 4 byte binary representation of the IP provided

```

### {ip.ntop}

Returns a string representation of the binary IP provided
Example:
```text

"192.168.2.134"{ip.pton}{ip.ntop} = "192.168.2.134"

```

### {ip.isip}

Returns 1 or 0, if the string provided is a valid IP or not.
Example:
```text

"192.168.2.134" {ip.isip} = 1
"192.168.2.134.1" {ip.isip} = 0

```

### {ip.family}
Returns INET or INET6 if the binary IP representation provided is IPv4 or IPv6.
Example:
```text

"192.168.2.134" {ip.pton}{ip.family} = "INET"

```

### {ip.resolve}
Returns the resolved IP address coresponding to the string domain provided. Transformation has no effect if a string IP is provided.
Example:
```text

"opensips.org" {ip.resolve} = "78.46.64.50"

```

## CSV Transformations

The name of the transformation starts with "csv.". The value of the variable is considered to be a string like "field1,field2,...". The transformations return the number of entries in the provided CSV, or the field at a specified position in the CSV.

Available transformations in this class:

### {csv.count}
Returns the number of entries in the provided CSV.
Example:
```text

"a,b,c" {csv.count} = 3

```

### {csv.value}
Returns the entry at the specified positions. Indexing starts from 0.
Example:
```text

"a,b,c" {csv.value,2} = c

```

## SDP Transformations

The name of the transformation starts with "sdp.". The value of the variable is considered to be a valid SDP body. The transformation returns a specific line in the SDP body.

Available transformations in this class:

### {sdp.line}
Returns the specified line in the SDP body. The transformations also accepts a second parameter, that specifies the line number of the first parameter's type to get from the SDP body. Indexing starts from 0. If the second parameter is missing, it is assumed to be 0. 
Example:
```bash

if (is_method("INVITE"))
   {
      $var(aline) = $(rb{sdp.line,a,1});
      xlog("The second a line in the SDP body is $var(aline)\n");
   }

if (is_method("INVITE"))
   {
      $var(mline) = $(rb{sdp.line,m});
      xlog("The first m line in the SDP body is $var(mline)\n");
   }

```

## Regular Expression Transformations

The name of the transformation starts with "re.". The input can be any string.

### {re.subst,reg_exp}

The reg_exp parameter can either be a plain string or a variable.
The format of the reg_exp is :
```text
/posix_match_expression/replacement_expression/flags
```

The flags can be
```text
i - match ignore case
s - match within multi-lines strings
g - replace all matches
```

Example:
```text

$var(reg_input)="abc";
$var(reg) = "/a/A/g";
xlog("Applying reg exp $var(reg) to $var(reg_input) : $(var(reg_input){re.subst,$var(reg)})\n");

...
...
xlog("Applying reg /b/B/g to $var(reg_input) : $(var(reg_input){re.subst,/b/B/g})\n");

```

## Examples

Within a variable, many transformation can be applied, being executed from left to right.

* The length of the value of parameter at position 1 (remember 0 is first position, 1 is second position)

```text

$var(x) = "a=1;b=22;c=333";
$(var(x){param.value,$(var(x){param.name,1})}{s.len}) = 2

```

* Test if whether is un-registration or not

```text

if(is_method("REGISTER") && is_present_hf("Expires") && $(hdr(Expires){s.int})==0)
    xlog("This is an un-registration");

```
