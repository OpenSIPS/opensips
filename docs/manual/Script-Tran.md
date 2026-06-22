---
title: "Script Transformations"
description: "Intuitively, a Transformation is a function that is applied to a variable(script variable, pseudo-variable, AVP, static string) to get a special value from i..."
---

Intuitively, a **Transformation** is a function that is applied to a variable(script variable, pseudo-variable, AVP, static string) to get a special value from it.  The input value is not altered.

Examples of using different kinds of variables in **OpenSIPS script**:

```bash

# check if username in From header is equal with username in To header
if ($fU == $tU) {
   ...
}

# Request-URI username based processing
switch ($rU) {
   case "1234":
      ...
   break;
   case "5678":
      ...
   break;
   default:
     ...
}

# assign an integer value to an variable
$var(gw_count) = 1;

# assign a string value to an AVP
$avp(server) = "opensips";

# store the Request-URI in a variable
$var(ru_backup) = $ru;

# concat "sip:" + From username + "@" + To domain in a script variable x
$var(x) = "sip:" + $fU + "@" + $td;

```

The transformations are intended to facilitate access to different attributes of variables (like strlen of value, parts of value, substrings) or complete different value of variables (encoded in hexa, md5 value, escape/unescape value for DB operations...).

A transformation is represented in between `{` and `}` and follows the name of a variable. When using transformations, the variable name and transformations **must** be enclosed in between `(` and `)`.

Example:

```bash

# the length of From URI ($fu is pseudo-variable for From URI)

$(fu{s.len})

```

Multiple transformations can be applied to a variable at the same time.

```bash

# the length of escaped 'Test' header body

$(hdr(Test){s.escape.common}{s.len})

```

All transformations, unless otherwise specified, will return NULL in case of error or unsuccessful operation (e.g looking for an nonexistent parameter in an URI with the "`{uri.param,name}`" transformation). Also, NULL is accepted as input for transformations in order to support chaining with a previous one that would return NULL.

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

Converts the initial part of the given string to an integer value. Returns 0 if there were no digits at all.

```bash

$var(dur) = "2868.12 sec";
if ($(var(dur){s.int}) < 3600) {
  ...
}

```

### {s.md5}

Returns the MD5 hash of the given input.

```text

xlog("MD5 over From username: $(fU{s.md5})\n");

```

### {s.crc32}

Returns the CRC-32 checksum of the value as a decimal string.

### {s.reverse}

Returns the input string in revers order.

```text

$var(forward) = "onetwothree";
$var(reverse) = $(var(forward){s.reverse}); //Contains "eerhtowteno";

```

### {s.substr,offset,length}

Return the substring starting at *offset* having size of *length*. If *offset* is negative, then it is counted from the end of the value, -1 being the last char.  In case of a positive value, *0* is the first char.  If *length* is *0* or greater than the string length, the substring to the end of the input string is returned. If *length* is negative, the end of the substring is counted from the end of the value, with -1 excluding the last char. Both offset and length may be specified using variables.

Example:
```text

$var(x) = "abcd";
$(var(x){s.substr,1,0}) = "bcd"

```

### {s.select,index,separator}

Return a field from the value of a variable. The field is selected based on separator and index. The separator must be a character used to identify the fields. Index must be a integer value or a variable. If index is negative, the count of fields starts from end of value, -1 being last field. If index is positive, 0 is the first field. Note that if a field is empty, an empty string will be returned and not NULL.

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

Return escaped string of variable's value. Characters escaped are ', ", backslash and 0. Useful when doing DB queries (care should be taken for non Latin character set).

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

### {s.index}

Searches for one string within another starting at the beginning of the first string. Returns starting index of the string found or NULL if not found.
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
if ($(var(strtosearch){s.index, $var(str)}) != NULL)
    xlog("found $var(str) in $var(strtosearch)\n");

```

### {s.rindex}

Searches for one string within another starting at the end of the first string. Returns starting index of the string found or NULL if not found.
The optional index specifies an offset to start the search before, e.g the start of the found string will be before the supplied offset. Negative offsets are supported and will wrap.

```text

$(var(strtosearch){s.rindex, $var(str)}) # will return 11
$(var(strtosearch){s.rindex, $var(str), -3}) # will return 11
$(var(strtosearch){s.rindex, $var(str), 11}) # will return 11
$(var(strtosearch){s.rindex, $var(str), -4}) # will return 0

```

### {s.fill.left, tok, len}

Fills a string to the left with a char/string until the given final length is reached. The initial string is returned if its length is greater or equal to the given final length.

```text

$var(in) = "485"; (also works for integer PVs)

$(var(in){s.fill.left, 0, 3})    => 485    
$(var(in){s.fill.left, 0, 6})    => 000485
$(var(in){s.fill.left, abc, 8})  => bcabc485

```

> [!NOTE]
> currently optimized for speed. Does not support pseudo-variable parameters or successive "s.fill" cascading.

### {s.fill.right, tok, len}

Fills a string to the right with a char/string until the given final length is reached. The initial string is returned if its length is greater or equal to the given final length.

```text

$var(in) = 485; (also works for string PVs)

$(var(in){s.fill.right, 0, 3})   => 485
$(var(in){s.fill.right, 0, 6})   => 485000
$(var(in){s.fill.right, abc, 8}) => 485abcab

```

### {s.width, len}

Truncates or expands the input to the given *len*. Expanding is done to the right with the space character ' '. Truncating is done in a similar manner, from the right. Examples:

Fills a string to the right with a char/string until the given final length is reached. The initial string is returned if its length is greater or equal to the given final length. If used on pseudo-variables containing integers, it will convert them to strings.

```text

$var(in) = "transformation";

$(var(in){s.width, 14})   => "transformation"
$(var(in){s.width, 16})  => "transformation  "
$(var(in){s.width, 9})   => "transform"

```

### {s.trim}

Strips any leading or trailing whitespace from the input string. Trimmed characters are " " (space), \t (tab), \n (newline) and \r (carriage return).

```text

$var(in) = "\t \n input string  \r  ";

$(var(in){s.trim})   => "input string"

```

### {s.trimr}

Strips any trailing whitespace from the input string. Trimmed characters are " " (space), \t (tab), \n (newline) and \r (carriage return).

```text

$var(in) = "\t \n input string  \r  ";

$(var(in){s.trimr})   => "\t \n input string"

```

### {s.triml}

Strips any leading whitespace from the input string. Trimmed characters are " " (space), \t (tab), \n (newline) and \r (carriage return).

```text

$var(in) = "\t \n input string  \r  ";

$(var(in){s.triml})   => "input string  \r  "

```

### {s.dec2hex}

Converts a decimal(base 10) number to hexadecimal (in base 16), represented as string.

### {s.hex2dec}

Converts a hexadecimal number (base 16) represented as string to decimal (base 10).

### {s.b64encode}

Represents binary input data in an ASCII string format.

```text

$var(in) = "\x2\x3\x4\x5!@#%^&*";
$(var(in){s.b64encode})   => "AgMEBSFAIyVeJio="

```

### {s.b64decode}

Assumes input is a Base64 string and decodes as many characters as possible.

```text

$var(in) = "AgMEBSFAIyVeJio=";
$(var(in){s.b64decode})   => "\x2\x3\x4\x5!@#%^&*"

```

### {s.xor,secret}

Performs one or more logical XOR operations with (a part of) the "secret" string parameter and the input string, depending on the lengths of the two strings.

```text

$var(in) = "aaaaaabbbbbb";
$(var(in){s.xor,x})   => "!/>^P!/>^P!^U2^Q!^U2^Q"

```

### {s.eval}

Interprets the string as a variable formatted string, evaluating all the variables declared in it.

```text

$var(in) = "client";
$var(format) = "Hello, $var(in)!";
$(var(format){s.eval})   => "Hello, client!"

```

### {s.date2unix}

Assumes the input is an RFC-3261 SIP "Date" header value, parses it accordingly and returns the equivalent UNIX timestamp.

```text

$var(date) = "Thu, 13 Jun 2024 12:48:00 GMT";
$(var(date){s.date2unix})   => "1718282880";

```

### {s.sha1}

Returns the SHA1 hash of the given input.
```text

xlog("SHA1 over From username: $(fU{s.sha1})\n");

```

### {s.sha224}

Returns the SHA224 hash of the given input.
```text

xlog("SHA224 over From username: $(fU{s.sha224})\n");

```

### {s.sha256}

Returns the SHA256 hash of the given input.
```text

xlog("SHA256 over From username: $(fU{s.sha256})\n");

```

### {s.sha384}

Returns the SHA384 hash of the given input.
```text

xlog("SHA384 over From username: $(fU{s.sha384})\n");

```

### {s.sha512}

Returns the SHA512 hash of the given input.
```text

xlog("SHA512 over From username: $(fU{s.sha512})\n");

```

### {s.sha1_hmac,key}

Returns the SHA1 HMAC hash of the given input using key.
```text

xlog("SHA1 HMAC over From username using key 'secret': $(fU{s.sha1_hmac,secret})\n");

```

### {s.sha224_hmac,key}

Returns the SHA224 HMAC hash of the given input using key.
```text

xlog("SHA224 HMAC over From username using key 'secret': $(fU{s.sha224_hmac,secret})\n");

```

### {s.sha256_hmac,key}

Returns the SHA256 HMAC hash of the given input using key.
```text

xlog("SHA256 HMAC over From username using key 'secret': $(fU{s.sha256_hmac,secret})\n");

```

### {s.sha384_hmac,key}

Returns the SHA384 HMAC hash of the given input using key.
```text

xlog("SHA384 HMAC over From username using key 'secret': $(fU{s.sha384_hmac,secret})\n");

```

### {s.sha512_hmac,key}

Returns the SHA512 HMAC hash of the given input using key.
```text

xlog("SHA512 HMAC over From username using key 'secret': $(fU{s.sha512_hmac,secret})\n");

```

## URI Transformations

The name of transformation starts with 'uri.'. The value of the variable is considered to be a SIP URI. This transformation returns parts of SIP URI (see struct sip_uri). If that part is missing, the returned value is NULL.

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

These transformations parse Via headers and all starts with `via.`. The value of the variable is considered to be a SIP Via header. This transformation returns parts of the via header (see struct via_body). If the requested part is missing, the returned value is NULL. Transformation will fail (with script error) if variable holding the Via header is empty. Unless otherwise specified in descriptions below, the result of transform is a string (not an integer).

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

Returns the value of parameter at position give by 'index' (0-based index). Negative indexes are accepted, with -1 being the last parameter.

Example:
```text

"a=1;b=2;c=3"{param.valueat,1} = "2"

```

'index' can be a variable

### {param.name,index}

Returns the name of parameter at position 'index'. Negative indexes are accepted, with -1 being the last parameter. 'index' can be a variable.

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

Each transformation supports an optional 'index'. This can be used when passing a list of nameaddr specs, and represents the spec index that should be considered when extracting the value. Indexes start with 0 (the default value when missing), and can accept negative values (-1 represents the last nameaddr spec).

Example:
```text

'"first" <first@opensips.org>, "second" <second@opensips.org>' {nameaddr.0.name} = "first"
'"first" <first@opensips.org>, "second" <second@opensips.org>' {nameaddr.1.name} = "second"
'"first" <first@opensips.org>, "second" <second@opensips.org>' {nameaddr.-1.name} = "second"

```

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

"194.168.4.134" {ip.pton} returns a 4 byte binary representation of the IP provided

```

### {ip.ntop}

Returns a string representation of the binary IP provided
Example:
```text

"194.168.4.134"{ip.pton}{ip.ntop} = "194.168.4.134"

```

### {ip.isip}

Returns `1` if the string provided is a valid IPv4 or IPv6 address, otherwise `0`.
Example:
```text

"194.168.4.134" {ip.isip} = 1
"194.168.4.134.1" {ip.isip} = 0

```

### {ip.isip4}

Returns `1` if the string provided is a valid IPv4, otherwise `0`.
Example:
```text

"194.168.4.134" {ip.isip4} = 1

```

### {ip.isip6}

Returns `1` if the string provided is a valid IPv6, otherwise `0`.
Example:
```text

"194.168.4.134" {ip.isip6} = 0
"2001:0db8:85a3:0000:0000:8a2e:0370:7334" {ip.isip6} = 1

```

### {ip.family}
Returns INET or INET6 if the binary IP representation provided is IPv4 or IPv6.
Example:
```text

"194.168.4.134" {ip.pton}{ip.family} = "INET"

```

### {ip.resolve}
Returns the resolved IP address corresponding to the string domain provided. Transformation has no effect if a string IP is provided.
Example:
```text

"opensips.org" {ip.resolve} = "78.46.64.50"

```

### {ip.matches}
Checks if the input IP address matches a net mask given as IP/masklen (short format). It returns 1 if matches, 0 if not. NULL is returned on error (invalid input, invalid parameter, AF mismatch). Variables are supported for the parameter.
Example:
```bash

if ( $(si{ip.matches,10.10.0.1/24})==1 )
	xlog("It DOES match \n");
else
	xlog("It DOES NOT match \n");

```

### {ip.isprivate}
Checks if the input IP address is an IPv4 private IP, according to RFC 1918 and RFC 6598, or a loopback IP (127.0.0.0/8). It returns 1 if the IP is private, 0 if not.
Example:
```bash

if ( $(si{ip.isprivate})==1 )
	xlog("source ip is private\n");
else
	xlog("source ip is not private\n");

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

### {csv.value,index}
Returns the entry at the specified position. Indexing starts from 0. Negative indexes are accepted, with -1 being the last entry. 'index' can be a variable.
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

### {sdp.stream}
Returns a specific stream (starting with the m= line) from an SDP body. The stream to be returned can be specified using its index within the body, or using on its media type. If specified as index, it starts at `0`, but it can also be negative, with `-1` being the last stream. If specified as media type, **only the first** stream of its type will be returned. If the media type or index does not exist, NULL is returned.

Example:
```bash

if (is_method("INVITE"))
   {
      $var(first_stream) = $(rb{sdp.stream,0});
      xlog("First stream is $var(first_stream)\n");
   }

if (is_method("INVITE"))
   {
      $var(audio_stream) = $(rb{sdp.stream,audio});
      xlog("Audio stream is $var(audio_stream)\n");
   }

```

### {sdp.stream-delete}
Returns the specified SDP body with some of its streams deleted. The stream to be deleted can be specified using its index, or using on its media type. If specified as index, it starts at `0`, but it can also be negative, with `-1` being the last stream. If specified as media type, all streams matching will be deleted! If the media type or index does not exist, NULL is returned.

Example:
```bash

if (is_method("INVITE"))
   {
      $var(new_body) = $(rb{sdp.stream-delete,0});
      xlog("SDP body without first stream is $var(new_body)\n");
   }

if (is_method("INVITE"))
   {
      $var(new_body) = $(rb{sdp.stream-delete,video});
      xlog("SDP body without video stream is $var(new_body)\n");
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
    xlog("This is a de-registration\n");

```
