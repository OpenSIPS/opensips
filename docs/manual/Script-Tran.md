---
title: "Script Transformations"
description: "This documentation is valid for OpenSIPS v1.5.x"
---

This documentation is valid for **OpenSIPS v1.5.x**

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

Return substring starting at offset having size of 'length'. If offset is negative, then it is counted from the end of the value, -1 being the last char. In case of positive value, 0 is first char. Length must be non-negative; in case of 0 or a value greater than the remaining string length, substring to the end of variable value is returned. offset and length can be a varibale as well.

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

## Examples

Within a variable, many transformation can be applied, being executed from left to right.

* The length of the value of parameter at postion 1 (remember 0 is first position, 1 is second position)

```text

$var(x) = "a=1;b=22;c=333";
$(var(x){param.value,$(var(x){param.name,1})}{s.len}) = 2

```

* Test if whether is un-registration or not

```text

if(is_method("REGISTER") && is_present_hf("Expires") && $(hdr(Expires){s.int})==0)
    xlog("This is an un-registrationn");

```
