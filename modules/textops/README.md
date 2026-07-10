---
title: "textops Module"
description: "The module implements text based operations over the SIP message processed by OpenSIPS."
---

## Admin Guide


### Overview


The module implements text based operations over the SIP message
processed by OpenSIPS. SIP is a text based protocol and the module
provides a large set of very useful functions to manipulate the
message at text level, e.g., regular expression search and replace,
Perl-like substitutions, checks for method type, header presence,
insert of new header and date, etc.


#### Known Limitations


search ignores folded lines. For example, 
search("(From|f):.*@foo.bar")
doesn't match the following From header field:


```c
From: medabeda 
 <sip:medameda@foo.bar>;tag=1234
```


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
running OpenSIPS with this module loaded:


- *None*.


### Exported Functions


#### search(re)


Searches for the re in the message.


Meaning of the parameters is as follows:


- *re* - Regular expression.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="search usage"
...
if ( search("[Ss][Ii][Pp]") ) { /*....*/ };
...
```


#### search_body(re)


Searches for the re in the body of the message.


Meaning of the parameters is as follows:


- *re* - Regular expression.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="search_body usage"
...
if ( search_body("[Ss][Ii][Pp]") ) { /*....*/ };
...
```


#### search_append(re, txt)


Searches for the first match of re and appends txt after it.


Meaning of the parameters is as follows:


- *re* - Regular expression.
- *txt* - String to be appended.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="search_append usage"
...
search_append("[Oo]pen[Ss]er", " SIP Proxy");
...
```


#### search_append_body(re, txt)


Searches for the first match of re in the body of the message
and appends txt after it.


Meaning of the parameters is as follows:


- *re* - Regular expression.
- *txt* - String to be appended.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="search_append_body usage"
...
search_append_body("[Oo]pen[Ss]er", " SIP Proxy");
...
```


#### replace(re, txt)


Replaces the first occurrence of re with txt.


Meaning of the parameters is as follows:


- *re* - Regular expression.
- *txt* - String.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="replace usage"
...
replace("opensips", "Open SIP Server");
...
```


#### replace_body(re, txt)


Replaces the first occurrence of re in the body of the message
with txt.


Meaning of the parameters is as follows:


- *re* - Regular expression.
- *txt* - String.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="replace_body usage"
...
replace_body("opensips", "Open SIP Server");
...
```


#### replace_all(re, txt)


Replaces all occurrence of re with txt.


Meaning of the parameters is as follows:


- *re* - Regular expression.
- *txt* - String.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="replace_all usage"
...
replace_all("opensips", "Open SIP Server");
...
```


#### replace_body_all(re, txt)


Replaces all occurrence of re in the body of the message
with txt. Matching is done on a per-line basis.


Meaning of the parameters is as follows:


- *re* - Regular expression.
- *txt* - String.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="replace_body_all usage"
...
replace_body_all("opensips", "Open SIP Server");
...
```


#### replace_body_atonce(re, txt)


Replaces all occurrence of re in the body of the message
with txt. Matching is done over the whole body.


Meaning of the parameters is as follows:


- *re* - Regular expression.
- *txt* - String.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="replace_body_atonce usage"
...
# strip the whole body from the message:
if(has_body() && replace_body_atonce("^.+$", ""))
        remove_hf("Content-Type"); 
...
```


#### subst('/re/repl/flags')


Replaces re with repl (sed or perl like).


Meaning of the parameters is as follows:


- *'/re/repl/flags'* - sed like regular 
expression. flags can be a combination of i (case insensitive),
g (global) or s (match newline don't treat it as end of line).
're' - is regular expresion
'repl' - is replacement string - may contain pseudo-varibales
'flags' - substitution flags (i - ignore case, g - global)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="subst usage"
...
# replace the uri in to: with the message uri (just an example)
if ( subst('/^To:(.*)sip:[^@]*@[a-zA-Z0-9.]+(.*)$/t:\1\u\2/ig') ) {};

# replace the uri in to: with the value of avp sip_address (just an example)
if ( subst('/^To:(.*)sip:[^@]*@[a-zA-Z0-9.]+(.*)$/t:\1$avp(sip_address)\2/ig') ) {};

...
```


#### subst_uri('/re/repl/flags')


Runs the re substitution on the message uri (like subst but works
only on the uri)


Meaning of the parameters is as follows:


- *'/re/repl/flags'* - sed like regular 
expression. flags can be a combination of i (case insensitive),
g (global) or s (match newline don't treat it as end of line).
're' - is regular expresion
'repl' - is replacement string - may contain pseudo-varibales
'flags' - substitution flags (i - ignore case, g - global)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="subst_uri usage"
...
# adds 3463 prefix to numeric uris, and save the original uri (\0 match)
# as a parameter: orig_uri (just an example)
if (subst_uri('/^sip:([0-9]+)@(.*)$/sip:3463\1@\2;orig_uri=\0/i')){$

# adds the avp 'uri_prefix' as prefix to numeric uris, and save the original
# uri (\0 match) as a parameter: orig_uri (just an example)
if (subst_uri('/^sip:([0-9]+)@(.*)$/sip:$avp(uri_prefix)\1@\2;orig_uri=\0/i')){$

...
```


#### subst_user('/re/repl/flags')


Runs the re substitution on the message uri (like subst_uri but works
only on the user portion of the uri)


Meaning of the parameters is as follows:


- *'/re/repl/flags'* - sed like regular
expression. flags can be a combination of i (case insensitive),
g (global) or s (match newline don't treat it as end of line).
're' - is regular expresion
'repl' - is replacement string - may contain pseudo-varibales
'flags' - substitution flags (i - ignore case, g - global)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="subst usage"
...
# adds 3463 prefix to uris ending with 3642 (just an example)
if (subst_user('/3642$/36423463/')){$

...
# adds avp 'user_prefix' as prefix to username in r-uri ending with 3642
if (subst_user('/(.*)3642$/$avp(user_prefix)\13642/')){$
...
```


#### subst_body('/re/repl/flags')


Replaces re with repl (sed or perl like) in the body of the message.


Meaning of the parameters is as follows:


- *'/re/repl/flags'* - sed like regular 
expression. flags can be a combination of i (case insensitive),
g (global) or s (match newline don't treat it as end of line).
're' - is regular expresion
'repl' - is replacement string - may contain pseudo-varibales
'flags' - substitution flags (i - ignore case, g - global)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="subst_body usage"
...
if ( subst_body('/^o=(.*) /o=$fU ') ) {};

...
```


#### filter_body(content_type)


Filters multipart body by leaving out all other body
parts except the first body part of given type.


Meaning of the parameters is as follows:


- *content_type* -
Content type to be left in the body.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="filter_body usage"
...
if (has_body("multipart/mixed")) {
    if (filter_body("application/sdp") {
        remove_hf("Content-Type");
        append_hf("Content-Type: application/sdp\r\n");
    } else {
        xlog("Body part application/sdp not found\n");
    }
}
...
```


#### append_to_reply(txt)


Append txt as header to the reply.


Meaning of the parameters is as follows:


- *txt* - String which may contains
pseudo-variables.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
ERROR_ROUTE.


```opensips title="append_to_reply usage"
...
append_to_reply("Foo: bar\r\n");
append_to_reply("Foo: $rm at $Ts\r\n");
...
```


#### append_hf(txt)


Appends 'txt' as header after the last header field.


Meaning of the parameters is as follows:


- *txt* - Header field to be appended. The
value can contain pseudo-variables which will be replaced at run
time.


Note: Headers which are added in main route cannot be removed in further routes
(e.g. failure routes). So, the idea is not to add there any headers that you 
might want to remove later. To add headers temporarely use the branch route 
because the changes you do there are per-branch.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="append_hf usage"
...
append_hf("P-hint: VOICEMAIL\r\n");
append_hf("From-username: $fU\r\n");
...
```


#### append_hf(txt, hdr)


Appends 'txt' as header after first 'hdr' header field.


Meaning of the parameters is as follows:


- *txt* - Header field to be appended. The
value can contain pseudo-variables which will be replaced at run
time.
- *hdr* - Header name after which the 'txt'
is appended.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="append_hf usage"
...
append_hf("P-hint: VOICEMAIL\r\n", "Call-ID");
append_hf("From-username: $fU\r\n", "Call-ID");
...
```


#### insert_hf(txt)


Inserts 'txt' as header before the first header field.


Meaning of the parameters is as follows:


- *txt* - Header field to be inserted. The
value can contain pseudo-variables which will be replaced at run
time.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="insert_hf usage"
...
insert_hf("P-hint: VOICEMAIL\r\n");
insert_hf("To-username: $tU\r\n");
...
```


#### insert_hf(txt, hdr)


Inserts 'txt' as header before first 'hdr' header field.


Meaning of the parameters is as follows:


- *txt* - Header field to be inserted. The
value can contain pseudo-variables which will be replaced at run
time.
- *hdr* - Header name before which the 'txt'
is inserted.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="insert_hf usage"
...
insert_hf("P-hint: VOICEMAIL\r\n", "Call-ID");
insert_hf("To-username: $tU\r\n", "Call-ID");
...
```


#### append_urihf(prefix, suffix)


Append header field name with original Request-URI 
in middle.


Meaning of the parameters is as follows:


- *prefix* - string (usually at least 
header field name).
- *suffix* - string (usually at least 
line terminator).


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, 
BRANCH_ROUTE.


```opensips title="append_urihf usage"
...
append_urihf("CC-Diversion: ", "\r\n");
...
```


#### is_present_hf(hf_name)


Return true if a header field is present in message.


> [!NOTE]
> The function is also able to distinguish the compact names. For
exmaple "From" will match with "f"


Meaning of the parameters is as follows:


- *hf_name* - Header field name.(long or 
compact form)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="is_present_hf usage"
...
if (is_present_hf("From")) log(1, "From HF Present");
...
```


#### append_time()


Adds a time header to the reply of the request. You must use it
before functions that are likely to send a reply, e.g., save()
from 'registrar' module. Header format is: 
"Date: %a, %d %b %Y %H:%M:%S GMT", with the legend:


- *%a* abbreviated week of day name (locale)
- *%d* day of month as decimal number
- *%b* abbreviated month name (locale)
- *%Y* year with century
- *%H* hour
- *%M* minutes
- *%S* seconds


Return true if a header was succesfully appended.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, 
BRANCH_ROUTE.


```opensips title="append_time usage"
...
append_time();
...
```


#### is_method(name)


Check if the method of the message matches the name. If name is a
known method (invite, cancel, ack, bye, options, info, update, register,
message, subscribe, notify, refer, prack), the function performs method
ID testing (integer comparison) instead of ignore case string
comparison.


The 'name' can be a list of methods in the form of
'method1|method2|...'. In this case, the function returns true if the
SIP message's method is one from the list. IMPORTANT NOTE: in the list
must be only methods defined in OpenSIPS with ID (invite, cancel, ack,
bye, options, info, update, register, message, subscribe, notify,
refer, prack, publish; for more see:
[http://www.iana.org/assignments/sip-parameters](http://www.iana.org/assignments/sip-parameters)).


If used for replies, the function tests the value of method field from
CSeq header.


Meaning of the parameters is as follows:


- *name* - SIP method name


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, and BRANCH_ROUTE.


```opensips title="is_method usage"
...
if(is_method("INVITE"))
{
    # process INVITEs here
}
if(is_method("OPTION|UPDATE"))
{
    # process OPTIONs and UPDATEs here
}
...
```


#### remove_hf(hname)


Remove from message all headers with name "hname"


Returns true if at least one header is found and removed.


Meaning of the parameters is as follows:


- *hname* - header name to be removed.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE and BRANCH_ROUTE.


```opensips title="remove_hf usage"
...
if(remove_hf("User-Agent"))
{
    # User Agent header removed
}
...
```


#### has_body(), has_body(mime)


The function returns *true* if the SIP message
has a body attached. The checked includes also the 
"Content-Lenght" header presence and value.


If a paramter is given, the mime described will be also checked against
the "Content-Type" header.


Meaning of the parameters is as follows:


- *mime* - mime to be checked against the 
"Content-Type" header. If not present or 0, this
check will be disabled.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE and BRANCH_ROUTE.


```opensips title="has_body usage"
...
if(has_body("application/sdp"))
{
    # do interesting stuff here
}
...
```


#### is_privacy(privacy_type)


The function returns *true* if 
the SIP message has a Privacy header field that includes
the given privacy_type among its privacy values.  See
[http://www.iana.org/assignments/sip-priv-values](http://www.iana.org/assignments/sip-priv-values)
for possible privacy type values.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE and BRANCH_ROUTE.


```opensips title="is_privacy usage"
...
if(is_privacy("id"))
{
    # do interesting stuff here
}
...
```


### Known Limitations


Search functions are applied to the original request,
i.e., they ignore all changes resulting from message
processing in OpenSIPS script.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
