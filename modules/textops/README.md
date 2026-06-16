---
title: "textops Module"
description: "The module implements text based operations over the SIP message processed by OpenSIPS. SIP is a text based protocol and the module provides a large set of very useful functions to manipulate the message at text level, e.g., regular expression search and replace, Perl-like substitutions, ..."
---

## Admin Guide


### Overview


The module implements text based operations over the SIP message
		processed by OpenSIPS. SIP is a text based protocol and the module
		provides a large set of very useful functions to manipulate the
		message at text level, e.g., regular expression search and replace,
		Perl-like substitutions, etc.


Note: all SIP-aware functions like *insert_hf*,
		*append_hf* or *codec*
		operations have been moved to the *sipmsgops*
		module.


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


- *re* (string) - Regular expression.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="search usage"
...
if ( search("[Ss][Ii][Pp]") ) { /*....*/ };
...
```


#### search_body(re)


Searches for the re in the body of the message.


Meaning of the parameters is as follows:


- *re* (string) - Regular expression.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="search_body usage"
...
if ( search_body("[Ss][Ii][Pp]") ) { /*....*/ };
...
```


#### search_append(re, txt)


Searches for the first match of re and appends txt after it.


Meaning of the parameters is as follows:


- *re* (string) - Regular expression.
- *txt* (string) - String to be appended.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="search_append usage"
...
search_append("[Oo]pen[Ss]er", " SIP Proxy");
...
```


#### search_append_body(re, txt)


Searches for the first match of re in the body of the message
		and appends txt after it.


Meaning of the parameters is as follows:


- *re* (string) - Regular expression.
- *txt* (string) - String to be appended.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="search_append_body usage"
...
search_append_body("[Oo]pen[Ss]er", " SIP Proxy");
...
```


#### replace(re, txt)


Replaces the first occurrence of re with txt.


Meaning of the parameters is as follows:


- *re* (string) - Regular expression.
- *txt* (string)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="replace usage"
...
replace("opensips", "Open SIP Server");
...
```


#### replace_body(re, txt)


Replaces the first occurrence of re in the body of the message
		with txt.


Meaning of the parameters is as follows:


- *re* (string) - Regular expression.
- *txt* (string)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="replace_body usage"
...
replace_body("opensips", "Open SIP Server");
...
```


#### replace_all(re, txt)


Replaces all occurrence of re with txt.


Meaning of the parameters is as follows:


- *re* - (string) Regular expression.
- *txt* (string)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="replace_all usage"
...
replace_all("opensips", "Open SIP Server");
...
```


#### replace_body_all(re, txt)


Replaces all occurrence of re in the body of the message
		with txt. Matching is done on a per-line basis.


Meaning of the parameters is as follows:


- *re* (string) - Regular expression.
- *txt* (string)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="replace_body_all usage"
...
replace_body_all("opensips", "Open SIP Server");
...
```


#### replace_body_atonce(re, txt)


Replaces all occurrence of re in the body of the message
		with txt. Matching is done over the whole body.


Meaning of the parameters is as follows:


- *re* (string) - Regular expression.
- *txt* (string)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="replace_body_atonce usage"
...
# strip the whole body from the message:
if(has_body() && replace_body_atonce("^.+$", ""))
        remove_hf("Content-Type"); 
...
```


#### subst('/re/repl/flags')


Replaces re with repl (sed or perl like).


Meaning of the parameters is as follows:


- *'/re/repl/flags'* (string) - sed like regular 
				expression. flags can be a combination of i (case insensitive),
				g (global) or s (match newline don't treat it as end of line).
're' - is regular expression
'repl' - is replacement string - may contain pseudo-variables
'flags' - substitution flags (i - ignore case, g - global)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="subst usage"
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


- *'/re/repl/flags'* (string) - sed like regular 
				expression. flags can be a combination of i (case insensitive),
				g (global) or s (match newline don't treat it as end of line).
're' - is regular expression
'repl' - is replacement string - may contain pseudo-variables
'flags' - substitution flags (i - ignore case, g - global)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="subst_uri usage"
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


- *'/re/repl/flags'* (string) - sed like regular
				expression. flags can be a combination of i (case insensitive),
				g (global) or s (match newline don't treat it as end of line).
're' - is regular expression
'repl' - is replacement string - may contain pseudo-variables
'flags' - substitution flags (i - ignore case, g - global)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="subst usage"
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


- *'/re/repl/flags'* (string) - sed like regular
				expression. flags can be a combination of i (case insensitive),
				g (global) or s (match newline don't treat it as end of line).
're' - is regular expression
'repl' - is replacement string - may contain pseudo-variables
'flags' - substitution flags (i - ignore case, g - global)


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="subst_body usage"
...
if (subst_body("/^o=([^ ]*) /o=$fU /"))
	xlog("successfully prepared an "o" line update!\n");

...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
