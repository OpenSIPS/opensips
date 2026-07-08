---
title: "Regex Module"
description: "This module offers matching operations against regular expressions using the powerful [PCRE](http://www.pcre.org/) library."
---

## Admin Guide


### Overview


This module offers matching operations against regular expressions using the
			powerful [PCRE](http://www.pcre.org/) library.


A text file containing regular expressions categorized in groups is compiled
			when the module is loaded, storing the compiled PCRE objects in an array. A
			function to match a string or pseudo-variable against any of these groups is
			provided. The text file can be modified and reloaded at any time via a MI command.
			The module also offers a function to perform a PCRE matching operation against a
			regular expression provided as function parameter.


For a detailed list of PCRE features read the
			[man page](http://www.pcre.org/pcre.txt) of the library.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
				OpenSIPS with this module loaded:


- *libpcre-dev - the development libraries of [PCRE](http://www.pcre.org/)*.


### Exported Parameters


#### file (string)


Text file containing the regular expression groups. It must be set in order
				to enable the group matching function.


*Default value is "NULL".*


```opensips title="Set file parameter"
...
modparam("regex", "file", "/etc/opensips/regex_groups")
...
```


#### max_groups (int)


Max number of regular expression groups in the text file.


*Default value is "20".*


```opensips title="Set max_groups parameter"
...
modparam("regex", "max_groups", 40)
...
```


#### group_max_size (int)


Max content size of a group in the text file.


*Default value is "8192".*


```opensips title="Set group_max_size parameter"
...
modparam("regex", "group_max_size", 16384)
...
```


#### pcre_caseless (int)


If this options is set, matching is done caseless. It is equivalent to
				Perl's /i option, and it can be changed within a pattern by a (?i) or
				(?-i) option setting.


*Default value is "0".*


```opensips title="Set pcre_caseless parameter"
...
modparam("regex", "pcre_caseless", 1)
...
```


#### pcre_multiline (int)


By default, PCRE treats the subject string as consisting of a single line
				of characters (even if it actually contains newlines). The "start of line"
				metacharacter (^) matches only at the start of the string, while the "end
				of line" metacharacter ($) matches only at the end of the string, or before
				a terminating newline.


When this option is set, the "start of line" and "end of line" constructs
				match immediately following or immediately before internal newlines in the
				subject string, respectively, as well as at the very start and end. This is
				equivalent to Perl's /m option, and it can be changed within a pattern by a
				(?m) or (?-m) option setting. If there are no newlines in a subject string,
				or no occurrences of ^ or $ in a pattern, setting this option has no effect.


*Default value is "0".*


```opensips title="Set pcre_multiline parameter"
...
modparam("regex", "pcre_multiline", 1)
...
```


#### pcre_dotall (int)


If this option is set, a dot metacharater in the pattern matches all characters,
				including those that indicate newline. Without it, a dot does not match when
				the current position is at a newline. This option is equivalent to Perl's /s
				option, and it can be changed within a pattern by a (?s) or (?-s) option setting.


*Default value is "0".*


```opensips title="Set pcre_dotall parameter"
...
modparam("regex", "pcre_dotall", 1)
...
```


#### pcre_extended (int)


If this option is set, whitespace data characters in the pattern are totally
				ignored except when escaped or inside a character class. Whitespace does not
				include the VT character (code 11). In addition, characters between an
				unescaped # outside a character class and the next newline, inclusive, are
				also ignored. This is equivalent to Perl's /x option, and it can be changed
				within a pattern by a (?x) or (?-x) option setting.


*Default value is "0".*


```opensips title="Set pcre_extended parameter"
...
modparam("regex", "pcre_extended", 1)
...
```


### Exported Functions


#### pcre_match (string, pcre_regex [, match])


Matches the given string parameter against the regular expression pcre_regex,
				which is compiled into a PCRE object. Returns TRUE if it matches, FALSE
				otherwise. When the optional match parameter is provided, it is set to
				the matched part of the string, or cleared if there is no match.


Meaning of the parameters is as follows:


- *string* - String to compare.
- *pcre_regex* (string) - Regular expression to be compiled
						in a PCRE object.
- *match* (var, optional) - Writable pseudo-variable
						where the matched part of the string is stored.


NOTE: To use the "end of line" symbol '$' in the pcre_regex parameter use '$$'.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE,
				BRANCH_ROUTE and LOCAL_ROUTE.


```opensips title="pcre_match usage (forcing case insensitive)"
...
if (pcre_match("$ua", "(?i)^twinkle")) {
    xlog("L_INFO", "User-Agent matches\n");
}
...
```


```opensips title="pcre_match usage (using 'end of line' symbol)"
...
if (pcre_match($rU, "^user[1234]$$")) {  # Will be converted to "^user[1234]$"
    xlog("L_INFO", "RURI username matches\n");
}
...
```


#### pcre_match_group (string [, group])


It uses the groups readed from the text file
				(see [file format id](#file_format)) to match the given string
				parameter against the compiled regular expression in group number group.
				Returns TRUE if it matches, FALSE otherwise.


Meaning of the parameters is as follows:


- *string* - String to compare.
- *group* (int) - group to use in the operation.
						If not specified then 0 (the first group) is used.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE,
				BRANCH_ROUTE and LOCAL_ROUTE.


```opensips title="pcre_match_group usage"
...
if (pcre_match_group($rU, 2)) {
    xlog("L_INFO", "RURI username matches group 2\n");
}
...
```


### Exported MI Functions


#### regex:reload


Replaces obsolete MI command: *regex_reload*.


Causes regex module to re-read the content of the text file
				and re-compile the regular expressions. The number of groups
				in the file can be modified safely.


Name: *regex:reload*


Parameters: *none*


MI FIFO Command Format:


```bash
...
opensips-cli -x mi regex:reload
...
```


#### regex:match


Replaces obsolete MI command: *regex_match*.


Matches the given string parameter against the regular expression pcre_regex.
				Returns "Match" if it matches, "Not Match" otherwise.


Name: *regex:match*


Parameters:


- string
- pcre_regex


MI FIFO Command Format:


```bash
...
opensips-cli -x mi regex:match string="1234" pcre_regex="^1234$"
"Match"
opensips-cli -x mi regex:match string="1234" pcre_regex="^1235$"
"Not Match"
...
```


#### regex:match_group


Replaces obsolete MI command: *regex_match_group*.


It uses the groups readed from the text file to match the given string parameter against the compiled
				regular expression in group number group. Returns "Match" if it matches, "Not Match" otherwise.


Name: *regex:match_group*


Parameters:


- string
- group


MI FIFO Command Format:


```bash
...
opensips-cli -x mi regex:match_group string="1234" group="0"
"Match"
opensips-cli -x mi regex:match_group string="1234" group="1"
"Not Match"
...
```


### Installation and Running


#### File format


The file contains regular expressions categorized in groups. Each
				group starts with "[number]" line. Lines starting by space, tab,
				CR, LF or # (comments) are ignored. Each regular expression must
				take up just one line, this means that a regular expression can't
				be splitted in various lines.


An example of the file format would be the following:


```c title="regex file"
### List of User-Agents publishing presence status
[0]

# Softphones
^Twinkle/1
^X-Lite
^eyeBeam
^Bria
^SIP Communicator
^Linphone

# Deskphones
^Snom

# Others
^SIPp
^PJSUA


### Blacklisted source IP's
[1]

^190\.232\.250\.226$
^122\.5\.27\.125$
^86\.92\.112\.


### Free PSTN destinations in Spain
[2]

^1\d{3}$
^((\+|00)34)?900\d{6}$
```


The module compiles the text above to the following regular
				expressions:


```c
group 0: ((^Twinkle/1)|(^X-Lite)|(^eyeBeam)|(^Bria)|(^SIP Communicator)|
          (^Linphone)|(^Snom)|(^SIPp)|(^PJSUA))
group 1: ((^190\.232\.250\.226$)|(^122\.5\.27\.125$)|(^86\.92\.112\.))
group 2: ((^1\d{3}$)|(^((\+|00)34)?900\d{6}$))
```


The first group can be used to avoid auto-generated PUBLISH (pua_usrloc
				module) for UA's already supporting presence:


```opensips title="Using with pua_usrloc"
route[REGISTER] {
    if (! pcre_match_group("$ua", 0)) {
        xlog("L_INFO", "Auto-generated PUBLISH for $fu ($ua)\n");
        pua_set_publish();
    }
    save("location");
    exit;
}
```


NOTE: It's important to understand that the numbers in each group
				header ([number]) must start by 0. If not, the real group number
				will not match the number appearing in the file. For example, the
				following text file:


```c title="Incorrect groups file"
[1]
^aaa
^bbb

[2]
^ccc
^ddd
```


will generate the following regular expressions:


```c
group 0: ((^aaa)|(^bbb))
group 1: ((^ccc)|(^ddd))
```


Note that the real index doesn't match the group number in the file. This
				is, compiled group 0 always points to the first group in the file, regardless
				of its number in the file. In fact, the group number appearing in the file is
				used for nothing but for delimiting different groups.


NOTE: A line containing a regular expression cannot start by '[' since it
				would be treated as a new group. The same for lines starting by space, tab,
				or '#' (they would be ignored by the parser). As a workaround, using brackets
				would work:


```c
[0]
([0-9]{9})
( #abcde)
( qwerty)
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
