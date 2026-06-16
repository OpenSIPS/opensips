---
title: "gflags Module"
description: "gflags module (global flags) keeps a bitmap of flags in shared memory and may be used to change behaviour of server based on value of the flags. Example: ```c if (is_gflag(1)) { t_relay(\"udp:10.0.0.1:5060\"); } else { t_relay(\"udp:10.0.0.2:5060\"); } ```"
---

## Admin Guide


### Overview


gflags module (global flags) keeps a bitmap of flags in shared memory
	and may be used to change behaviour of server based on value of the flags.
	Example:


```c
	if (is_gflag(1)) {
		t_relay("udp:10.0.0.1:5060");
	} else {
		t_relay("udp:10.0.0.2:5060");
	}
	
```


The benefit of this module is the value of the switch flags
	can be manipulated by external applications such as web interface
	or command line tools. The size of bitmap is 32.


The module exports external commands that can be used to change
	the global flags via Management Interface. The MI commands are:
	"set_gflag", "reset_gflag" and
	"is_gflag".


### Dependencies


The module depends on the following modules (in the other words the
		listed modules must be loaded before this module):


- *none*


### Exported Parameters


#### initial (integer)


The initial value of global flags bitmap.


Default value is "0".


```c title="initial parameter usage"
modparam("gflags", "initial", 15)
		
```


### Exported Functions


#### set_gflag(flag)


Set the bit at the position "flag" in global flags.


The "flag" (int) parameter can have a value in the range of 0..31.


This function may be used from any route.


```c title="set_gflag() usage"
...
set_gflag(4);
...
```


#### reset_gflag(flag)


Reset the bit at the position "flag" in global flags.


The "flag" (int) parameter can have a value in the range of 0..31.


This function may be used from any route.


```c title="reset_gflag() usage"
...
reset_gflag(4);
...
```


#### is_gflag(flag)


Check if bit at the position "flag" in global flags is
		set.


The "flag" (int) parameter can have a value in the range of 0..31.


This function may be used from any route.


```c title="is_gflag() usage"
...
if(is_gflag(4))
{
	log("global flag 4 is set\n");
} else {
	log("global flag 4 is not set\n");
};
...
```


### Exported MI Functions


Functions that check or change some flags accepts one parameter 
			which is the flag bitmap/mask specifing the corresponding flags.
			It is not possible to specify directly the flag position that 
			should be changed as in the functions available in the routing 
			script.


#### set_gflag


Set the value of some flags (specified by bitmask) to 1.


The parameter value must be a bitmask in decimal or hexa format.
			The bitmaks has a 32 bit size.


```c title="set_gflag usage"
...
$ opensips-cli -x mi set_gflag 1
$ opensips-cli -x mi set_gflag 0x3
...
```


#### reset_gflag


Reset the value of some flags to 0.


The parameter value must be a bitmask in decimal or hexa format.
			The bitmaks has a 32 bit size.


```c title="reset_gflag usage"
...
$ opensips-cli -x mi reset_gflag 1
$ opensips-cli -x mi reset_gflag 0x3
...
```


#### is_gflag


Returns true if the all the flags from the bitmask are set.


The parameter value must be a bitmask in decimal or hexa format.
			The bitmaks has a 32 bit size.


The function returns TRUE if all the flags from the set are set
			and FALSE if at least one is not set.


```c title="is_gflag usage"
...
$ opensips-cli -x mi set_gflag 1024
$ opensips-cli -x mi is_gflag 1024
TRUE
$ opensips-cli -x mi is_gflag 1025
TRUE
$ opensips-cli -x mi is_gflag 1023
FALSE
$ opensips-cli -x mi set_gflag 0x10
$ opensips-cli -x mi is_gflag 1023
TRUE
$ opensips-cli -x mi is_gflag 1007
FALSE
$ opensips-cli -x mi is_gflag 16
TRUE
...
```


#### get_gflags


Return the bitmap with all flags. The function gets no 
			parameters and returns the bitmap in hexa and decimal format.


```c title="get_gflags usage"
...
$ opensips-cli -x mi get_gflags
0x3039
12345
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
