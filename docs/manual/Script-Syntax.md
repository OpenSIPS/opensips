---
title: "Script Syntax"
description: "The OpenSIPs configuration script has three main logical parts:"
---

## Script Format

The OpenSIPs configuration script has three main logical parts:

* global parameters 
* modules section
* routing logic

---

### Global parameters

Usually, in the first part, you declare the [OpenSIPS global parameters](Script-CoreParameters.md) - these global or core parameters are affecting the OpenSIPS core and possible the modules.

Configuring the network listeners, available transport protocols, forking (and number of processes), the logging and other global stuff is provided by these global parameters.

Example:

```opensips

disable_tcp = yes
listen = udp:192.168.3.00:5060
listen = udp:192.168.3.00:5070
fork = yes
children = 4
log_stderror = no

```

---

#### Modules section

In regards to the OpenSIPS modules,the modules that are to be loaded (no module is loaded by default) are specified by using the directive **loadmodule**. Modules are to be specified by name and an optional path (to the *.so* file). If no path is provided (and just the name of the module), the default path will be assumed for locating the loading the module (default path is */usr/lib/opensips/modules* if not other one configured at [compile time](Install-CompileAndInstall.md). For configuring a different path, either the path is pushed directly with the module name (to get control per module) or it can be globally (for all modules) configured via the **mpath** global parameter.  
\
Once the modules are loaded, the parameters of the modules may be set using the **modparam** directive - to list of available parameters for each module, the type of parameter value (integer or string) can be found in the [documentation of the modules](Modules.md), the *Parameters* section.

Examples:
```opensips

loadmodule "modules/mi_datagram/mi_datagram.so"
modparam("mi_datagram", "socket_name", "udp:127.0.0.1:4343")
modparam("mi_datagram", "children_count", 3)

```

or 

```opensips

mpath="/usr/local/opensips_proxy/lib/modules"
loadmodule "mi_datagram.so"
modparam("mi_datagram", "socket_name", "udp:127.0.0.1:4343")
modparam("mi_datagram", "children_count", 3)
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "/tmp/opensips_fifo")

```

---

#### Routing logic

The routing logic is actually a sum of routes (script routes) that contain the OpenSIPS logic for routing SIP traffic. The description of **OpenSIPS behavior in relation to the SIP traffic** is done via this routes.  
\
There are different types of routes : 
* **top routes** - routes that are directly triggered by OpenSIPs when some events occurs (like SIP request received, SIP reply received, transaction failed, etc)
* **sub-routes** - routes that are triggered / used from other routes in script.
  

What are the existing **top routes**, when they are triggered, what kind of SIP messages is handled, what SIP operations are allowed and other are documented in the [types of routes section](Script-Routes.md).  
\
The **sub-routes** have names and they are to be called from any other route (top or sub) in the script via their names. The **sub-routes** may take parameters (when called) or return a numerical code (avoid returning 0 value as this will terminate your whole script. The **sub-routes** are similar to functions / procedure in any programing language.
See the [description of the *route*](Script-CoreFunctions.md#route) directive.

## Data Types

The OpenSIPS scripting language supports the following data types:

### Basic

* *integer* (32-bit, signed).
  * Max value: +2,147,483,647 == 2 ^ 31 - 1
  * Min value: -2,147,483,648 == - 2 ^ 31
* *string* (unlimited size)
  * note that some functions which use strings may have internal buffers which limit the maximum size of the strings (e.g. the [xlog()](https://docs.opensips.org/manual/3-0/script-corefunctions#xlog) function's output buffer is configurable via [xlog_buf_size](https://docs.opensips.org/manual/3-0/script-coreparameters))
* *double* (packed as string), through the **[mathops](../../modules/mathops/README.md)** module

### Complex

* *list* via the **[`$avp` variable](https://docs.opensips.org/manual/3-0/script-corevar#avp_variables)**
* *map* via the **[`$json`](../../modules/json/README.md#pv_json)** and **[`$xml`](../../modules/xml/README.md#pv_xml)** variables

## Function Calling Conventions

A significant portion of *opensips.cfg* scripting logic consists of **functions**.  Currently, there are two types of functions:

### Core Functions

The [core functions](https://docs.opensips.org/manual/3-0/script-corefunctions) are always available at script level, since they are baked into the **opensips** binary.  The calling convention for these functions varies greatly from one function to another, since each function is individually provided by the language parser.

#### Example core function calls:

  

```text

cache_raw_query("mongodb", "{ \"op\" : \"count\",\"query\": { \"username\" : $rU} }", "$avp(mongo_count_result)");

```

... will look up the specified document within MongoDB and return the results in `$avp(mongo_count_result)`.

  

```text

cache_fetch("redis:cluster1", "my_counter", $var(redis_counter_val));

```

... will look up "my_counter" within Redis and return the results in `$avp(redis_counter_val)`.  Notice how the output parameter is unquoted for this function, while the previous one, *cache_raw_query()*, had a similar meaning for its equivalent parameter, yet mandated quotes.

  

```text

force_send_socket(tcp:10.10.10.10:5060);

```

... will force the egress interface to be tcp:10.10.10.10:5060.  Notice how its parameter is not a string -- in fact, it's a unique data type (a socket), as the Yacc grammar interprets it.

  

**Summary**: OpenSIPS core functions are very useful, but are often inflexible: their parameters must have the exact type(s) as expected by the language grammar.  There are plans to align the core function and module function interfaces (the latter is more powerful, see below) -- this work is scheduled for OpenSIPS 3.1.  Script writers are advised to carefully consult the specifics of each core function while keeping in mind that consistency across core functions, if any, is only due to diligent collaboration between OpenSIPS developers, and is not the result of some internal programming interface.

#### Module Functions

[Module functions](https://docs.opensips.org/manual/3-0/function-index) become available for OpenSIPS script writers to use once their respective modules are loaded via the **loadmodule** statement (see the "Script Format" section above).  All module functions implement the same internal function interface, such that they benefit from the following, more sophisticated calling convention:

  

* **any integer or string function parameter may also be passed using a "holder" variable**

```text

ds_select_dst(1, 1); 

```

... is equivalent to:

```text

$var(x) = 1;
ds_select_dst($var(x), $var(x));

```

  

* **any string function parameter can also be passed as a format string**

```text

set_dlg_profile("caller", "$var(country_code)_$var(area)_$fU");

```

  

> [!NOTE]
> literal "$" characters can be included in a format string using the "$$" escape sequence

  

* **input or output variables passed to functions must not be quoted**:

```text

ds_count(1, "a", $var(out_result));

```

  

* **integers no longer need to be passed as double-quoted strings**:

```text del={2-2}
# this is deprecated
ds_select_dst("1", "1");
```

```text

ds_select_dst(1, 1);

```

**Summary**: module functions currently benefit from a more powerful calling convention than core functions.  This enables a greater flexibility when passing parameters to these functions, while additionally ensuring a greater degree of consistency across all such functions.
