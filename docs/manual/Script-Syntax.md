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
listen = udp:192.168.4.10:5060
listen = udp:192.168.4.10:5070
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
See the [description of the *route*](Script-CoreFunctions.md#setuser) directive.

## Data Types

The OpenSIPS scripting language supports the following data types:

### Basic

* *integer* (32-bit, signed).
  * Max value: +2,147,483,647 == 2 ^ 31 - 1
  * Min value: -2,147,483,648 == - 2 ^ 31
* *string* (unlimited size)
  * note that some functions which use strings may have internal buffers which limit the maximum size of the strings (e.g. the [xlog()](https://docs.opensips.org/manual/devel/script-corefunctions#socket_belongs_to_bond) function's output buffer is configurable via [xlog_buf_size](https://docs.opensips.org/manual/devel/script-coreparameters#udp_workers))
* *double* (packed as string), through the **[mathops](../../modules/mathops/README.md)** module

### Complex

* *list* via the **[`$avp` variable](https://docs.opensips.org/manual/devel/script-corevar#avp_variables)**
* *map* via the **[`$json`](../../modules/json/README.md#pv_json)** and **[`$xml`](../../modules/xml/README.md#pv_xml)** variables

## Function Calling Conventions
All OpenSIPS [core](https://docs.opensips.org/manual/devel/script-corefunctions) and [module](https://docs.opensips.org/manual/devel/function-index) functions internally share the same function interface, such that they benefit from the following calling convention:

  

* **any integer or string function parameter may also be passed using a "holder" variable**

```opensips

ds_select_dst(1, 1); 

```

... is equivalent to:

```opensips

$var(x) = 1;
ds_select_dst($var(x), $var(x));

```

  

* **any string function parameter can be passed as a format string**

```opensips

set_dlg_profile("caller", "$var(country_code)_$var(area)_$fU");

```

  

Literal **"$"** characters can be included in a format string using the **"$$"** escape sequence

  

> [!NOTE]
> There still are a few exceptions for the conventions above in the case of string parameters, due to performance optimizations, as some functions still require some parameters to be plain, static strings (e.g. *save("location")*).  Such cases will be noted in the function's documentation.

  

* **input or output variables passed to functions must not be quoted**:

```opensips

ds_count(1, "a", $var(out_result));

```

  

* **integers no longer need to be passed as double-quoted strings**:

```opensips del={2-2}
# this is deprecated
ds_select_dst("1", "1");
```

```opensips

ds_select_dst(1, 1);

```
