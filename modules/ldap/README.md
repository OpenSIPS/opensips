---
title: "LDAP Module"
description: "The LDAP module implements an LDAP search interface for OpenSIPS. It exports script functions to perform an LDAP search operation and to store the search results as OpenSIPS AVPs. This allows for using LDAP directory data in the OpenSIPS SIP message routing script."
---

## Admin Guide


### Overview


The LDAP module implements an LDAP search interface for OpenSIPS. It exports script functions to perform an LDAP search operation and to store the search results as OpenSIPS AVPs. This allows for using LDAP directory data in the OpenSIPS SIP message routing script.


The following features are offered by the LDAP module:


- LDAP search function taking an LDAP URL as input both synchronous and asynchronous
- LDAP result parsing functions to store LDAP data as AVP
- Support for accessing multiple LDAP servers
- LDAP SIMPLE authentication
- LDAP server failover and automatic reconnect
- Configurable LDAP connection and bind timeouts
- Module API for LDAP search operations that can be used by other OpenSIPS modules
- StartTLS support


The module implementation makes use of the open source OpenLDAP library available on most UNIX/Linux platforms. Besides LDAP server failover and automatic reconnect, this module can handle multiple LDAP sessions concurrently allowing to access data stored on different LDAP servers. Each OpenSIPS worker process maintains one LDAP TCP connection per configured LDAP server. This enables parallel execution of LDAP requests and offloads LDAP concurrency control to the LDAP server(s).


An LDAP search module API is provided that can be used by other OpenSIPS modules. A module using this API does not have to implement LDAP connection management and configuration, while still having access to the full OpenLDAP API for searching and result handling.


Since LDAP server implementations are optimized for fast read access they are a good choice to store SIP provisioning data. Performance tests have shown that this module achieves lower data access times and higher call rates than other database modules like e.g. the OpenSIPS MYSQL module.


#### Usage Basics


First so called LDAP sessions have to be specified in an external configuration file (as described in [ldap config](#ldap_configuration_file)). Each LDAP session includes LDAP server access parameters like server hostname or connection timeouts. Normally only a single LDAP session will be used unless there is a need to access more than one LDAP server. The LDAP session name will then be used in the OpenSIPS configuration script to refer to a specific LDAP session.


The `ldap_search` function ([ldap search fn](#func_ldap_search)) performs an LDAP search operation. It expects an LDAP URL as input which includes the LDAP session name and search parameters. [ldap urls](#ldap_urls)  provides a quick overview on LDAP URLs.


The result of an LDAP search is stored internally and can be accessed with one of the `ldap_result*` functions. `ldap_result` ([ldap result fn](#func_ldap_result)) stores resulting LDAP attribute value as AVPs. `ldap_result_check` ([ldap result check fn](#func_ldap_result_check)) is a convenience function to compare a string with LDAP attribute values using regular expression matching. Finally, `ldap_result_next` ([ldap result next fn](#func_ldap_result_next)) allows to handle LDAP search queries that return more than one LDAP entry.


All `ldap_result*` functions do always access the LDAP result set from the last `ldap_search` call. This should be kept in mind when calling `ldap_search` more than once in the OpenSIPS configuration script.


#### LDAP URLs


`ldap_search` expects an LDAP URL as argument. This section describes the format and semantics of an LDAP URL.


RFC 4516 [RFC4516](#RFC4516) describes the format of an LDAP Uniform Resource Locator (URL). An LDAP URL represents an LDAP search operation in a compact format. The LDAP URL format is defined as follows (slightly modified, refer to section 2 of [RFC4516](#RFC4516) for ABNF notation):


`ldap://[ldap_session_name][/dn?attrs[?scope[?filter]]]]`


**`ldap_session_name`**


An LDAP session name as defined in the LDAP
              configuration file.


(RFC 4516 defines this as LDAP hostport parameter)


**`dn`**


Base Distinguished Name (DN) of LDAP search or target of
              non-search operation, as defined in RFC 4514 [RFC4514](#RFC4514)


**`attrs`**


Comma separated list of LDAP attributes to be
              returned


**`scope`**


Scope for LDAP search, valid values are
              "base", "one", or
              "sub"


**`filter`**


LDAP search filter definition following rules of RFC 4515
				  [RFC4515](#RFC4515)


> [!NOTE]
> The following table lists characters that have to be
                  escaped in LDAP search filters:


> [!NOTE]
> Non-URL characters in an LDAP URL have to be escaped using
          percent-encoding (refer to section 2.1 of RFC 4516). In particular
	  this means that any "?" character in an LDAP URL component must be
	  written as "%3F", since "?" is used as a URL delimiter. The exported function `ldap_filter_url_encode` ([ldap filter url encode fn](#func_ldap_filter_url_encode))
	  implements RFC 4515/4516 LDAP search filter and URL escaping
	  rules.


### Dependencies


#### OpenSIPS Modules


The module depends on the following modules (the listed modules
        must be loaded before this module):


- *No dependencies on other OpenSIPS modules.*


#### External Libraries or Applications


The following libraries or applications must be installed before
        running OpenSIPS with this module loaded:


- OpenLDAP library (libldap) v2.1 or greater, libldap header files
            (libldap-dev) are needed for compilation


### LDAP Configuration File


The module reads an external confiuration file at module
      initialization time that includes LDAP session definitions.


#### Configuration File Syntax


The configuration file follows the Windows INI file syntax,
        section names are enclosed in square brackets:


```c
[Section_Name]
```


Any
        section can contain zero or more configuration key assignments of the
        form


```c
key = value ; comment
```


Values can
        be given enclosed with quotes. If no quotes are present, the value is
        understood as containing all characters between the first and the last
        non-blank characters. Lines starting with a hash sign and blank lines
        are treated as comments.


Each section describes one LDAP session that can be referred to
        in the OpenSIPS configuration script. Using the section name as the
        host part of an LDAP URL tells the module to use the LDAP session
        specified in the respective section. An example LDAP session
        specification looks like:


```c
[example_ldap]
ldap_server_url            = "ldap://ldap1.example.com, ldap://ldap2.example.com"
ldap_bind_dn               = "cn=sip_proxy,ou=accounts,dc=example,dc=com"
ldap_bind_password         = "pwd"
ldap_network_timeout       = 500
ldap_client_bind_timeout   = 500
ldap_ca_cert_file		   = "/usr/share/ca-certificates/mycert.pem"
ldap_cert_file			   = "/var/my-certificate/certificate.pem"
ldap_key_file			   = "/var/my-certificate/key.pem"
ldap_require_certificate   = "ALLOW"
```


The configuration keys are
        explained in the following section. This LDAP session can be referred
        to in the routing script by using an LDAP URL like
        e.g.


```c
ldap://example_ldap/cn=admin,dc=example,dc=com
```


#### LDAP Session Settings


**ldap_server_url (mandatory)**


LDAP URL including fully qualified domain name or IP address of LDAP server optionally followed by a colon and TCP port to connect: `ldap://<FQDN/IP>[:<port>]`. Failover LDAP servers can be added, each separated by a comma. In the event of connection errors, the module tries to connect to servers in order of appearance.


Default value: none, this is a mandatory setting


```c title="ldap_server_url examples"
ldap_server_url = "ldap://localhost"
ldap_server_url = "ldap://ldap.example.com:7777"
ldap_server_url = "ldap://ldap1.example.com,
                   ldap://ldap2.example.com:80389"
				
```


**ldap_version (optional)**


Supported LDAP versions are 2 and 3.


Default value: `3` (LDAPv3)


```c title="ldap_version example"
ldap_version = 2
```


**ldap_bind_dn (optional)**


Authentication user DN used to bind to LDAP server (module
              currently only supports SIMPLE_AUTH). Empty string enables
              anonymous LDAP bind.


Default value: "" (empty string -->
              anonymous bind)


```c title="ldap_bind_dn example"
ldap_bind_dn = "cn=root,dc=example,dc=com";
```


**ldap_bind_password (optional)**


Authentication password used to bind to LDAP server
              (SIMPLE_AUTH). Empty string enables anonymous bind.


Default value: "" (empty string -->
              anonymous bind)


```c title="ldap_bind_password example"
ldap_bind_password = "secret";
```


**ldap_network_timeout (optional)**


LDAP TCP connect timeout in milliseconds. Setting this
              parameter to a low value enables fast failover if `ldap_server_url` contains more than one LDAP server addresses.


Default value: 1000 (one second)


```c title="ldap_network_timeout example"
ldap_network_timeout = 500 ; setting TCP timeout to 500 ms
```


**ldap_client_bind_timeout (optional)**


LDAP bind operation timeout in milliseconds.


Default value: 1000 (one second)


```c title="ldap_client_bind_timeout example"
ldap_client_bind_timeout = 1000
```


**ldap_ca_cert_file (optional)**


LDAP full path of the CA certificate file.


No default value. It is mandatory in case you wish to use StartTLS


```c title="ldap_ca_cert_file example"
ldap_ca_cert_file = "/usr/local/CAcert.pem"
```


**ldap_cert_file (optional)**


LDAP full path of the certificate file.


No default value. It is mandatory in case you wish to use StartTLS


```c title="ldap_cert_file example"
ldap_cert_file = "/usr/local/mycert.pem"
```


**ldap_key_file (optional)**


LDAP full path of the key file.


No default value. It is mandatory in case you wish to use StartTLS


```c title="ldap_key_file example"
ldap_key_file = "/usr/local/mykey.pem"
```


**ldap_require_certificate (optional)**


LDAP peer certificate checking strategy, one of "NEVER", "HARD", "DEMAND", "ALLOW", "TRY".
						Lower case letters are also accepted.


Default value "NEVER".


```c title="ldap_require_certificate example"
ldap_require_certificate = "NEVER"
```


#### Configuration File Example


The following configuration file example includes two LDAP
        session definitions that could be used e.g. for accessing H.350 data
        and do phone number to name mappings.


```c title="Example LDAP Configuration File"
# LDAP session "sipaccounts":
#
# - using LDAPv3 (default)
# - two redundant LDAP servers
#
[sipaccounts]
ldap_server_url = "ldap://h350-1.example.com, ldap://h350-2.example.com"
ldap_bind_dn = "cn=sip_proxy,ou=accounts,dc=example,dc=com"
ldap_bind_password = "pwd"
ldap_network_timeout = 500
ldap_client_bind_timeout = 500
#using StartTLS
ldap_ca_cert_file = "/ldap/path/to/ca/certificate.pem"
ldap_cert_file = "/ldap/path/to/certificate.pem"
ldap_key_file = "/ldap/path/to/key/file.pem"
ldap_require_certificate = "NEVER"


# LDAP session "campus":
#
# - using LDAPv2
# - anonymous bind
#
[campus]
ldap_version = 2
ldap_server_url = "ldap://ldap.example.com"
ldap_network_timeout = 500
ldap_client_bind_timeout = 500
			
```


### Exported Parameters


#### config_file (string)


Full path to LDAP configuration file.


Default value:
        `/usr/local/etc/opensips/ldap.cfg`


```opensips title="config_file parameter usage"
modparam("ldap", "config_file", "/etc/opensips/ldap.ini")
		  
```


#### max_async_connections (int)


Number of maximum asynchronous connections that will be started
			  with the ldap server for executing asynchronous ldap_search calls.
			  The number of connections is per process, so if there are 8
			  worker processes with 20 max_async_connections, there will be a
			  maximum of 160 connections to the ldap server.


Default value: `20`


```opensips title="max_async_connections parameter usage"
modparam("ldap", "max_async_connections", 50)
		  
```


### Exported Functions


#### ldap_search(ldap_url)


Performs an LDAP search operation using given LDAP URL and stores result
        internally for later retrieval by `ldap_result*` functions. If one ore
        more LDAP entries are found the function returns the number of found
        entries which evaluates to TRUE in the OpenSIPS configuration script.
        It returns `-1` (`FALSE`) in case no
        LDAP entry was found, and `-2`
        (`FALSE`) if an internal error like e.g. an LDAP
        error occurred.


**`ldap_url (string)`**


An LDAP URL defining the LDAP search operation (refer to
			  [ldap urls](#ldap_urls) for a description of the LDAP URL
              format). The hostport part must be one of the LDAP session names
              declared in the LDAP configuration script.


Search with LDAP session named
                `sipaccounts`, base
                `ou=sip,dc=example,dc=com`,
                `one` level deep using search filter
                `(cn=schlatter)` and returning all
                attributes:


```c title="Example Usage of ldap_url"
ldap://sipaccounts/ou=sip,dc=example,dc=com??one?(cn=schlatter)
```


Subtree search with LDAP session named
                `ldap1`, base
                `dc=example,dc=com` using search filter
                `(cn=$(avp(name)))` and returning
                `SIPIdentityUserName` and
                `SIPIdentityServiceLevel` attributes


```opensips title="Example Usage of ldap_url"
ldap://ldap_1/dc=example,dc=com?
       SIPIdentityUserName,SIPIdentityServiceLevel?sub?(cn=$(avp(name)))
	        
```


**`n` > 0 (TRUE):**


- Found `n` matching LDAP
                  entries


**`-1` (FALSE):**


- No matching LDAP entries found


**`-2` (FALSE):**


- LDAP error (e.g. LDAP server unavailable), or
- internal error


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE, and ONREPLY_ROUTE.


```opensips title="Example Usage"
...
# ldap search
if (!ldap_search("ldap://sipaccounts/ou=sip,dc=example,dc=com??one?(cn=$rU)"))
{
    switch ($retcode)
    {
    case -1:
        # no LDAP entry found
        sl_send_reply(404, "User Not Found");
        exit;
    case -2:
        # internal error
        sl_send_reply(500, "Internal server error");
        exit;
    default:
        exit;
    }
}
xlog("L_INFO", "ldap_search: found [$retcode] entries for (cn=$rU)");

# save telephone number in $avp(tel_number)
ldap_result("telephoneNumber/$avp(tel_number)");
...
			
```


#### ldap_result(ldap_attr_name, avp_spec, [avp_type], [regex_subst])


This function converts LDAP attribute values into AVPs for later
        use in the message routing script. It accesses the LDAP result set
        fetched by the last `ldap_search` call.
        `ldap_attr_name` specifies the LDAP attribute name
        who's value should be stored in AVP `avp_spec`. Multi
        valued LDAP attributes generate an indexed AVP. The optional
        `regex_subst` parameter allows to further define what
        part of an attribute value should be stored as AVP.


An AVP can either be of type string or integer. As default, `ldap_result` stores LDAP attribute values as AVP of type string. The optional `avp_type` parameter can be used to explicitly specify the type of the AVP. It can be either `str` for string, or `int` for integer. If `avp_type` is specified as `int` then `ldap_result` tries to convert the LDAP attribute values to integer. In this case, the values are only stored as AVP if the conversion to integer is successful.


**ldap_attr_name (string)**


The name of the LDAP attribute who's value should be
              stored, e.g. `SIPIdentityServiceLevel` or
              `telephonenumber`


**avp_spec (var)**


Specification of destination AVP, e.g.
              `$avp(service_level)` or
              `$avp(12)`


**avp_type (string, optional)**


Specification of destination AVP type, either `str` or `int`. If this parameter is not specified then the LDAP attribute values are stored as AVP of type string.


**regex_subst (string)**


Regex substitution that gets applied to LDAP attribute
              value before storing it as AVP, e.g.
              `"/^sip:(.+)$/\1/"` to strip off "sip:" from
              the beginning of an LDAP attribute value.


**`n` > 0 (TRUE)**


LDAP attribute `ldap_attr_name` found in LDAP result set and `n` LDAP attribute values stored in `avp_spec`


**-1 (FALSE)**


No LDAP attribute `ldap_attr_name` found
              in LDAP result set


**-2 (FALSE)**


Internal error occurred


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE, and ONREPLY_ROUTE.


```opensips title="Example Usage"
...

# ldap_search call
...

# save SIPIdentityServiceLevel in $avp(service_level)
if (!ldap_result("SIPIdentityServiceLevel", $avp(service_level)))
{
    switch ($retcode)
    {
    case -1:
        # no SIPIdentityServiceLevel found
        sl_send_reply(403, "Forbidden");
        exit;
    case -2:
        # internal error
        sl_send_reply(500, "Internal server error");
        exit;
    default:
        exit;
    }
}

# save SIP URI domain in $avp(10)
ldap_result("SIPIdentitySIPURI", $avp(10), "/^[^@]+@(.+)$/\1/");
...
			
```


#### ldap_result_check(ldap_attr_name, string_to_match, [, regex_subst])


This function compares `ldap_attr_name`'s value
        with `string_to_match` for equality. It accesses the LDAP result set
        fetched by the last `ldap_search` call. The
        optional `regex_subst` parameter allows to further
        define what part of the attribute value should be used for the
        equality match. If `ldap_attr_name` is multi valued,
        each value is checked against `string_to_match`. If
        one or more of the values do match the function returns `1`
        (TRUE).


**ldap_attr_name (string)**


The name of the LDAP attribute who's value should be
              matched, e.g. `SIPIdentitySIPURI`


**string_to_match (string)**


String to be matched. Included AVPs and pseudo variabels
              do get expanded.


**regex_subst (string, optional)**


Regex substitution that gets applied to LDAP attribute
              value before comparing it with string_to_match, e.g.
              `"/^[^@]@+(.+)$/\1/"` to extract the domain part
              of a SIP URI


**1 (TRUE)**


One or more `ldap_attr_name` attribute values match
              `string_to_match` (after
              `regex_subst` is applied)


**-1 (FALSE)**


`ldap_attr_name` attribute not found or
              attribute value doesn't match `string_to_match`
              (after `regex_subst` is applied)


**-2 (FALSE)**


Internal error occurred


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE, and ONREPLY_ROUTE.


```opensips title="Example Usage"
...
# ldap_search call
...

# check if 'sn' ldap attribute value equals username part of R-URI,
# the same could be achieved with ldap_result_check("sn/$rU")
if (!ldap_result_check("sn", $ru, "/^sip:([^@]).*$/\1/"))
{
    switch ($retcode)
    {
    case -1:
        # R-URI username doesn't match sn
        sl_send_reply(401, "Unauthorized");
        exit;
    case -2:
        # internal error
        sl_send_reply(500, "Internal server error");
        exit;
    default:
        exit;
    }
}
...
			
```


#### ldap_result_next()


An LDAP search operation can return multiple LDAP entries. This
        function can be used to cycle through all returned LDAP entries. It
        returns 1 (TRUE) if there is another LDAP entry present in the LDAP
        result set and causes `ldap_result*` functions to work on the next LDAP
        entry. The function returns -1 (FALSE) if there are no more LDAP
        entries in the LDAP result set.


**1 (TRUE)**


Another LDAP entry is present in the LDAP result set and
              result pointer is incremented by one


**-1 (FALSE)**


No more LDAP entries are available


**`-2` (FALSE)**


Internal error


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE, and ONREPLY_ROUTE.


```opensips title="Example Usage"
...
# ldap_search call
...

ldap_result("telephonenumber/$avp(tel1)");
if (ldap_result_next())
{
	ldap_result("telephonenumber/$avp(tel2)");
}
if (ldap_result_next())
{
	ldap_result("telephonenumber/$avp(tel3)");
}
if (ldap_result_next())
{
	ldap_result("telephonenumber/$avp(tel4)");
}
...
			
```


#### ldap_filter_url_encode(string, avp_spec)


This function applies the following escaping rules to
        `string` and stores the result in AVP
        `avp_spec`:


**ldap_filter_url_encode() escaping rules**


| character in
                `string` | gets replaced with | defined in |
| --- | --- | --- |
| * | \2a | RFC 4515 |
| ( | \28 | RFC 4515 |
| ) | \29 | RFC 4515 |
| \ | \5c | RFC 4515 |
| ? | %3F | RFC 4516 |


The string stored in AVP `avp_spec` can be safely used in an LDAP
        URL filter string.


**`string`**


String to apply RFC 4515 and URL escpaing rules to.
	      AVPs and pseudo variables do get expanded. Example:
              `"cn=$avp(name)"`


**`avp_spec (var)`**


AVP to store resulting RFC 4515
	      and URL encoded string, e.g. `$avp(ldap_search)`
	      or `$avp(10)`


**`1` (TRUE)**


RFC 4515 and URL encoded
              `filter_component` stored as AVP
              `avp_name`


**`-1` (FALSE)**


Internal error


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE, and ONREPLY_ROUTE.


```opensips title="Example Usage"
...
if (!ldap_filter_url_encode("cn=$avp(name)", $avp(name_esc)))
{
    # RFC 4515/URL encoding failed --> silently discard request
    exit;
}

xlog("L_INFO", "encoded LDAP filter component: [$avp(name_esc)]\n");

if (ldap_search(
     "ldap://h350/ou=commObjects,dc=example,dc=com??sub?($avp(name_esc))"))
    { ... }
...
			
```


### Exported Asynchronous Functions


#### ldap_search(ldap_url)


Performs an LDAP search operation using given LDAP URL and stores result
        internally for later retrieval by `ldap_result*` functions. If one ore
        more LDAP entries are found the function returns the number of found
        entries which evaluates to TRUE in the OpenSIPS configuration script.
        It returns `-1` (`FALSE`) in case no
        LDAP entry was found, and `-2`
        (`FALSE`) if an internal error like e.g. an LDAP
        error occurred.


**`ldap_url (string)`**


An LDAP URL defining the LDAP search operation (refer to
			  [ldap urls](#ldap_urls) for a description of the LDAP URL
              format). The hostport part must be one of the LDAP session names
              declared in the LDAP configuration script.


Search with LDAP session named
                `sipaccounts`, base
                `ou=sip,dc=example,dc=com`,
                `one` level deep using search filter
                `(cn=schlatter)` and returning all
                attributes:


```c title="Example Usage of ldap_url"
ldap://sipaccounts/ou=sip,dc=example,dc=com??one?(cn=schlatter)
```


Subtree search with LDAP session named
                `ldap1`, base
                `dc=example,dc=com` using search filter
                `(cn=$(avp(name)))` and returning
                `SIPIdentityUserName` and
                `SIPIdentityServiceLevel` attributes


```opensips title="Example Usage of ldap_url"
ldap://ldap_1/dc=example,dc=com?
       SIPIdentityUserName,SIPIdentityServiceLevel?sub?(cn=$(avp(name)))
	        
```


**`n` > 0 (TRUE):**


- Found `n` matching LDAP
                  entries


**`-1` (FALSE):**


- No matching LDAP entries found


**`-2` (FALSE):**


- LDAP error (e.g. LDAP server unavailable), or
- internal error


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE, and ONREPLY_ROUTE.


```opensips title="Example Usage"
...
# ldap search

route {
	async( ldap_search("ldap://sipaccounts/ou=sip,dc=example,dc=com??one?(cn=$rU)"), resume);
}
....
route[resume] {
{
    switch ($rc)
    {
    case -1:
        # no LDAP entry found
        sl_send_reply(404, "User Not Found");
        exit;
    case -2:
        # internal error
        sl_send_reply(500, "Internal server error");
        exit;
    default:
        exit;
    }
    xlog("L_INFO", "ldap_search: found [$retcode] entries for (cn=$rU)");

    # save telephone number in $avp(tel_number)
    ldap_result("telephoneNumber", $avp(tel_number)");
...
}
			
```


### Installation & Running


#### Compiling the Module


OpenLDAP library (libldap) and header files (libldap-dev) v2.1 or greater (this module was tested with v2.1.3 and v2.3.32) are required for compiling the LDAP module. The OpenLDAP source is available at [http://www.openldap.org/](http://www.openldap.org/).


The OpenLDAP library is available pre-compiled for most UNIX/Linux flavors. On Debian/Ubuntu, the following packages must be installed:


```c
# apt-get install libldap2 libldap2-dev
```


.


## Developer Guide


### Overview


The LDAP module API can be used by other OpenSIPS modules to implement LDAP search functionality. This frees the module implementer from having to care about LDAP connection management and configuration.


In order to use this API, a module has to load the API using the `load_ldap_api` function which returns a pointer to a `ldap_api` structure. This structure includes pointers to the API functions described below. The LDAP module source file `api.h` includes all declarations needed to load the API, it has to be included in the file that loads the API. Loading the API is typically done inside a module's `mod_init` call as the following example shows:


```c title="Example code fragment to load LDAP module API"
#include "../../sr_module.h"
#include "../ldap/api.h"

/*
 * global pointer to ldap api
 */
extern ldap_api_t ldap_api;

...

static int mod_init(void)
{
    /*
     * load the LDAP API
     */
    if (load_ldap_api(&ldap_api) != 0)
    {
        LM_ERR("Unable to load LDAP API - this module requires ldap module\n");
        return -1;
    }

    ...
}

...
		
				
```


The API functions can then be used like in the following example:


```c title="Example LDAP module API function call"
...
	
    rc = ldap_api.ldap_rfc4515_escape(str1, str2, 0);	
				
...		
		
				
```


### API Functions


#### ldap_params_search


Performs an LDAP search using the parameters given as function arguments.


```c
typedef int (*ldap_params_search_t)(int* _ld_result_count,
                                    char* _lds_name,
                                    char* _dn,
                                    int _scope,
                                    char** _attrs,
                                    char* _filter,
                                    ...);

			
```


**int* _ld_result_count**


The function stores the number of returned LDAP entries in `_ld_result_count`.


**char* _lds_name**


LDAP session name as configured in the LDAP module configuration file.


**char* _dn**


LDAP search DN.


**int _scope**


LDAP search scope, one of `LDAP_SCOPE_ONELEVEL`, `LDAP_SCOPE_BASE`, or `LDAP_SCOPE_SUBTREE`, as defined in OpenLDAP's `ldap.h`.


**char** _attrs**


A null-terminated  array  of attribute types to return from entries. If empty (`NULL`), all attribute types are returned.


**char* _filter**


LDAP search filter string according to RFC 4515. `printf` patterns in this string do get replaced with the function arguments' values following the `_filter` argument.


**-1**


Internal error.


**0**


Success, `_ld_result_count` includes the number of LDAP entries found.


#### ldap_url_search


Performs an LDAP search using an LDAP URL.


```c
typedef int (*ldap_url_search_t)(char* _ldap_url,
                                 int* _result_count);

			
```


**char* _ldap_url**


LDAP URL as described in [ldap urls](#ldap_urls).


**int* _result_count**


The function stores the number of returned LDAP entries in `_ld_result_count`.


**-1**


Internal error.


**0**


Success, `_ld_result_count` includes the number of LDAP entries found.


#### ldap_result_attr_vals


Retrieve the value(s) of a returned LDAP attribute. The function accesses the LDAP result returned by the last call of `ldap_params_search` or `ldap_url_search`. The `berval` structure is defined in OpenLDAP's `ldap.h`, which has to be included.


This function allocates memory to store the LDAP attribute value(s). This memory has to freed with the function `ldap_value_free_len` (see next section).


```c
typedef int (*ldap_result_attr_vals_t)(str* _attr_name,
                                       struct berval ***_vals);
									   
typedef struct berval {
        ber_len_t       bv_len;
        char            *bv_val;
} BerValue;

			
```


**str* _attr_name**


`str` structure holding the LDAP attribute name.


**struct berval ***_vals**


A null-terminated array of the attribute's value(s).


**-1**


Internal error.


**0**


Success, `_vals` includes the attribute's value(s).


**1**


No attribute value found.


#### ldap_value_free_len


Function used to free memory allocated by `ldap_result_attr_vals`. The `berval` structure is defined in OpenLDAP's `ldap.h`, which has to be included.


```c
typedef void (*ldap_value_free_len_t)(struct berval **_vals);

typedef struct berval {
        ber_len_t       bv_len;
        char            *bv_val;
} BerValue;

			
```


**struct berval **_vals**


`berval` array returned by `ldap_result_attr_vals`.


#### ldap_result_next


Increments the LDAP result pointer.


```c
typedef int (*ldap_result_next_t)();

			
```


**-1**


No LDAP result found, probably because `ldap_params_search` or `ldap_url_search` was not called.


**0**


Success, LDAP result pointer points now to next result.


**1**


No more results available.


#### ldap_str2scope


Converts LDAP search scope string into integer value e.g. for `ldap_params_search`.


```c
typedef int (*ldap_str2scope_t)(char* scope_str);

			
```


**char* scope_str**


LDAP search scope string. One of "one", "onelevel", "base", "sub", or "subtree".


**-1**


`scope_str` not recognized.


**n >= 0**


LDAP search scope integer.


#### ldap_rfc4515_escape


Applies escaping rules described in [ldap filter url encode fn](#func_ldap_filter_url_encode).


```c
typedef int (*ldap_rfc4515_escape_t)(str *sin, str *sout, int url_encode);

			
```


**str *sin**


`str` structure holding the string to apply the escaping rules.


**str *sout**


`str` structure holding the escaped string. The length of this string must be at least three times the length of `sin` plus one.


**int url_encode**


Flag that specifies if a '?' character gets escaped with '%3F' or not. If `url_encode` equals `0`, '?' does not get escaped.


**-1**


Internal error.


**0**


Success, `sout` contains escaped string.


#### get_ldap_handle


Returns the OpenLDAP LDAP handle for a specific LDAP session. This allows a module implementor to use the OpenLDAP API functions directly, instead of using the API functions exported by the OpenSIPS LDAP module. The `LDAP` structure is defined in OpenLDAP's `ldap.h`, which has to be included.


```c
typedef int (*get_ldap_handle_t)(char* _lds_name, LDAP** _ldap_handle);

			
```


**char* _lds_name**


LDAP session name as specified in the LDAP module configuration file.


**LDAP** _ldap_handle**


OpenLDAP LDAP handle returned by this function.


**-1**


Internal error.


**0**


Success, `_ldap_handle` contains the OpenLDAP LDAP handle.


#### get_last_ldap_result


Returns the OpenLDAP LDAP handle and OpenLDAP result handle of the last LDAP search operation. These handles can be used as input for OpenLDAP LDAP result API functions. `LDAP` and `LDAPMessage` structures are defined in OpenLDAP's `ldap.h`, which has to be included.


```c
typedef void (*get_last_ldap_result_t)
	     (LDAP** _last_ldap_handle, LDAPMessage** _last_ldap_result);

			
```


**LDAP** _last_ldap_handle**


OpenLDAP LDAP handle returned by this function.


**LDAPMessage** _last_ldap_result**


OpenLDAP result handle returned by this function.


### Example Usage


The following example shows how this API can be used to perform an LDAP search operation. It is assumed that the API is loaded and available through the `ldap_api` pointer.


```c
...
	
int rc, ld_result_count, scope = 0;
char* sip_username = "test";

/*
 * get LDAP search scope integer
 */
scope = ldap_api.ldap_str2scope("sub");
if (scope == -1)
{
    LM_ERR("ldap_str2scope failed\n");
    return -1;
}

/*
 * perform LDAP search
 */

if (ldap_api.ldap_params_search(
       &ld_result_count,
       "campus",
       "dc=example,dc=com",
       scope,
       NULL,
       "(&(objectClass=SIPIdentity)(SIPIdentityUserName=%s))",
       sip_username)
     != 0)
{
    LM_ERR("LDAP search failed\n");
    return -1;
}

/*
 * check result count
 */
if (ld_result_count < 1)
{
    LM_ERR("LDAP search returned no entry\n");
    return 1;
}

/*
 * get password attribute value 
 */
 
struct berval **attr_vals = NULL;
str ldap_pwd_attr_name = str_init("SIPIdentityPassword");
str res_password;

rc = ldap_api.ldap_result_attr_vals(&ldap_pwd_attr_name, &attr_vals);
if (rc < 0)
{
    LM_ERR("ldap_result_attr_vals failed\n");
    ldap_api.ldap_value_free_len(attr_vals);
    return -1;
}
if (rc == 1)
{
    LM_INFO("No password attribute value found for [%s]\n", sip_username);
    ldap_api.ldap_value_free_len(attr_vals);
    return 2;
}

res_password.s = attr_vals[0]->bv_val;
res_password.len = attr_vals[0]->bv_len;

ldap_api.ldap_value_free_len(attr_vals);

LM_INFO("Password for user [%s]: [%s]\n", sip_username, res_password.s);

...

return 0;		

		
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
