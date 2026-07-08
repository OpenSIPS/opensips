---
title: "XCAP_Client Module"
description: "The modules is an XCAP client for OpenSIPS that can be used by other modules. It fetches XCAP elements, either documents or part of them, by sending HTTP GET requests. It also offers support for conditional queries. It uses libcurl library as a client-side HTTP transfer library."
---

## Admin Guide


### Overview


The modules is an XCAP client for OpenSIPS that can be used by other modules.
	It fetches XCAP elements, either documents or part of them, by sending 
	HTTP GET requests. It also offers support for conditional queries.
	It uses libcurl library as a client-side HTTP transfer library.


The module offers an xcap client interface with general functions that
	allow requesting for an specific element from an xcap server.
	In addition to that it also offers the service of storing and update
	in database the documents it receives. In this case only an initial
	request to the module is required - xcapGetNewDoc-which is like a 
	request to the module to handle from that point on the referenced
	document so as to promise that the newest version will always be
	present in database.


The update method is also configurable, 
	either through periodical queries, applicable to any kind of xcap
	server or with an MI command that should be sent by the server
	upon an update.


The module is currently used by the presence_xml module, if the 
	'integrated_xcap_server' parameter is not set.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *xcap*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libxml-dev*.
- *libcurl-dev*.


### Exported Parameters


#### periodical_query(int)


A flag to disable periodical query as an update method for
		the documents the module is responsible for. It could be
		disabled when the xcap server is capable to send the exported
		MI command when a change occurs or when another module in OpenSIPS
		handles updates.


To disable it set this parameter to 0.


*Default value is "1".*


```opensips title="Set periodical_query parameter"
...
modparam("xcap_client", "periodical_query", 0)
...
```


#### query_period(int)


Should be set if periodical query is not disabled. 
		Represents the time interval the xcap servers should be 
		queried for an update


To disable it set this parameter to 0.


*Default value is "100".*


```opensips title="Set query_period parameter"
...
modparam("xcap_client", "query_period", 50)
...
```


### Exported Functions


None to be used in configuration file.


### Exported MI Functions


#### refreshXcapDoc


MI command that should be sent by an xcap server when a
		stored document changes.


Name: *refreshXcapDoc*


Parameters:


- doc_uri: the uri of the document
- port: the port of the xcap server


MI FIFO Command Format:


```bash
...
opensips-cli -x mi refreshXcapDoc /xcap-root/resource-lists/users/eyebeam/buddies-resource-list.xml 8000
...
		
```


## Developer Guide


The module exports a number of functions that allow selecting 
		and retrieving an element from an xcap server and also registering
		a callback to be called when a MI command refreshXcapDoc is received
		and the document in question is retrieved.


### bind_xcap_client_api(xcap_client_api_t* api)


This function allows binding the needed functions.


```c title="xcap_client_api structure"
...
typedef struct xcap_client_api {
	
	/* xcap node selection and retrieving functions*/
	xcap_get_elem_t get_elem;
	xcap_nodeSel_init_t int_node_sel;
	xcap_nodeSel_add_step_t add_step;
	xcap_nodeSel_add_terminal_t add_terminal;
	xcap_nodeSel_free_t free_node_sel;
	xcapGetNewDoc_t getNewDoc; /* an initial request for the module 
	fo fetch this document that does not exist in xcap db table
	and handle its update*/

	/* function to register a callback to document changes*/
	register_xcapcb_t register_xcb;
}xcap_client_api_t;
...
			
```


### get_elem


Field type:


```c
...
typedef char* (*xcap_get_elem_t)(char* xcap_root,
xcap_doc_sel_t* doc_sel, xcap_node_sel_t* node_sel);
...
				
```


This function sends a HTTP request and gets the specified information
			from the xcap server.


The parameters signification:


- *xcap_root*-
				the XCAP server address;
- *doc_sel*-
				structure with document selection info;

  ```
  Parameter type:
  ...
  typedef struct xcap_doc_sel
  {
  	str auid; /* application defined Unique ID*/
  	int type; /* the type of the path segment
  				after the AUID  which must either
  				be GLOBAL_TYPE (for "global") or
  				USERS_TYPE (for "users") */ 
  	str xid; /* the XCAP User Identifier 
  				if type is USERS_TYPE */
  	str filename; 
  }xcap_doc_sel_t;
  ...
  ```
- *node_sel*-
structure with node selection info;

  ```
  Parameter type:
  ...
  typedef struct xcap_node_sel
  {
  	step_t* steps;
  	step_t* last_step;
  	int size;
  	ns_list_t* ns_list;
  	ns_list_t* last_ns;
  	int ns_no;
  
  }xcap_node_sel_t;
  
  typedef struct step
  {
  	str val;
  	struct step* next;
  }step_t;
  
  typedef struct ns_list
  {
  	int name;
  	str value;
  	struct ns_list* next;
  }ns_list_t;
  ...
  ```
The node selector is represented like a list of steps that will
		be represented in the path string separated by '/' signs. 
		The namespaces for the nodes are stored also in a list, as an
		association of name and value, where the value is to be included
		in the respective string val field of the step.
To construct the node structure the following functions in the xcap_api
		structure should be used: 'int_node_sel', 'add_step' and if needed, 
		'add_terminal'.
If the intention is to retrieve the whole document this argument must
		be NULL.


### register_xcb


Field type:


```c
...
typedef int (*register_xcapcb_t)(int types, xcap_cb f);
...
	
```


- 'types' parameter can have a combined value of PRES_RULES, RESOURCE_LISTS,
	RLS_SERVICES, OMA_PRES_RULES and PIDF_MANIPULATION.


-the callback function has type :


```c
...
typedef int (xcap_cb)(int doc_type, str xid, char* doc);
...
	
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
