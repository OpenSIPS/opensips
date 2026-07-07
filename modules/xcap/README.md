---
title: "XCAP Module"
description: "The module contains several parameters and functions common to all modules using XCAP capabilities."
---

## Admin Guide


### Overview


The module contains several parameters and functions common to all
        modules using XCAP capabilities.


The module is currently used by the following modules: presence_xml, rls and xcap_client.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database module*.


### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libxml-dev*.


### Exported Parameters


#### db_url(str)


The database url.


*Default value is "mysql://opensips:opensipsrw@localhost/opensips".*


```opensips title="Set db_url parameter"
...
modparam("xcap", "db_url", "dbdriver://username:password@dbhost/dbname")
...
                
```


#### xcap_table(str)


The name of the db table where XCAP documents are stored.


*Default value is "xcap".*


```opensips title="Set xcap_table parameter"
...
modparam("xcap", "xcap_table", "xcap")
...
                
```


#### integrated_xcap_server (int)


This parameter is a flag for the type of XCAP server or servers 
		used. If integrated ones, like OpenXCAP from AG Projects, 
		with direct access to database table, the parameter should be
		set to a positive value. Apart from updating in xcap table,
		the integrated server must send an MI command refershWatchers 
		[pres_uri] [event] when a user modifies a rules document.


*Default value is "0".*


```opensips title="Set integrated_xcap_server parameter"
...
modparam("xcap", "integrated_xcap_server", 1)
...
                
```


### Exported Functions


None to be used in configuration file.


## Developer Guide


The module exports a number of parameters and functions that are used
            in several other modules.


### bind_xcap_api(xcap_api_t* api)


This function allows binding the needed functions.


```c title="xcap_api structure"
...
typedef struct xcap_api {
        int integrated_server;
        str db_url;
        str xcap_table;
        normalize_sip_uri_t normalize_sip_uri;
        parse_xcap_uri_t parse_xcap_uri;
        get_xcap_doc_t get_xcap_doc;
} xcap_api_t;
...
			
```


### normalize_xcap_uri


This function normalizes a SIP URI found in a XCAP document. It un-escapes it and
                    adds the SIP scheme in case it was missing. Returns a statically allocated string
                    buffer containing the normalized form.


Parameters:


- *uri*-
				the URI that needs to be normalized


### parse_xcap_uri


This function parses the given XCAP URI.


Parameters:


- *uri*-
				the URI that needs to be parsed in string format
- *xcap_uri*-
				xcap_uri_t structure that will be filled with the parsed information

  ```
  Parameter type:
  ...
  typedef struct {
      char buf[MAX_URI_SIZE];
      str uri;
      str root;
      str auid;
      str tree;
      str xui;
      str filename;
      str selector;
  } xcap_uri_t;
  ...
                          
  ```


### get_xcap_doc


This function queries the local DB for the required XCAP document. It will return the document and its
                    corresponding etag.


Parameters:


- *user*-
				user part od the URI of the document owner
- *domain*-
				domain part od the URI of the document owner
- *type*-
                                type of the requested document, represents the AUID, can be one of PRES_RULES, RESOURCE_LISTS,
                                RLS_SERVICES, PIDF_MANIPULATION, OMA_PRES_RULES
- *filename*-
				if specified it will be used to match the document filename, it defaults to 'index'
- *match_etag*-
				if specified the document is only returned its etag matches this one
- *doc*-
				reference to the storage for the returned document
- *etag*-
				reference to the storage for the returned document's etag


### db_url


URL of the database to which the XCAP mdoules witll connect.


### xcap_table


Name of the table used to store XCAP documents. Defaults to 'xcap'.


### integrated_server


Boolean flag indicating if the XCAP server has access to the local database or
                xcap_client will be used to fetch documents.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
