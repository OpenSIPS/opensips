---
title: "Presence User Agent Module"
description: "This module offer the internal support for OpenSIPS to act as a Presence User Agent client, by sending Subscribe and Publish messages."
---

## Admin Guide


### Overview


This module offer the internal support for OpenSIPS to act as a 
		Presence User Agent client, by sending Subscribe and Publish messages.


Note that the module does NOT provide any functionality to be used
	directly from the script, but it is providing this PUA client support
	(via an internal API) for other event-specific modules to do PUA 
	client operations.


Some of modules build on top of the PUA module are pua_mi, pua_usrloc,
		 pua_dialoginfo, pua_bla and pua_xmpp.
		 The pua_mi offer the possibility to publish any kind of information
		 or subscribing to a resource through fifo. The pua_usrloc module calls
		 a function exported by pua modules to publish elementary presence
		 information, such as basic status "open" or "closed", for clients that
		 do not implement client-to-server presence.
		 The pua_dialoginfo provideds BLF support, by publishing the status of
		 the participants into a call (like ringing, established, terminated).
		 Through pua_bla , BRIDGED LINE APPEARANCE features are added to 
		 OpenSIPs.
		 The pua_xmpp module represents a gateway between SIP and XMPP, so 
		 that jabber and SIP clients can exchange presence information.


The module use cache to store presentity list and writes to database
		on timer to be able to recover upon restart.


Notice: This module must not be used in no fork mode (the locking 
		mechanism used may cause deadlock in no fork mode).


### PUA clustering


Starting 3.2, the module was extended with clustering support also. This 
	means multiple OpenSIPS instance, configured with PUA module, may work 
	together. For example, the publishing for a certain presentity may be done 
	via different node (PUA OpenSIPS instance) in the cluster.


The clustering support is a mixture of DB sharing and OpenSIPS clustering.
	The OpenSIPS clustering layer is used for broadcasting notifications with 
	the cluster when a presentity is modified by one of the nodes (so that, 
	the other nodes in cluster may refresh the presentity via DB.


The shared DB is used by sharing between the nodes the actual presentity
	data. A node caches into memory only the presentities created by the node
	or the presentitites the node worked with. A presentity record may be
	loaded into memory (from DB) if the node needs to perform an operation 
	with that presentity.


IMPORTANT: because the actual presentity data is shared between the nodes
	via DB (the clustering layer is used for notifications only), it is
	important to set a very low update interval for the DB (for data being
	flushed from memoryc cache into DB), to get the DB content updated as 
	realtime as possible. See the the [update period](#param_update_period),
	module parameter, with recomanded values like 2-5 seconds.


On the OpenSIPS clustering layer, the PUA module use the sharing-tags
	mechanism in order to control (between all the nodes in the cluster) which
	node is responsible for performing the expiring operation on the
	presentity (like sending the PUBLISH with expires 0).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database modules*.
- *tm*.
- *clusterer*, if the cluster_id 
				module parameter is set and clustering support activated.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libxml*.


### Exported Parameters


#### hash_size (int)


The size of the hash table used for storing Subscribe and 
		Publish information. 
        This parameter will be used as the power of 2 when computing table size.


*Default value is "9".*


```opensips title="Set hash_size parameter"
...
modparam("pua", "hash_size", 11)
...
```


#### db_url (str)


Database url.


*Default value is ">mysql://opensips:opensipsrw@localhost/opensips".*


```opensips title="Set db_url parameter"
...
modparam("pua", "db_url" "dbdriver://username:password@dbhost/dbname")
...
```


#### db_table (str)


The name of the database table.


*Default value is "pua".*


```opensips title="Set db_table parameter"
...
modparam("pua", "db_table", "pua")
...
```


#### min_expires (int)


The inferior expires limit for both Publish and Subscribe.


*Default value is "300".*


```opensips title="Set min_expires parameter"
...
modparam("pua", "min_expires", 0)
...
```


#### default_expires (int)


The default expires value used in case this information is not provisioned.


*Default value is "3600".*


```opensips title="Set default_expires parameter"
...
modparam("pua", "default_expires", 3600)
...
```


#### update_period (int)


The interval at which the information in database and hash table
		should be updated. In the case of the hash table updating is 
		deleting expired messages.


*Default value is "30".*


IMPORTANT - if you use clustering support for this module, set a low
		value here, like 2-5, see the clustering chapter above.


```opensips title="Set update_period parameter"
...
modparam("pua", "update_period", 100)
...
```


#### cluster_id (int)


The cluster ID where the PUA data should be replicated/shared.
		This parameter is to be used only if clustering mode is needed.
		In order to understand the concept of a cluster ID, please see the 
		*clusterer* module.


For more on PUA clustering see the 
		[pua clustering](#pua_clustering) chapter.


*Default value is "None".*


```opensips title="Set cluster_id parameter"
...
modparam("pua", "cluster_id", 10)
...
```


#### cluster_sharing_tag (int)


The clustering share-tag to be used by the PUA module when creating
		any new presentity record. The tag will by used to decide which
		OpenSIPS instance (owning the tag as active) will be responsible
		for expiring this presentity.
		This parameter is to be used only if clustering mode is needed.
		In order to understand the concept of sharing TAG, please see the 
		*clusterer* module.


For more on PUA clustering see the 
		[pua clustering](#pua_clustering) chapter.


*Default value is "NULL".*


```opensips title="Set cluster_sharing_tag parameter"
...
modparam("pua", "cluster_sharing_tag", "vip")
...
```


### Exported Functions


#### pua_update_contact()


The remote target can be updated by the Contact of a subsequent in
		dialog request. In the PUA watcher case (sending a SUBSCRIBE messages),
		this means that the remote target for the following Subscribe messages
		can be updated at any time by the contact of a Notify message. 
		If this function is called on request route on receiving a Notify
		message, it will try to update the stored remote target.


This function can be used from REQUEST_ROUTE.


*Return code:*


- *1 - if success*.
- *-1 - if error*.


```opensips title="pua_update_contact usage"
...
if($rm=="NOTIFY")
    pua_update_contact();
...
```


### Installation


The module requires 1 table in OpenSIPS database: pua. The SQL 
	syntax to create it can be found in presence_xml-create.sql     
	script in the database directories in the opensips/scripts folder.
	You can also find the complete database documentation on the
	project webpage, [https://opensips.org/docs/db/db-schema-devel.html](https://opensips.org/docs/db/db-schema-devel.html).


## Developer Guide


The module provides the following functions that can be used
		in other OpenSIPS modules.


### bind_pua(pua_api_t* api)


This function binds the pua modules and fills the structure 
				with the two exported function.


```c title="pua_api structure"
...
typedef struct pua_api {
	send_subscribe_t send_subscribe;
	send_publish_t send_publish;
	query_dialog_t is_dialog;
	register_puacb_t register_puacb;
	add_pua_event_t add_event;
} pua_api_t;
...
```


### send_publish


Field type:


```c
...
typedef int (*send_publish_t)(publ_info_t* publ);
...
				
```


This function receives as a parameter a structure with Publish 
			required information and sends a Publish message.


The structure received as a parameter:


```c
...
typedef struct publ_info

  str id;             /*  (optional )a value unique for one combination
                          of pres_uri and flag */
  str* pres_uri;      /*  the presentity uri */	
  str* body;          /*  the body of the Publish message; 
                          can be NULL in case of an update expires*/ 	
  int  expires;       /*  the expires value that will be used in
                          Publish Expires header*/	
  int flag;           /*  it can be : INSERT_TYPE or UPDATE_TYPE
                          if missing it will be established according 
                          to the result of the search in hash table*/ 	
  int source_flag;    /*  flag identifying the resource ;
                          supported values: UL_PUBLISH, MI_PUBLISH,
                          BLA_PUBLISH, XMPP_PUBLISH*/
  int event;          /*  the event flag;
                          supported values: PRESENCE_EVENT, BLA_EVENT,
                          MWI_EVENT */
  str content_type;   /*  the content_type of the body if present
                          (optional if the same as the default value
                          for that event)*/
  str* etag;          /*  (optional) the value of the etag the request
                          should match */
  str* extra_headers  /*  (optional) extra_headers that should be added
                          to Publish msg*/
  publrpl_cb_t* cbrpl;/*  callback function to be called when receiving
                          the reply for the sent request */
  void* cbparam;      /*  extra parameter for tha callback function */

  str outbound_proxy; /*  the outbound proxy to be used when sending
							the Publish request*/

}publ_info_t;
...
		
```


The callback function type:


```c
...
typedef int (publrpl_cb_t)(struct sip_msg* reply, void*  extra_param);
...
		
```


### send_subscribe


Field type:


```c
...
typedef int (*send_subscribe_t)(subs_info_t* subs);
...
```


This function receives as a parameter a structure with Subscribe 
			required information and sends a Subscribe message.


The structure received as a parameter:


```c
...
typedef struct subs_info

  str id;              /*  an id value unique for one combination
                           of pres_uri and flag */
  str* pres_uri;       /*  the presentity uri */	
  str* watcher_uri;    /*  the watcher uri */
  str* contact;        /*  the uri that will be used in
                           Contact header*/  
  str* remote_target;  /*  the uri that will be used as R-URI
                           for the Subscribe message(not compulsory;
                           if not set the value of the pres_uri field
                           is used) */
  str* outbound_proxy; /*  the outbound_proxy to use when sending the 
                           Subscribe request*/
  int event;           /*  the event flag; supported value: 
                           PRESENCE_EVENT, BLA_EVENT, PWINFO_EVENT*/ 
  int expires;         /*  the expires value that will be used in
                           Subscribe Expires header */	
  int flag;            /*  it can be : INSERT_TYPE or UPDATE_TYPE
                           not compulsory */	
  int source_flag;     /*  flag identifying the resource ;
                           supported values:  MI_SUBSCRIBE, 
                           BLA_SUBSCRIBE, XMPP_SUBSCRIBE,
                           XMPP_INITIAL_SUBS */
}subs_info_t;
...
```


### is_dialog


Field type:


```c
...
typedef int  (*query_dialog_t)(ua_pres_t* presentity);
...
				
```


This function checks is the parameter corresponds to a stored
			Subscribe initiated dialog.


```opensips title="pua_is_dialog usage example"
...	
	if(pua_is_dialog(dialog) < 0)
	{
		LM_ERR("querying dialog\n");
		goto error;
	}
...	
```


### register_puacb


Field type:


```c
...
typedef int (*register_puacb_t)(int types, pua_cb f, void* param );
...
				
```


This function registers a callback to be called on receiving the reply message
			for a sent Subscribe request.
			The type parameter should be set the same as the source_flag for that request.
			The function registered as callback for pua should be of type pua_cb , which is:
			typedef void (pua_cb)(ua_pres_t* hentity, struct msg_start * fl);
			The parameters are the dialog structure for that request and the first line of the
			reply message.


```c title="register_puacb usage example"
...
	if(pua.register_puacb(XMPP_SUBSCRIBE, Sipreply2Xmpp, NULL) & 0)
	{
		LM_ERR("Could not register callback\n");
		return -1;
	}
...	
	
```


### add_event


Field type:


```c
...
typedef int (*add_pua_event_t)(int ev_flag, char* name, 
   char* content_type,evs_process_body_t* process_body);

- ev_flag     : an event flag defined as a macro in pua module		
- name        : the event name to be used in Event request headers
- content_type: the default content_type for Publish body for 
                that event (NULL if winfo event)
- process_body: function that processes the received body before 
                using it to construct the PUBLISH request
                (NULL if winfo event)
...
				
```


This function allows registering new events to the pua module.
			Now there are 4 events supported by the pua module: presence, 
			presence;winfo, message-summary, dialog;sla. These events are registered
			from within the pua module.


Filed type for process_body:


```c
...
typedef int (evs_process_body_t)(struct publ_info* publ, 
  str** final_body, int ver, str* tuple);
- publ      : the structure received as a parameter in send_publish 
              function ( initial body found in publ->body)
- final_body: the pointer where the result(final_body) should be stored 
- ver       : a counter for the sent Publish requests
              (used for winfo events)
- tuple     : a unique identifier for the resource;
              if an initial Publish it should be returned as a result
              and it will be stored  for that record, otherwise it will
              be given as a parameter;    
...
				
```


```c title="add_event usage example"
...
	if(pua.add_event((PRESENCE_EVENT, "presence", "application/pidf+xml", 
				pres_process_body) & 0)
	{
		LM_ERR("Could not register new event\n");
		return -1;
	}
...	
	
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
