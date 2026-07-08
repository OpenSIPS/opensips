---
title: "Presence Module"
description: "The modules handles PUBLISH and SUBSCRIBE messages and generates NOTIFY messages in a general, event independent way. It allows registering events from other OpenSIPS modules. Events that can currently be added are: *presence*, *presence.winfo*, *dialog;sla* from presence_xml module *mes..."
---

## Admin Guide


### Overview


The modules handles PUBLISH and SUBSCRIBE messages and generates
	NOTIFY messages in a general, event independent way. It allows registering 
	events from other OpenSIPS modules. Events that can currently be added are:


- *presence*, *presence.winfo*,
		*dialog;sla* from presence_xml module
- *message-summary* from presence_mwi module
- *call-info*, *line-seize* from
		presence_callinfo module
- *dialog* from presence_dialoginfo module
- *xcap-diff* from presence_xcapdiff module
- *as-feature-event* from presence_dfks module


The module uses database storage. 
	It has later been improved with memory caching operations to improve
	performance. The Subscribe dialog information are stored in memory and 
	are periodically updated in database, while for Publish only the presence
	or absence of stored info for a certain resource is maintained in memory
	to avoid unnecessary, costly db operations. 
	It is possible to configure a fallback to database mode(by setting module
	parameter "fallback2db"). In this mode, in case a searched record is not 
	found in cache, the search is continued	in database. This is useful for
	an architecture in which processing and memory load might be divided on 
	more machines using the same database.


The module can also work only with the functionality of a library,
	with no message processing and generation, but used only for the exported
	functions.
	This mode of operation is enabled if the db_url parameter is not set to any value.


The server follows the specifications in: RFC3265, RFC3856, RFC3857, 
	RFC3858.


### Presence clustering


To read and understand the presence clustering, its abilities and how to
	implement scenarios like High-Availability, Load Balancing or Federations,
	please refer to this article [https://blog.opensips.org/2018/03/27/clustering-presence-services-with-opensips-2-4/](https://blog.opensips.org/2018/03/27/clustering-presence-services-with-opensips-2-4/).


As data synchronization at startup is performed when using the
	*full-sharing* [cluster federation mode](#param_cluster_federation_mode),
	you should define at least one "seed" node in the cluster in this case.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database module*.
- *signaling*.
- *clusterer*, if the cluster_id 
				module parameter is set and clustering support activated.


#### External Libraries or Applications


- *libxml-dev*.


### Exported Parameters


#### db_url(str)


The database url.


If set, the module is a fully operational
		presence server. Otherwise, it is used as a 'library', for 
		its exported functions.


*Default value is "NULL".*


```opensips title="Set db_url parameter"
...
modparam("presence", "db_url", 
	"mysql://opensips:opensipsrw@192.168.2.132/opensips")
...
```


#### fallback2db (int)


Setting this parameter enables a fallback to db mode of operation.
		In this mode, in case a searched record is not found in cache, 
		the search is continued	in database. Useful for an architecture in
		which processing and memory load might be divided on more machines
		using the same database.


```opensips title="Set fallback2db parameter"
...
modparam("presence", "fallback2db", 1)
...
```


#### cluster_id (int)


The ID of the cluster this presence server belongs to. This parameter
		is to be used only if clustering mode is needed. In order to
		understand th concept of a cluster ID, please see the 
		*clusterer* module.


This OpenSIPS cluster exposes the **"presence"**
capability in order to mark nodes as eligible for becoming data donors during an
arbitrary sync request. Consequently, the cluster must have *at least
one node* marked with the **"seed"** value
as the *clusterer.flags* column/property in order to be fully functional.
Consult the [clusterer - Capabilities](../clusterer#capabilities)
chapter for more details.


For more on presence clustering see the 
		[presence clustering](#presence_clustering) chapter.


*Default value is "None".*


```opensips title="Set cluster_id parameter"
...
modparam("presence", "cluster_id", 2)
...
```


#### cluster_federation_mode (str)


When enabling the federation mode, nodes inside the presence
		cluster will start broadcasting the data to other nodes via the
		clustering support.


*Possible values:*


- *disabled* - federation mode is disabled
- *on-demand-sharing* - the minimum needed information is
				kept on each node. Replicated information for non local
				subscribers is discarded and queries are broadcasted
				in the cluster for new subscribers.
- *full-sharing* - published state is kept on all presence
				nodes even when there aren't any local subscribers.


If you don't want to use a shared database (via
		[fallback2db](#param_fallback2db)), but still want a
		complete data set everywhere, you may choose mode *full-sharing*.
		This mode allows you to switch PUBLISH endpoints,
		even for already published Event States, thus allowing
		you to add and remove presence servers without losing
		state.


For more on presence clustering see the 
		[presence clustering](#presence_clustering) chapter.


*Default value is "disabled".*


```opensips title="Set cluster_federation_mode parameter"
...
modparam("presence", "cluster_federation_mode", "full-sharing")
...
```


#### cluster_pres_events (str)


Comma Separated Value (CSV) list with the events to considered by the
		federated cluster - only presentities advertising one of these events
		will be broadcasted via the cluster.


For more on presence clustering see the 
		[presence clustering](#presence_clustering) chapter.


*Default value is "empty" (meaning all).*


```opensips title="Set cluster_pres_events parameter"
...
modparam("presence", "cluster_pres_events" ,"presence, dialog;sla, message-summary")
...
```


#### cluster_be_active_shtag (str)


The name of a cluster sharing tag to be used to indicate when this
		node (as part of the cluster) should be active or not. If the sharing
		tag is off (or as backup), the node will become inactive from 
		clustering perspective, meaning not sending and not accepting any
		presence related cluster traffic.


This ability of a node to become inactive may be used when creating a
		federated cluster where 2 nodes are acting as a local active-backup 
		setup (for local High Availability purposes).


This parameter has meaning only in clustering mode. If not defined, the
		node will be active all the time.


For more on presence clustering see the 
		[presence clustering](#presence_clustering) chapter.


*Default value is "empty" (not tag define).*


```opensips title="Set cluster_be_active_shtag parameter"
...
modparam("presence", "cluster_be_active_shtag" ,"local_ha")
...
```


#### expires_offset (int)


The extra time to store a subscription/publication.


*Default value is "0".*


```opensips title="Set expires_offset parameter"
...
modparam("presence", "expires_offset", 10)
...
```


#### max_expires_subscribe (int)


The the maximum admissible expires value for SUBSCRIBE
		messages.


*Default value is "3600".*


```opensips title="Set max_expires_subscribe parameter"
...
modparam("presence", "max_expires_subscribe", 3600)
...
```


#### max_expires_publish (int)


The the maximum admissible expires value for PUBLISH
		messages.


*Default value is "3600".*


```opensips title="Set max_expires_publish parameter"
...
modparam("presence", "max_expires_publish", 3600)
...
```


#### contact_user (str)


This is the username that will be used in the Contact header for the 200 OK
		replies to SUBSCRIBE and in the following in-dialog NOTIFY requests.
		The IP address, port and transport for the Contact will be automatically
		determined based on the interface where the SUBSCRIBE was received.


If set to an empty string, no username will be added to the contact and
		the contact will be built just out of the IP, port and transport.


*Default value is "presence".*


```opensips title="Set contact_user parameter"
...
modparam("presence", "contact_user", "presence")
...
		
```


#### enable_sphere_check (int)


This parameter is a flag that should be set if permission rules 
		include sphere checking. The sphere information is expected to be 
		present in the RPID body published by the presentity. The flag is 
		introduced as this check requires extra processing that should be 
		avoided if this feature is not supported by the clients.


*Default value is "0 ".*


```opensips title="Set enable_sphere_check parameter"
...
modparam("presence", "enable_sphere_check", 1)
...
	
```


#### waiting_subs_daysno (int)


The number of days to keep the record of a subscription in server
			database if the subscription is in pending or waiting state 
			(no authorization policy was defined for it or the target user 
			did not register sice the subscription and was not informed about
			it).


*Default value is "3" days. Maximum accepted
			value is 30 days.*


```opensips title="Set waiting_subs_daysno parameter"
...
modparam("presence", "waiting_subs_daysno", 2)
...
	
```


#### mix_dialog_presence (int)


This module parameter enables a very nice feature in the presence 
		server - generating presence information from dialogs state. If this 
		parameter is set, the presence server will tell you if a buddy is in 
		a call even if his phone did not send a presence Publish with this 
		information. You will need to load the dialoginfo modules, 
		presence_dialoginfo, pua_dialoginfo, dialog and pua.


*Default value is "0".*


```opensips title="Set mix_dialog_presence parameter"
...
modparam("presence", "mix_dialog_presence", 1)
...
	
```


#### bla_presentity_spec (str)


By default the presentity uri for BLA subscribes (event=dialog;sla)
			is computed from contact username + from domain. In some cases 
			though, this way of computing the presentity might not be right 
			(for example if you have a SBC in front that masquerades the 
			contact). So we added this parameter that allows defining a custom 
			uri to be used as presentity uri for BLA subscribes. You should 
			set this parameter to the name of a pseudovariable and then set 
			this pseudovariable to the desired URI before calling the
			[handle subscribe](#func_handle_subscribe) function.


*Default value is "NULL".*


```opensips title="Set bla_presentity_spec parameter"
...
modparam("presence", "bla_presentity_spec", "$var(bla_pres)")
...
	
```


#### bla_fix_remote_target (int)


Polycom has a bug in the bla implementation. It inserts the 
			remote IP contact in the Notify body and when a phone picks up a 
			call put on hold by another phone in the same BLA group, it sends 
			an Invite directly to the remote IP. OpenSIPS BLA server tries to 
			prevent this by replacing the IP contact with the
			domain, when this is possible.


In some cases(configurations) however this is not desirable, so 
			this parameter was introduced to disable this behaviour when 
			needed.


*Default value is "1".*


```opensips title="Set bla_fix_remote_target parameter"
...
modparam("presence", "bla_fix_remote_target", 0)
...
	
```


#### notify_offline_body (int)


If this parameter is set, when no published info is found for
			a user, the presence server will generate a dummy body with status
			'closed' and use it when sending Notify, instead of notifying with
			no body.


*Default value is "0".*


```opensips title="Set notify_offline_body parameter"
...
modparam("presence", "notify_offline_body", 1)
...
	
```


#### end_sub_on_timeout (int)


If a presence subscription should be automatically terminated 
			(destroyed) when receiving a SIP timeout (408) for a sent
			NOTIFY requests.


*Default value is "1" (enabled).*


```opensips title="Set end_sub_on_timeout parameter"
...
modparam("presence", "end_sub_on_timeout", 0)
...
	
```


#### clean_period (int)


The period at which to clean the expired subscription dialogs.


*Default value is "100". A zero or negative 
		value disables this activity.*


```opensips title="Set clean_period parameter"
...
modparam("presence", "clean_period", 100)
...
```


#### db_update_period (int)


The period at which to synchronize cached subscriber info with the
		database.


*Default value is "100". A zero or negative 
		value disables synchronization.*


```opensips title="Set db_update_period parameter"
...
modparam("presence", "db_update_period", 100)
...
```


#### presentity_table(str)


The name of the db table where Publish information are stored.


*Default value is "presentity".*


```opensips title="Set presentity_table parameter"
...
modparam("presence", "presentity_table", "presentity")
...
```


#### active_watchers_table(str)


The name of the db table where active subscription information are 
		stored.


*Default value is "active_watchers".*


```opensips title="Set active_watchers_table parameter"
...
modparam("presence", "active_watchers_table", "active_watchers")
...
```


#### watchers_table(str)


The name of the db table where subscription states are stored.


*Default value is "watchers".*


```opensips title="Set watchers_table parameter"
...
modparam("presence", "watchers_table", "watchers")
...
```


#### subs_htable_size (int)


The size of the hash table to store subscription dialogs.
	This parameter will be used as the power of 2 when computing table size.


*Default value is "9 (512)".*


```opensips title="Set subs_htable_size parameter"
...
modparam("presence", "subs_htable_size", 11)
...
	
```


#### pres_htable_size (int)


The size of the hash table to store publish records.
	This parameter will be used as the power of 2 when computing table size.


*Default value is "9 (512)".*


```opensips title="Set pres_htable_size parameter"
...
modparam("presence", "pres_htable_size", 11)
...
	
```


### Exported Functions


#### handle_publish([sender_uri])


The function handles PUBLISH requests. It stores and updates 
		published information in database and calls functions to send 
		NOTIFY messages when changes in the published information occur.


It may takes one optional string argument, the 'sender_uri' SIP URI.
		The parameter was added 
		for enabling BLA implementation. If present, Notification of
		a change in published state is not sent to the respective uri
		even though a subscription exists.
		It should be taken from the Sender header. It was left at the
		decision of the administrator whether or not to transmit the 
		content of this header as parameter for handle_publish, to 
		prevent security problems.


This function can be used from REQUEST_ROUTE.


*Return code:*


- *1 - if success*.
- *-1 - if error*.


The module sends an appropriate stateless reply
			in all cases.


```opensips title="handle_publish usage"
...
	if(is_method("PUBLISH"))
	{
		if($hdr(Sender)!= NULL)
			handle_publish($hdr(Sender));
		else
			handle_publish();
	} 
...
```


#### handle_subscribe([force_active] [,sharing_tag])


This function is to be used for handling SUBSCRIBE requests. It stores
		or updates the watcher/subscriber information in database. 
		Additionally, in response to initial SUBSCRIBE requests (creating a 
		new subscription session), the function also sends back the NOTIFY 
		(with the presence information) to the wathcer/subscriber.


The function may take the following parameters:


- *force_active* (int, optional) - optional parameter that 
				controls what is the default policy (of the presentity) on 
				accepting new subscriptions (accept or reject) - of course, 
				this parameter makes sense only when using a presence 
				configuration with privacy rules enabled (force_active 
				parameter in presence_xml module is not set).
There are scenarios where the presentity (the party you 
				subscribe to) can not upload an XCAP document with its
				privacy rules (to control which watchers are allowed to 
				subscribe to it). In such cases, from script level, you can
				force the presence server to consider the current subscription
				allowed (with Subscription-Status:active) by calling the 
				handle_subscribe() function with the integer parameter "1".
- *sharing_tag* (string, optional) - optional parameter telling
				the owner tag (for the subscription) in clusetering scenarios 
				where the subscription data is shared between multiple 
				servers - see the [presence clustering](#presence_clustering)
				chapter for more details.


```opensips
   Ex: 
	if($ru =~ "kphone@opensips.org")
		handle_subscribe(1);
		
```


This function can be used from REQUEST_ROUTE.


*Return code:*


- *1 - if success*.
- *-1 - if error*.


The module sends an appropriate stateless reply
			in all cases.


```opensips title="handle_subscribe usage"
...
if($rm=="SUBSCRIBE")
    handle_subscribe();
...
```


### Exported MI Functions


#### refresh_watchers


Triggers sending Notify messages to watchers if a change in watchers
		authorization or in published state occurred.


Name: *refresh_watchers*


Parameters:


- presentity_uri : the uri of the user who made the change
				and whose watchers should be informed
- event : the event package
- refresh type : it distinguishes between the two different types of events
									that can trigger a refresh: 
									
									
									a change in watchers authentication: refresh type= 0 ;
									
									
									a statical update in published state (either through direct 
									update in db table or by modifying the pidf manipulation document,
									if pidf_manipulation parameter is set): refresh type!= 0.


MI FIFO Command Format:


```bash
opensips-cli -x mi refresh_watchers sip:11@192.168.2.132 presence 1
	
```


#### cleanup


Manually triggers the cleanup functions for watchers and presentity tables. Useful if you
		have set `clean_period` to zero or less.


Name: *cleanup*


Parameters: *none*


MI FIFO Command Format:


```bash
opensips-cli -x mi cleanup
	  
```


#### presence:phtable_list


Replaces obsolete MI command: *pres_phtable_list*.


Lists all the presentity records.


Name: *presence:phtable_list*


Parameters: *none*


MI FIFO Command Format:


```bash
opensips-cli -x mi presence:phtable_list
	  
```


#### subs_phtable_list


Lists all the subscription records, or the subscriptions for which the "To" and "From" URIs match the given parameters.


Name: *subs_phtable_list*


Parameters


- *from*(optional) - wildcard for "From" URI
- *to*(optional) - wildcard for "To" URI


MI FIFO Command Format:


```bash
opensips-cli -x mi subs_phtable_list sip:222@domain2.com sip:user_1@example.com
	  
```


#### presence:expose


Replaces obsolete MI command: *pres_expose*.


Exposes in the script, by rasing an
		  *E_PRESENCE_EXPOSED* event, all the
		  presentities of a specific event that match a specified
		  filter.


Name: *presence:expose*


Parameters:


- *event* - the desired presence
			event.
- *filter*(optional) - a regular
			expression (REGEXP) used for filtering the presentities
			for that event. Only the presentities that match will
			be exposed. If not specified, all presentities for that
			event are exposed.


MI FIFO Command Format:


```bash
opensips-cli -x mi presence:expose presence ^sip:10\.0\.5\.[0-9]*
	  
```


### Exported Events


#### E_PRESENCE_PUBLISH


This event is raised when the presence module receives
			a PUBLISH message.


Parameters:


- *user* - the AOR of the user
- *domain* - the domain
- *event* - the type of the
					event published
- *expires* - the expire value
					of the publish
- *etag* - the entity tag
- *old_etag* - the entity tag to be refreshed
- *body* - the body of the
					PUBLISH request


#### E_PRESENCE_EXPOSED


This event is raised for each presentity exposeed
			by the *presence:expose*.


Parameters:


Same parameters as the
			*E_PRESENCE_PUBLISH* event.


### Installation


The module requires 3 table in OpenSIPS database: presentity,
	active_watchers and watchers tables. The SQL 
	syntax to create them can be found in presence-create.sql 
	script in the database directories in the opensips/scripts folder.
	You can also find the complete database documentation on the
	project webpage, [https://opensips.org/docs/db/db-schema-devel.html](https://opensips.org/docs/db/db-schema-devel.html).


## Developer Guide


The module provides the following functions that can be used
		in other OpenSIPS modules.


### bind_presence(presence_api_t* api)


This function binds the presence modules and fills the structure 
				with the exported functions that represent functions adding events
				in presence module and functions specific for Subscribe processing.


```c title="presence_api_t structure"
...
typedef struct presence_api {
	add_event_t add_event;
	contains_event_t contains_event;
	search_event_t search_event;
	get_event_list_t get_event_list;
	
	update_watchers_t update_watchers_status;
	
	/* subs hash table handling functions */
	new_shtable_t new_shtable;
	destroy_shtable_t destroy_shtable;
	insert_shtable_t insert_shtable;
	search_shtable_t search_shtable;
	delete_shtable_t delete_shtable;
	update_shtable_t update_shtable;
	/* function to duplicate a subs structure*/
	mem_copy_subs_t  mem_copy_subs;
	/* function used for update in database*/
	update_db_subs_t update_db_subs;
	/* function to extract dialog information from a
	SUBSCRIBE message */
	extract_sdialog_info_t extract_sdialog_info;
	/* function to request sphere defition for a presentity */
	pres_get_sphere_t get_sphere;
	pres_contains_presence_t contains_presence;
}presence_api_t;
...
```


### add_event


Field type:


```c
...
typedef int (*add_event_t)(pres_ev_t* event);
...
```


This function receives as a parameter a structure with event specific
			information and adds it to presence event list.


The structure received as a parameter:


```c
...
typedef struct pres_ev
{
	str name;
	event_t* evp;
	str content_type;
	int default_expires;
	int type;
	int etag_not_new;
	/*
	 *  0 - the standard mechanism (allocating new etag
			for each Publish)
	 *  1 - allocating an etag only
			for an initial Publish 
	*/
	int req_auth;
	get_rules_doc_t* get_rules_doc;
	apply_auth_t*  apply_auth_nbody;
	is_allowed_t*  get_auth_status;
	
	/* an agg_body_t function should be registered
	 * if the event permits having multiple published
	 * states and requires an aggregation of the information
	 * otherwise, this field should be NULL and the last
	 * published state is taken when constructing Notify msg
	 */
	agg_nbody_t* agg_nbody;
	publ_handling_t  * evs_publ_handl;
	subs_handling_t  * evs_subs_handl;
	free_body_t* free_body;
	
	/* sometimes it is necessary that a module make changes for a body for each 
	 * active watcher (e.g. setting the "version" parameter in an XML document.
	 * If a module registers the aux_body_processing callback, it gets called for
	 * each watcher. It either gets the body received by the PUBLISH, or the body
	 * generated by the agg_nbody function.
	 * The module can deceide if it makes a copy of the original body, which is then
	 * manipulated, or if it works directly in the original body. If the module makes a
	 * copy of the original body, it also has to register the aux_free_body() to 
	 * free this "per watcher" body.
	 */
	aux_body_processing_t* aux_body_processing;
	free_body_t* aux_free_body;

	struct pres_ev* wipeer;			
	struct pres_ev* next;
	
}pres_ev_t;
...
```


### get_rules_doc


Filed type:


```c
...
typedef int (get_rules_doc_t)(str* user, str* domain, str** rules_doc);
...
			
```


This function returns the authorization rules document that will be
		used in obtaining the status of the subscription and processing the
		notified body. A reference to the document should be put in the 
		auth_rules_doc of the subs_t structure given as a parameter to the
		functions described bellow.


### get_auth_status


This filed is a function to be called for a subscription request
			to return the state for that subscription according to
			authorization rules. In the auth_rules_doc field of the subs_t
			structure received as a parameter should contain the rules 
			document of the presentity in case, if it exists.


It is called only if the req_auth field is not 0.


Filed type:


```c
...
typedef int (is_allowed_t)(struct subscription* subs);
...
			
```


### apply_auth_nbody


This parameter should be a function to be called for an event 
			that requires authorization, when constructing final body. 
			The authorization document is taken from the auth_rules_doc
			field of the subs_t structure given as a parameter.
			It is called only if the req_auth field is not 0.


Filed type:


```c
...
typedef int (apply_auth_t)(str* , struct subscription*, str** );
...
			
```


### agg_nbody


If present, this field marks that the events requires aggregation
			of states. This function receives a body array and should return
			the final body.	If not present, it is considered that the event
			does not require aggregation and the most recent published
			information is used when constructing Notifies.


Filed type:


```c
...
typedef str* (agg_nbody_t)(str* pres_user, str* pres_domain, 
str** body_array, int n, int off_index);
..
			
```


### free_body


This field must be field in if subsequent processing is performed
			on the info from database before being inserted in Notify
			message body(if agg_nbody or apply_auth_nbody fields are
			filled in). It should match the allocation function used when
			processing the body.


Filed type:


```c
...
typedef void(free_body_t)(char* body);
..
			
```


### aux_body_processing


This field must be set if the module needs to manipulate the NOTIFY body 
			for each watcher. E.g. if the XML body includes a 'version' parameter which 
			will be increased for each NOTIFY, on a "per watcher" basis.
			The module can either allocate a new buffer for the new body an return it (aux_free_body
			function must be set too) or it manipualtes the original body directly and returns NULL.


Filed type:


```c
...
typedef str* (aux_body_processing_t)(struct subscription *subs, str* body);
..
			
```


### aux_free_body


This field must be set if the module registers the aux_body_processing function
			and allocates memory for the new modified body. Then, this function will be used
			to free the pointer returned by the aux_body_processing function.
			If the module does use the aux_body_processing, but does not allocate new memory, but
			manipulates directly the original body buffer, then the aux_body_processing
			must return NULL and this field should not be set.


Filed type:


```c
...
typedef void(free_body_t)(char* body);
..
			
```


### evs_publ_handl


This function is called when handling Publish requests. Most contain 
		body correctness check.


```c
...
typedef int (publ_handling_t)(struct sip_msg*);
..
			
```


### evs_subs_handl


It is not compulsory. Should contain event specific handling for
		Subscription requests.


Filed type:


```c
...
typedef int (subs_handling_t)(struct sip_msg*);
..
```


### contains_event


Field type:


```c
..
typedef pres_ev_t* (*contains_event_t)(str* name,
event_t* parsed_event);
...
```


The function parses the event name received as a parameter and searches
	the result in the list. It returns the found event or NULL, if not found. 
	If the second argument is an allocated event_t* structure it fills it
	with the result of the parsing.


### get_event_list


Field type:


```c
...
typedef int (*get_event_list_t) (str** ev_list);
...
```


This function returns a string representation of the events registered
	in presence module.( used for Allowed-Events header).


### update_watchers_status


Field type:


```c
...
typedef int (*update_watchers_t)(str pres_uri, pres_ev_t* ev,
str* rules_doc);
...
```


This function is an external command that can be used to announce a change
	in authorization rules for a presentity. It updates the stored status and
	sends a Notify to the watchers whose status has changes. (used by
	presence_xml module when notified through an MI command of a change in
	an xcap document).


### get_sphere


Field type:


```c
...
typedef char* (*pres_get_sphere_t)(str* pres_uri);
...
```


This function searches for a sphere definition in the published information
	if this has type RPID. If not found returns NULL. (the return value is
	allocated in private memory and should be freed)


### contains_presence


Field type:


```c
...
typedef int (*pres_contains_presence_t)(str* pres_uri);
...
```


This function searches is a presence uri has published any presence
	information. It return 1 if a record is found, -1 otherwise.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
