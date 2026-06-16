---
title: "jabber Module"
description: "This is new version of Jabber module that integrates XODE XML parser for parsing Jabber messages. That introduces a new module dependency: expat library."
---

## Admin Guide


### Overview


This is new version of Jabber module that integrates XODE 
		XML parser for parsing Jabber messages. That 
		introduces a new module dependency: expat library.


Expat is a common XML library and is the fastest 
		available for Linux/Unix, the second over all, after msxml library. It 
		is integrated in most of well known Linux distributions.


#### New Features


- Presence support (see doc/xxjab.cfg for a sample cfg file) 
			(January 2003).
- SIP to Jabber conference support (December 2003).
- Possibility to manage all kinds of Jabber messages 
			(message/presence/iq) (December 2003).
- Aliases -- Possibility to set host aliases for addresses 
			(see parameter's desc.) (December 2003).
- Send received SIP MESSAGE messages to different IM networks 
			(Jabber, ICQ,MSN, AIM, Yahoo) using a Jabber server (December 2003).
- Send incoming Jabber instant messages as SIP MESSAGE messages.
- Gateways detection -- Ability to see whether an IM gateway is up 
			or down.


### Admin's Guide


> [!NOTE]
> A more complete guide about SIMPLE2Jabber gateway can be found 
		at [https://opensips.org/](https://opensips.org/). The part below will be removed soon, only the manual 
		from web will be updated.


The Jabber server setup is not a subject of this guide. Check [http://www.jabber.org](http://www.jabber.org) for that.


Useful scripts, for creating Jabber Gateway database, or for managing 
		the Jabber accounts form web are located in 'doc' subdirectory of the 
		module.


Main steps of using the Jabber gateway:


- Create the MySQL database.
- Setup the local Jabber server.
- Set the module parameter values in cfg file of OpenSIPS, load the 
			dependent modules, set up the routing rules for Jabber gateway.
- Run OpenSIPS.


The administrator of OpenSIPS/Jabber gateway *must* 
		inform the users what are the aliases for Jabber/Other IM networks. 
		Other IMs could be AIM, ICQ, 
		MSN, Yahoo, and so on.


These aliases depend on the server hostname where runs OpenSIPS and 
		how local Jabber server is setup.


Next is presented a use case. Prologue:


- OpenSIPS is running on "server.org".
- Local Jabber server is running on "jabsrv.server.org".
- Jabber network alias (first part of "jdomain") is
			"jabber.server.org"


The aliases for other IM networks *must* be the 
		same as JID set in Jabber configuration file for 
		each IM transport.


The JIDs of Jabber transports 
		*must* start with the name of the network. 
		For AIM, JID must start
		with "aim.", for ICQ with 
		"icq" (that because I use icqv7-t), for 
		MSN with "msn." and for
		Yahoo with "yahoo.". The gateway needs these to find 
		out what transport is working and which not. For our use case these 
		could be like "aim.server.org", 
		"icq.server.org",
		"msn.server.org", "yahoo.server.org".


It is indicated to have these aliases in DNS, thus 
		the client application can resolve the DNS name. 
		Otherwise there must be set the outbound proxy to OpenSIPS server.


*** Routing rules for Jabber gateway First step is to configure OpenSIPS 
		to recognize messages for Jabber gateway. Look at 
		"doc/xjab.cfg" to see a sample. The idea is to look in 
		messages for destination address and if it contains Jabber alias or
		other IM alias, that means the message is for Jabber gateway.


Next step is to find out what means that message for Jabber gateway. 
		It could be a special message what triggers the gateway to take an 
		action or is a simple message which should be delivered to Jabber 
		network (using the method "jab_send_message").


The special messages are for:


- Registering to Jabber server (go online in Jabber network)--here 
			must be called "jab_go_online" method.
- Leaving the Jabber network (go offline in Jabber network)--here 
			must be called "jab_go_offline" method.
- Joining a Jabber conference room--here must be called 
			"jab_join_jconf".
- Leaving a Jabber conference room--here must be called 
			"jab_exit_jconf".


The destination address *must* follow the 
		following patterns:


- For Jabber network: 
			"username<delim>jabber_server@jabber_alias".
- For Jabber conference: "nickname<delim>room<delim>conference_server@jabber_alias".
- For AIM network: 
			"aim_username@aim_alias".
- For ICQ network: 
			"icq_number@icq_alias".
- For MSN network:
			"msn_username<delim>msn_server@msn_alias".
			msn_server can be "msn.com" or 
			"hotmail.com".
- For YAHOO network: "yahoo_username@yahoo_alias".


> [!NOTE]
> "jabber_alias" is the first part of "jdomain".


### Admin Guide


The user must activate his Jabber account associated with his SIP id. For each other
		IM network on which he wants to send messages, he must set an account for that IM
		network. The gateway is not able to create new account in foreign networks, excepting
		local Jabber server.


When you want to send a message to someone in other IM network, you must set the
		destination of the message according with the pattern corresponding to that IM network
		(see last part of "Admin guide" chapter).


Sending a message to user@jabber.xxx.org which is in Jabber network, the
		destination must be: user<delim>jabber.xxx.org@jabber_alias.


For someone who is in Yahoo network the destination must be:
		user@yahoo_alias


> [!NOTE]
> The OpenSIPS administrator have to set the Jabber transports for each IM network in
		order to be able to send messages to those networks. The alias of each IM network
		can be found out from OpenSIPS admin. You cannot send messages from your SIP client to your associated Jabber
		account--is something like sending messages to yourself.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- A database module.
- *pa* (Optionally) - Presence Agent.
- *tm* - Transaction Manager.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *Expat* library.


### Exported Parameters


#### db_url (string)


SQL URL of database.


*Default value is "mysql://root@127.0.0.1/sip_jab".*


```c title="Set db_url parameter"
...
modparam("jabber", "db_url", "mysql://username:password@host/sip_jab")
...
```


#### jaddress (string)


IP or hostname of Jabber server -- it must be the same as the value from <host>
		tag of Jabber server config file.


*Default value is "127.0.0.1".*


```c title="Set jaddress parameter"
...
modparam("jabber", "jaddress", "1.2.3.4")
...
```


#### jport (integer)


Port number of Jabber server.


*Default value is "5222".*


```c title="Set jport parameter"
...
modparam("jabber", "jport", 1234)
...
```


#### jdomain (string)


Format: jabber.sipserver.com=<delim>. If the destination is for Jabber network
		the URI should be like: username<delim>jabber_server@jdomain or
		nickname<delim>roomname<delim>conference_server@jdomain


<delim> must be a un-reserved character. By default this character is * .  The
		destination will be transformed to username@jabber_server or
		roomname@conference_server/nickname before the message is sent to Jabber server.


*Default value is none.*


```c title="Set jdomain parameter"
...
modparam("jabber", "jdomain", "jabber.sipserver.com=*")
...
```


#### aliases (string)


Aliases for IM networks.


Format: "N;alias1=<delim1>;...;aliasN=<delimN>;"
		Destinations like '*@aliasX' could have other format than those specified for Jabber
		network.  All <delim> from user part of the destination address will be
		changed to <delimX> if the destination address contains <aliasX>.


(Ex: jdomain is 'jabber.x.com=*' and msn_alias is 'msn.x.com=%'. The destination
		address forM MSN Network, on SIP side, is like
		'username*hotmail.com@msn.x.com'. The destination address will be transformed to
		'username%hotmail.com@msn.x.com'.  'msn.x.com' must be the same as the
		JID associated with MSN transport in Jabber
		configuration file (usually is 'jabberd.xml'))


*Default value is none.*


```c title="Set jdomain parameter"
...
modparam("jabber", "aliases", "1;msn.x.com=%")
...
```


#### proxy (string)


Outbound proxy address.


Format: ip_address:port hostname:port


All SIP messages generated by gateway will be sent to that address. If is
		missing, the message will be delivered to the hostname of the destination address


Default value is none.


```c title="Set proxy parameter"
...
modparam("jabber", "proxy", "10.0.0.1:5060 sipserver.com:5060")
...
```


#### registrar (string)


The address in whose behalf the INFO and ERROR messages are sent.


*Default value is "jabber_gateway@127.0.0.1".*


```c title="Set registrar parameter"
...
modparam("jabber", "registrar", "jabber_gateway@127.0.0.1")
...
```


#### workers (integer)


Number of workers.


*Default value is 2.*


```c title="Set workers parameter"
...
modparam("jabber", "workers", 2)
...
```


#### max_jobs (integer)


Maximum jobs per worker.


*Default value is 10.*


```c title="Set max_jobs parameter"
...
modparam("jabber", "max_jobs", 10)
...
```


#### cache_time (integer)


Cache time of a Jabber connection.


*Default value is 600.*


```c title="Set cache_time parameter"
...
modparam("jabber", "cache_time", 600)
...
```


#### delay_time (integer)


Time to keep a SIP message (in seconds).


*Default value is 90 seconds.*


```c title="Set delay_time parameter"
...
modparam("jabber", "delay_time", 90)
...
```


#### sleep_time (integer)


Time between expired Jabber connections checking (in seconds).


*Default value is 20 seconds.*


```c title="Set sleep_time parameter"
...
modparam("jabber", "sleep_time", 20)
...
```


#### check_time (integer)


Time between checking the status of JabberGW workers (in seconds).


*Default value is 20 seconds.*


```c title="Set check_time parameter"
...
modparam("jabber", "check_time", 20)
...
```


#### priority (str)


Presence priority for Jabber gateway.


*Default value is "9".*


```c title="Set priority parameter"
...
modparam("jabber", "priority", "3")
...
```


### Exported Functions


#### jab_send_message()


Converts SIP MESSAGE message to a Jabber message and sends it to Jabber server.


This function can be used from REQUEST_ROUTE.


```c title="jab_send_message() usage"
...
jab_send_message();
...
```


#### jab_join_jconf()


Join a Jabber conference--the nickname, room name and conference server address
		should be included in To header as: nickname%roomname%conference_server@jdomain . If
		the nickname is missing, then the SIP username is used.


This function can be used from REQUEST_ROUTE.


```c title="jab_join_jconf() usage"
...
jab_join_jconf();
...
```


#### jab_exit_jconf()


Leave a Jabber conference--the nickname, room name and conference server address
		should be included in To header as: nickname%roomname%conference_server@jdomain .


This function can be used from REQUEST_ROUTE.


```c title="jab_exit_jconf() usage"
...
jab_exit_jconf();
...
```


#### jab_go_online()


Register to the Jabber server with associated Jabber ID of the SIP user.


This function can be used from REQUEST_ROUTE.


```c title="jab_go_online() usage"
...
jab_go_online();
...
```


#### jab_go_offline()


Log off from Jabber server the associated Jabber ID of the SIP user.


This function can be used from REQUEST_ROUTE.


```c title="jab_go_offline() usage"
...
jab_go_offline();
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
