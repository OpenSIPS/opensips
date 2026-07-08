---
title: "qrouting (Quality-based Routing) Module"
description: "*qrouting* is a module which sits on top of [drouting](../drouting/doc/drouting.html), [dialog](../dialog/doc/dialog.html) and [tm](../tm/doc/tm.html) and performs live tracking of a series of essential gateway signaling quality indicators (i.e. ASR, CCR, PDD, AST, ACD -- more details below)..."
---

## Admin Guide


### Overview


*qrouting* is a module which sits on top of
	[drouting](../drouting/doc/drouting.html),
	[dialog](../dialog/doc/dialog.html) and
	[tm](../tm/doc/tm.html) and performs live
	tracking of a series of essential gateway signaling quality indicators
	(i.e. ASR, CCR, PDD, AST, ACD -- more details below).  Thus, qrouting is
	able to adjust the prefix routing behavior at runtime, by dynamically
	re-ordering the gateways based on how well they perform during live
	traffic, such that:


- well-performing gateways get prioritized for routing
- gateways which show a degradation in signaling quality are
			demoted to the end of the routing list


### Monitored Statistics


The module keeps track of a series of statistics, for each drouting
	**(prefix, destination)** pair, where a
	"destination" may be either a gateway or a carrier.  The statistics are:


- ASR (Answer Seizure Ratio) - the percentage of telephone
				calls which are answered (200 reply status code).
- CCR (Call Completion Ratio) - the percentage of telephone
				calls which are answered back by the gateway, excluding
				5xx, 6xx reply codes and internal 408 timeouts.  The following
				is always true: CCR >= ASR.
- PDD (Post Dial Delay) - the duration, in milliseconds,
				between the receival of the initial INVITE and the receival
				of the first 180/183 provisional reply (the call state
				advances to *"ringing"*).
- AST (Average Setup Time) - the duration, in milliseconds,
				between the receival of the initial INVITE and the receival
				of the first 200 OK reply (the call state advances to
				*"answered"*).  The following is always
				true: AST >= PDD.
- ACD (Average Call Duration) - the duration, in seconds,
				between the receival of the initial INVITE and the receival
				of the first BYE request from either participant (the call
				state advances to *"ended"*).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded for this module to work:


- *an SQL DB module, offering access to the
						"qr_profiles" table*
- *tm*
- *dialog*
- *drouting*


### Exported Parameters


#### db_url (string)


An SQL database URL.


*Default value is **NULL**.*


```opensips title="Setting the db_url parameter"
modparam("qrouting", "db_url", "mysql://opensips:opensipsrw@localhost/opensips")
	
```


#### table_name (string)


The name of the quality-based routing profiles table.


*Default value is **"qr_profiles"**.*


```opensips title="Setting the table_name parameter"
modparam("qrouting", "table_name", "qr_profiles_bak")
	
```


#### algorithm (integer)


Quality-based destination selection/balancing algorithm to use.


Possible values:


- **"dynamic-weights"** -
					for each prefix, all destinations start with equal
					weights and receive an equal share of the traffic.  As
					signaling statistics are gathered for the destinations, the
					ones which underperform will receive less traffic,
					based on the "penalty" columns of the
					*qr_profiles* table
- **"best-dest-first"** - for each
					prefix, the 1st (i.e. *best scoring*)
					destination will receive all the traffic as long as its
					quality stays the same.  Initially, all destinations start
					with a perfect score.  This score may degrade if one or
					more signaling statistics fall below the "warn" or "crit"
					thresholds during routing, case in which the destinations
					will be sorted accordingly and traffic will be routed to
					the newly determined 1st position in the list
*NOTE*:  for optimal results when
						using the "best-dest-first" algorithm, the destinations
						must be provisioned in descending order of their
						expected quality! (i.e. best quality gateways must be
						placed towards the start of the list)


*Default value is **"dynamic-weights"**.*


```opensips title="Setting the algorithm parameter"
modparam("qrouting", "algorithm", "best-dest-first")
	
```


#### history_span (integer)


The duration (in minutes) that a gateway's statistics for a given call
		will be kept for.


*Default value is **30** minutes.*


```opensips title="Setting the connection_timeout parameter"
modparam("qrouting", "history_span", 15)
	
```


#### sampling_interval (integer)


The duration (in seconds) of the statistics sampling window.  Every
		*[sampling interval](#param_sampling_interval)* seconds,
		the accumulated statistics during the most recent sampling window get
		added to each gateway, while the oldest sampled interval statistics are
		subtracted (rotated away) from each gateway.


A lower value will lead to a closer to realtime adjustment to traffic
		changes, but it will also increase CPU usage and internal contention
		due to locking.


*Default value is **5** seconds.*


```opensips title="Setting the connect_poll_interval parameter"
modparam("qrouting", "sampling_interval", 5)
	
```


#### extra_stats (string)


A semicolon-separated list of custom statistics to be additionally kept
		and monitored by the module.  In order to gather these statistics, the
		module expects the script writer to call
		[qr set xstat](#func_qr_set_xstat) whenever they want to increment a
		custom statistic for a (prefix, destination) tuple.


Extra statistics come in two flavours: *positive*
		(a higher value is better, e.g. ASR) or *negative*
		(a lower value is better, e.g. PDD).  The flavour determines the
		comparison operator to be used against the statistics's thresholds, and
		can be specified by prepending **"+"** or
		**"-"**, respectively, in front
		of the statistic's name (see example below).


The minimally accepted number of samples for each statistic may be
		changed using the optional **/<min_samples>**
		suffix.  Default value: **30** samples
		(minimum).


The thresholds and penalties for a custom statistic must be provided
		via the *qr_profiles* table, by extending it with 4
		columns for each extra statistic, named according to these
		templates:


- warn_threshold_*<STAT>*
- crit_threshold_*<STAT>*
- warn_penalty_*<STAT>*
- crit_penalty_*<STAT>*


*Default value is **NULL**.*


```opensips title="Setting the extra_stats parameter"
modparam("qrouting", "extra_stats", "+mos/60; +r_factor; -503_replies/100")
	
```


#### min_samples_asr (integer)


The minimally accepted amount of sampled ASR statistics for each
		(prefix, destination) pair before they can be taken into account.  As
		long as the number of samples stays below this limit, the ASR statistic
		of the pair is assumed to be healthy.


*Default value is **30**.*


```opensips title="Setting the min_samples_asr parameter"
modparam("qrouting", "min_samples_asr", 50)
	
```


#### min_samples_ccr (integer)


The minimally accepted amount of sampled CCR statistics for each
		(prefix, destination) pair before they can be taken into account.  As
		long as the number of samples stays below this limit, the CCR statistic
		of the pair is assumed to be healthy.


*Default value is **30**.*


```opensips title="Setting the min_samples_ccr parameter"
modparam("qrouting", "min_samples_ccr", 50)
	
```


#### min_samples_pdd (integer)


The minimally accepted amount of sampled PDD statistics for each
		(prefix, destination) pair before they can be taken into account.  As
		long as the number of samples stays below this limit, the PDD statistic
		of the pair is assumed to be healthy.


*Default value is **10**.*


```opensips title="Setting the min_samples_pdd parameter"
modparam("qrouting", "min_samples_pdd", 15)
	
```


#### min_samples_ast (integer)


The minimally accepted amount of sampled AST statistics for each
		(prefix, destination) pair before they can be taken into account.  As
		long as the number of samples stays below this limit, the AST statistic
		of the pair is assumed to be healthy.


*Default value is **10**.*


```opensips title="Setting the min_samples_ast parameter"
modparam("qrouting", "min_samples_ast", 15)
	
```


#### min_samples_acd (integer)


The minimally accepted amount of sampled ACD statistics for each
		(prefix, destination) pair before they can be taken into account.  As
		long as the number of samples stays below this limit, the ACD statistic
		of the pair is assumed to be healthy.


*Default value is **20**.*


```opensips title="Setting the min_samples_acd parameter"
modparam("qrouting", "min_samples_acd", 30)
	
```


#### event_bad_dst_threshold (string)


The minimally accepted quality of a (prefix, destination) combination,
		given as a quoted floating point number in the [0, 1] interval.
		Whenever a (prefix, destination) combination receives a score below
		this threshold, the [E QROUTING BAD DST](#event_e_qrouting_bad_dst) event
		will be triggered.


*Default value is **NULL** (not set).*


```opensips title="Setting the event_bad_dst_threshold parameter"
modparam("qrouting", "event_bad_dst_threshold", "0.5")
	
```


#### decimal_digits (string)


The amount of decimal digits to use in logging or MI output.


*Default value is **2**.*


```opensips title="Setting the decimal_digits parameter"
modparam("qrouting", "decimal_digits", 4)
	
```


### Exported Functions


#### qr_set_xstat(rule_id, gw_name, stat_name, inc_by, [part], [inc_total])


Provide a new sample value for an extra statistic on a given (prefix,
		gateway) combination.  Extra statistics may be defined using the
		[extra stats](#param_extra_stats) module parameter.


Parameters:


- *rule_id (integer)* - database id of the
				drouting rule holding the prefix and its destinations
- *gw_name (string)* - gateway to account the
				statistic for.  The gateway must be part of the above rule's
				destinations.
- *stat_name (string)* - statistic to account
- *inc_by (string)* - quoted floating point
				number, representing the amount to add to the stat
- *part (string, optional, default: 'Default')* -
				the drouting partition to use
- *inc_total (string, optional, default: 1)* -
				the amount to add to the total stat counter.  Usually, this
				value should be 1, but it may make sense to set it to 0 when a
				custom statistic needs to be set a 2nd, 3rd, etc. time across
				the duration of the same established call.


This function can be used from any route.


```opensips title="qr_set_xstat() usage"
# the MoS is set exactly once per call, so we can omit "inc_total"
$var(rule_id) = 1574;
$var(gw_name) = "GW-28";
$var(mos_score) = "4.28";
qr_set_xstat($var(rule_id), $var(gw_name), "mos", $var(mos_score));
	
```


#### qr_disable_dst(rule_id, dst_name, [part])


Within a given routing rule, temporarily remove the given gateway or
		carrier from routing, until they are re-enabled via
		[qr enable dst](#func_qr_enable_dst) or [mi enable dst](#mi_enable_dst).
		The removal effect will be lost on an OpenSIPS restart.


Parameters:


- *rule_id (integer)* - database id of the
				drouting rule
- *dst_name (string)* - gateway or carrier
					to disable
- *part (string, optional)* - drouting partition


This function can be used from any route.


```opensips title="qr_disable_dst() usage"
# the signaling quality for @rule_id through @dst_name is degrading, remove it!
event_route [E_QROUTING_BAD_DST]
{
	qr_disable_dst($param(rule_id), $param(dst_name), $param(partition));
}
	
```


#### qr_enable_dst(rule_id, dst_name, [part])


Within a given routing rule, re-introduce the given gateway or
		carrier into the routing process.


Parameters:


- *rule_id (integer)* - database id of the
				drouting rule
- *dst_name (string)* - gateway or carrier
					to disable
- *part (string, optional)* - drouting partition


This function can be used from any route.


```opensips title="qr_enable_dst() usage"
# the ban has expired, let's re-enable this gateway and see how it behaves
qr_enable_dst($param(rule_id), $param(dst_name), $param(partition));
	
```


### Exported MI Functions


#### qrouting:reload


Replaces obsolete MI command: *qr_reload*.


Reload all quality-based routing rules from the SQL database.


MI FIFO Command Format:


```bash
opensips-cli -x mi qrouting:reload
		
```


#### qrouting:status


Replaces obsolete MI command: *qr_status*.


Inspect the signaling quality statistics of the current
		[history span](#param_history_span) for all drouting gateways in all
		partitions, with various levels of filtering.


Parameters:


- *partition (optional)* - a specific
				drouting partition to list statistics for
- *rule_id (optional)* - a specific drouting
				rule database id to list statistics for
- *dst_name (optional)* - a specific gateway or
				carrier name to list statistics for


MI FIFO Command Format:


```bash
opensips-cli -x mi qrouting:status
opensips-cli -x mi qrouting:status pstn
opensips-cli -x mi qrouting:status pstn 11 MY-GW-3
opensips-cli -x mi qrouting:status pstn 17 MY-CARR-7
		
```


#### qrouting:disable_dst


Replaces obsolete MI command: *qr_disable_dst*.


Within a given routing rule, temporarily remove the given gateway or
		carrier from routing, until they are re-enabled manually.  The removal
		effect will be lost on an OpenSIPS restart.


Parameters:


- *partition (optional)* - drouting partition
- *rule_id* - database id of the drouting rule
- *dst_name* - gateway or carrier to disable


MI FIFO Command Format:


```bash
opensips-cli -x mi qrouting:disable_dst 14 MY-CARR-7
opensips-cli -x mi qrouting:disable_dst pstn 81 MY-GW-3
		
```


#### qrouting:enable_dst


Replaces obsolete MI command: *qr_enable_dst*.


Within a given routing rule, re-introduce the given gateway or
		carrier into the routing process.


Parameters:


- *partition (optional)* - drouting partition
- *rule_id* - database id of the drouting rule
- *dst_name* - gateway or carrier to enable


MI FIFO Command Format:


```bash
opensips-cli -x mi qrouting:enable_dst 14 MY-CARR-7
opensips-cli -x mi qrouting:enable_dst pstn 81 MY-GW-3
		
```


### Exported Events


#### E_QROUTING_BAD_DST


This event may be raised during routing, asynchronously, whenever the
		score of a (prefix, destination) pair falls below
		[event bad dst threshold](#param_event_bad_dst_threshold).


Parameters:


- *partition* - drouting partition name
- *rule_id* - database id of the drouting rule
- *dst_name* - name of the concerned gateway or carrier
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
