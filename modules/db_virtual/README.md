---
title: "virtual_db Module"
---

## Admin Guide


### Overview


#### The idea


A virtual db will expose the same front db api however, it will backed by many real db.
                This means that a virtual db url translates to many real db urls.
                This virtual layer also enables us to use the real dbs in multiple ways such as: parallel, failover(hotswap), round-robin.

                Therefore: 
                    each virtual db url with associated real dbs and
                    a way to use(mode) it's real dbs must be specified.


#### Modes


The implemented modes are:


- FAILOVER
Use the first url; if it fails, use the next one, redo operation.
- PARALLEL
Use all the urls in the virtual db url.
                                Fails if all the urls fail.
- ROUND (round-robin)
Use the next url each time; if it fails, use the next one, redo operation.


There are conceptual limitations to the above modes with respect to the operation.
                    For example in parallel mode it is ok to insert into multiple dbs the same value but it
                    is bad to query multiple dbs into the same result.
                    This implementation threats such operation as it would be in failover mode.
                    ```c

  Conceptual allowed(1) and not allowed(0) operations
                          parallel    round
    dbb->use_table
    dbb->init
    dbb->close

    dbb->query              0           1
    dbb->fetch_result       0           0
    dbb->raw_query          0           1
    dbb->free_result        0           0
    dbb->insert             1           1
    dbb->delete             1           0
    dbb->update             1           0
    dbb->replace            1           0
    dbb->last_inserted_id   0           0
    dbb->insert_update      1           1
```
                Note 1: The capabilities returned are the minimum common denominator of all the dbs in the set.
                    The capabilities are reduced even more based on the mode of the set (PARALLEL, ROUND).
                Note 2: The capabilities will not be reduced for PARALLEL mode but conceptual not allowed operations
                    will be done on a single db.
                    Ex: query will only query one db.


#### Failures


```c
    When an operation from a process on a real db fails:
        it is marked (global and local CAN flag down)
        its connection closed

    Later a timer process (probe):
    foreach virtual db url
        foreach real db_url
            if global CAN down
                try to connect
            if ok
                global CAN up
                close connection

    Later each process:
        if local CAN down and global CAN up
            if db_max_consec_retrys *
                try to connect
        if ok
            local CAN up

                
```


Note *: there could be inconsistencies between the probe and each process so a retry limit is in order.
                It is reset and ignored by an MI command.


#### The timer process


The timer process(probe) is a process that tries to reconnect to failed dbs from time to time.
                It is a separate process so that when it blocks (for a timeout on the connection) it doesn't matter.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *At least one real db module*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_urls (str)


Multiple value parameter used for virtual db urls declaration.


```opensips title="Set db_urls parameter"
...

modparam("group","db_url","virtual://set1")
modparam("presence|presence_xml", "db_url","virtual://set2")

modparam("db_virtual", "db_urls", "define set1 PARALLEL")
modparam("db_virtual", "db_urls", "mysql://opensips:opensipsrw@localhost/testa")
modparam("db_virtual", "db_urls", "postgres://opensips:opensipsrw@localhost/opensips")

modparam("db_virtual", "db_urls", "define set2 FAILOVER")
modparam("db_virtual", "db_urls", "mysql://opensips:opensipsrw@localhost/testa")
...
                
```


#### db_probe_time (integer)


Time interval after which a registered timer process attempts to check
        failed(as reported by other processes) connections to real dbs. The probe will connect and
        disconnect to the failed real db and announce others.


*Default value is 10 (10 sec).*


```opensips title="Set db_probe_time parameter"
...
modparam("db_virtual", "db_probe_time", 20)
...
                
```


#### db_max_consec_retrys (integer)


After the timer process has reported that it can connect to the real db,
        other processes will try to reconnect to it. There are cases where although
        the probe could connect some might fail. This parameter represents the number
        of consecutive failed retries that a process will do before it gives up.
        This value is reset and suppressed by a MI function(db_set).


*Default value is 10 (10 consecutive times).*


```opensips title="Set db_max_consec_retrys parameter"
...
modparam("db_virtual", "db_max_consec_retrys", 20)
...

                
```


### Exported MI Functions


#### db_get


Return information about global state of the real dbs.


Name: 
                *db_get*


Parameters:


- None.


MI FIFO Command Format:


```c
                db_get
                _empty_line_
            
```


#### db_set


Sets the permissions for real dbs access per set per db.


Sets the reconnect reset flag.


Name:
                *db_set*


Parameters:


- set_index [int]
- db_url_index [int]
- may_use_db_flag [boolean]
- ignore db_max_consec_retrys[boolean](optional)


db_set 3 2 0 1 means:


- 3 - the fourth set (must exist)
- 2 - the third url in the fourth set(must exist)
- 0 - processes are not allowed to use that url
- 1 - reset and suppress db_max_consec_retrys


MI FIFO Command Format:


```c
                db_set 3 2 0 1
                _empty_line_
            
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
