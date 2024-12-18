Trie Module
     __________________________________________________________

   Table of Contents

   1. Admin Guide

        1.1. Overview

              1.1.1. Introduction

        1.2. Dependencies

              1.2.1. OpenSIPS Modules
              1.2.2. External Libraries or Applications

        1.3. Exported Parameters

              1.3.1. trie_table(str)
              1.3.2. no_concurrent_reload (int)
              1.3.3. use_partitions (int)
              1.3.4. db_partitions_url (str)
              1.3.5. db_partitions_table (str)
              1.3.6. extra_prefix_chars (str)

        1.4. Exported Functions

              1.4.1. trie_search(number, [flags],
                      [trie_attrs_pvar], [match_prefix_pvar],
                      [partition])

        1.5. Exported MI Functions

              1.5.1. trie_reload
              1.5.2. trie_reload_status
              1.5.3. trie_search
              1.5.4. trie_number_delete
              1.5.5. trie_number_upsert

        1.6. Installation

   List of Examples

   1.1. Set trie_table parameter
   1.2. Set no_concurrent_reload parameter
   1.3. Set use_partitions parameter
   1.4. Set db_partitions_url parameter
   1.5. Set db_partitions_table parameter
   1.6. Set extra_prefix_chars parameter
   1.7. trie_search usage
   1.8. trie_reload_status usage when use_partitions is 0

Chapter 1. Admin Guide

1.1. Overview

1.1.1. Introduction

   Trie is a module for efficiently caching and lookup of a set of
   prefixes ( stored in a trie data structure )

1.2. Dependencies

1.2.1. OpenSIPS Modules

   The following modules must be loaded before this module:
     * a database module.

1.2.2. External Libraries or Applications

     * none.

1.3. Exported Parameters

1.3.1. trie_table(str)

   The name of the db table storing prefix rules.

   Default value is “trie_table”.

   Example 1.1. Set trie_table parameter
...
modparam("drouting", "trie_table", "my_prefix_table")
...

1.3.2. no_concurrent_reload (int)

   If enabled, the module will not allow do run multiple
   trie_reload MI commands in parallel (with overlapping) Any new
   reload will be rejected (and discarded) while an existing
   reload is in progress.

   If you have a large routing set (millions of rules/prefixes),
   you should consider disabling concurrent reload as they will
   exhaust the shared memory (by reloading into memory, in the
   same time, multiple instances of routing data).

   Default value is “0 (disabled)”.

   Example 1.2. Set no_concurrent_reload parameter
...
# do not allow parallel reload operations
modparam("trie", "no_concurrent_reload", 1)
...

1.3.3. use_partitions (int)

   Flag to configure whether to use partitions for tries. If this
   flag is set then the db_partitions_url and db_partitions_table
   variables become mandatory.

   Default value is “0”.

   Example 1.3. Set use_partitions parameter
...
modparam("trie", "use_partitions", 1)
...

1.3.4. db_partitions_url (str)

   The url to the database containing partition-specific
   information.The use_partitions parameter must be set to 1.

   Default value is “"NULL"”.

   Example 1.4. Set db_partitions_url parameter
...
modparam("trie", "db_partitions_url", "mysql://user:password@localhost/o
pensips_partitions")
...

1.3.5. db_partitions_table (str)

   The name of the table containing partition definitions. To be
   used with use_partitions and db_partitions_url.

   Default value is “trie_partitions”.

   Example 1.5. Set db_partitions_table parameter
...
modparam("trie", "db_partitions_table", "trie_partition_defs")
...

1.3.6. extra_prefix_chars (str)

   List of ASCII (0-127) characters to be additionally accepted in
   the prefixes. By default only '0' - '9' chars (digits) are
   accepted.

   Default value is “NULL”.

   Example 1.6. Set extra_prefix_chars parameter
...
modparam("trie", "extra_prefix_chars", "#-%")
...

1.4. Exported Functions

1.4.1.  trie_search(number, [flags], [trie_attrs_pvar],
[match_prefix_pvar], [partition])

   Function to search for an entry ( number ) in a trie.

   This function can be used from all routes.

   If you set use_partitions to 1 the partition last parameter
   becomes mandatory.

   All parameters are optional. Any of them may be ignored,
   provided the necessary separation marks "," are properly
   placed.
     * number (str) - number to be searched in the trie
     * flags (string, optional) - a list of letter-like flags for
       controlling the routing behavior. Possible flags are:
          + L - Do strict length matching over the prefix -
            actually the trie engine will do full number matching
            and not prefix matching anymore.
     * trie_attrs_pvar (var, optional) - a writable variable which
       will be populated with the attributes of the matched trie
       rule.
     * match_prefix_pvar (var, optional) - a writable variable
       which will be the actual prefix matched in the trie.
     * partition (string, optional) - the name of the trie
       partition to be used. This parameter is to be defined ONLY
       if the "use_partition" module parameter is turned on.

   Example 1.7. trie_search usage
...
if (trie_search("$rU","L",$avp(code_attrs),,"my_partition")) {
    # we found it in the trie, it's a match
    xlog("We found $rU in the trie with attrs $avp(code_attrs) \n");
}

1.5. Exported MI Functions

1.5.1.  trie_reload

   Command to reload trie rules from database.
     * if use_partition is set to 0 - all routing rules will be
       reloaded.
     * if use_partition is set to 1, the parameters are:
          + partition_name (optional) - if not provided all the
            partitions will be reloaded, otherwise just the
            partition given as parameter will be reloaded.

   MI FIFO Command Format:
                opensips-cli -x mi trie_reload part_1

1.5.2. trie_reload_status

   Gets the time of the last reload for any partition.
     * if use_partition is set to 0 - the function doesn't receive
       any parameter. It will list the date of the last reload for
       the default (and only) partition.
     * if use_partition is set to 1, the parameters are:
          + partition_name (optional) - if not provided the
            function will list the time of the last update for
            every partition. Otherwise, the function will list the
            time of the last reload for the given partition.

   Example 1.8. trie_reload_status usage when use_partitions is 0
$ opensips-cli -x mi dr_reload_status
Date:: Tue Aug 12 12:26:00 2014

1.5.3. trie_search

   Tries to match a number in the existing tries loaded from the
   database.
     * if use_partition is set to 1 the function will have 2
       parameters:
          + partition_name
          + number - the number to test against
     * if use_partition is set to 0 the function will have 1
       parameter:
          + number - the number to test against

   MI FIFO Command Format:
                opensips-cli -x mi trie_search partition_name=part1 numb
er=012340987

1.5.4.  trie_number_delete

   Deletes individual entries in the trie, without reloading all
   of the data
     * if use_partition is set to 1 the function will have 2
       parameters:
          + partition_name
          + number - the array of numbers to delete

   MI FIFO Command Format:
                opensips-cli -x mi trie_number_delete partition_name=par
t1 number=["012340987","4858345"]

1.5.5.  trie_number_upsert

   Upserts ( insert if not found, update is found ) an array of
   numbers in the trie, without reloading all of the data
     * if use_partition is set to 1 the function will have 3
       parameters:
          + partition_name
          + number - the array of numbers to update
          + attrs - the array of new attributes for the numbers

   MI FIFO Command Format:
                opensips-cli -x mi trie_number_upsert partition_name=par
t1 number=["012340987"] attrs=["my_attrs"]

1.6. Installation

   The module requires some tables in the OpenSIPS database. You
   can also find the complete database documentation on the
   project webpage,
   https://opensips.org/docs/db/db-schema-devel.html.

   Documentation Copyrights:

   Copyright © 2024 OpenSIPS Project
