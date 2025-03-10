cachedb_dynamodb Module
     __________________________________________________________

   Table of Contents

   1. Admin Guide

        1.1. Overview

              1.1.1. Functionalities
              1.1.2. Table Format and TTL Option

        1.2. Advantages
        1.3. Limitations
        1.4. Dependencies

              1.4.1. OpenSIPS Modules
              1.4.2. External Libraries or Applications
              1.4.3. Deploying DynamoDB locally on your computer

        1.5. Exported Parameters

              1.5.1. cachedb_url (string)

        1.6. Exported Functions

   2. Contributors

        2.1. By Commit Statistics
        2.2. By Commit Activity

   3. Documentation

        3.1. Contributors

   List of Tables

   2.1. Top contributors by DevScore^(1), authored commits^(2) and
          lines added/removed^(3)

   2.2. Most recently active contributors^(1) to this module

   List of Examples

   1.1. Set cachedb_url parameter
   1.2. Use Dynamodb servers

Chapter 1. Admin Guide

1.1. Overview

   This module is an implementation of a cachedb system designed
   to work with Amazon DynamoDB. It uses the AWS SDK library for
   C++ to connect to a DynamoDB instance. It leverages the
   Key-Value interface exported from the core.

   https://aws.amazon.com/pm/dynamodb/

1.1.1. Functionalities

     * set - sets a key in DynamoDB using the cachedb_store
       function
     * get - queries a key from DynamoDB using the cachedb_fetch
       function
     * remove - removes a key from DynamoDB using the
       cachedb_remove function
     * get_counter - queries a key with a numerical value from
       DynamoDB using the cachedb_counter_fetch function
     * add - increments the value of a specific item with a given
       value using the cachedb_add function
     * sub - decrements the value of a specific item with a given
       value using the cachedb_sub function

   The following are internally used by OpenSIPS:
     * map_get
     * map_set
     * map_remove

1.1.2. Table Format and TTL Option

   The tables used with DynamoDB must adhere to a specific format.
   Below is an example of creating a table:

aws dynamodb create-table \
--table-name TableName \
--attribute-definitions \
        AttributeName=KeyName,AttributeType=S \
--key-schema \
        AttributeName=KeyName,KeyType=HASH \
--provisioned-throughput \
        ReadCapacityUnits=5,WriteCapacityUnits=5 \
--table-class STANDARD

   If you create the table using the above command, then you have
   to specify the key in the cachedb_url:
   modparam("cachedb_dynamodb", "cachedb_url",
   "dynamodb://localhost:8000/TableName?key=KeyName;val=ValName")"

   For additional examples of how cachedb_url should be formatted,
   refer to the cachedb_url (string) section.

   To enable TTL (Time to Live) for the table, which can be used
   with operations like set, add, and subtract, you can update the
   table with the TTL option:

aws dynamodb update-time-to-live --table-name TableName --time-to-live-s
pecification
"Enabled=true, AttributeName=ttl"

   For additional information about the table format and TTL
   options, follow these links:

   Creating a Table

   Time to Live (TTL)

1.2. Advantages

     * scalable and fully managed NoSQL database service provided
       by AWS
     * integrated with other AWS services, providing robust
       security and scalability features
     * high availability and durability due to data replication
       across multiple AWS Availability Zones
     * serverless architecture, reducing operational overhead
     * offers single-digit response times, with DynamoDB
       Accelerator (DAX) for even lower latencies

1.3. Limitations

     * relies heavily on indexes; without them, querying involves
       costly full table scans
     * does not support table joins, limiting complex queries
       involving multiple tables
     * item size limit:each item has a size limit of 400KB, which
       cannot be increased.

1.4. Dependencies

1.4.1. OpenSIPS Modules

   There is no need to load any module before this module.

1.4.2. External Libraries or Applications

   The following libraries or applications must be installed
   before running OpenSIPS with this module loaded:
     * AWS SDK for C++:
       By following these steps, you'll have the AWS SDK for C++
       installed and configured on your Linux system, allowing you
       to integrate with DynamoDB: AWS SDK for C++ Installation
       Guide
       Additional instructions for installation can be found at:
       AWS SDK for C++ GitHub Repository

1.4.3. Deploying DynamoDB locally on your computer

   For testing purposes, you can run a DynamoDB locally. To
   achieve this, you should follow these steps in order to deploy
   dynamodb locally.

   Don't forget to always run the server using this command: java
   -Djava.library.path=./DynamoDBLocal_lib -jar DynamoDBLocal.jar
   -sharedDb in the directory where you extracted
   DynamoDBLocal.jar.

1.5. Exported Parameters

1.5.1. cachedb_url (string)

   The URLs of the server groups that OpenSIPS will connect to in
   order to use, from script, the cache_store(), cache_fetch(),
   etc. operations. It may be set more than once. The prefix part
   of the URL will be the identifier that will be used from the
   script.

   There are some default parameters that can appear in the URL:
     * region - specifies the AWS region where the DynamoDB table
       is located
     * key - specifies the table's Key column; default value is
       "opensipskey"
     * val - specifies the table's Value column on which cache
       operations such as cache_store, cache_fetch, etc., will be
       performed; default value is "opensipsval"

   Syntax for cachedb_url
     * when using a previously created table (you have to specify
       the key and value):
          + host and port
            "dynamodb://id_host:id_port/tableName?key=key1;val=val
            1"
          + region
            "dynamodb:///tableName?region=regionName;key=key2;val=
            val2"
     * when using the default key and value:
          + host and port
            "dynamodb://id_host:id_port/tableName"
          + region
            "dynamodb:///tableName?region=regionName"

   Example 1.1. Set cachedb_url parameter
...

# single-instance URLs
modparam("cachedb_dynamodb", "cachedb_url", "dynamodb://localhost:8000/t
able1")
modparam("cachedb_dynamodb", "cachedb_url", "dynamodb:///table2?region=c
entral-1")


# multi-instance URL (will perform circular failover on each query)
modparam("cachedb_dynamodb", "cachedb_url",
        "dynamodb://localhost:8000/table1?key=Key;val=Val")
modparam("cachedb_dynamodb", "cachedb_url",
        "dynamodb:///table2?region=central-1;key=Key;val=Val")


...

   Example 1.2. Use Dynamodb servers
...

cache_store("dynamodb", "call1", "10");
cache_store("dynamodb", "call2", "25", 150) // expires = 150s -optional
cache_fetch("dynamodb", "call1", $var(total));
cache_remove("dynamodb", "call1");


cache_store("dynamodb", "counter1", "200");
cache_sub("dynamodb", "counter1", 4, 1000); // expires = 1000s -mandator
y parameter
cache_add("dynamodb", "call2", 5, 0) // -this update will not expire  -m
andatory parameter
cache_remove("dynamodb", "counter1");

...

1.6. Exported Functions

   The module does not export functions to be used in
   configuration script.

Chapter 2. Contributors

2.1. By Commit Statistics

   Table 2.1. Top contributors by DevScore^(1), authored
   commits^(2) and lines added/removed^(3)
                   Name               DevScore Commits Lines ++ Lines --
   1. Alexandra Titoc                    67      17      3573     1192
   2. Razvan Crainea (@razvancrainea)    6        2       0       213

   (1) DevScore = author_commits + author_lines_added /
   (project_lines_added / project_commits) + author_lines_deleted
   / (project_lines_deleted / project_commits)

   (2) including any documentation-related commits, excluding
   merge commits. Regarding imported patches/code, we do our best
   to count the work on behalf of the proper owner, as per the
   "fix_authors" and "mod_renames" arrays in
   opensips/doc/build-contrib.sh. If you identify any
   patches/commits which do not get properly attributed to you,
   please submit a pull request which extends "fix_authors" and/or
   "mod_renames".

   (3) ignoring whitespace edits, renamed files and auto-generated
   files

2.2. By Commit Activity

   Table 2.2. Most recently active contributors^(1) to this module
                   Name                 Commit Activity
   1. Alexandra Titoc                 Jul 2024 - Sep 2024
   2. Razvan Crainea (@razvancrainea) Aug 2024 - Aug 2024

   (1) including any documentation-related commits, excluding
   merge commits

Chapter 3. Documentation

3.1. Contributors

   Last edited by: Razvan Crainea (@razvancrainea), Alexandra
   Titoc.

   Documentation Copyrights:

   Copyright © 2024 www.opensips-solutions.com
