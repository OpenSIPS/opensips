db_sqlite Module
     __________________________________________________________

   Table of Contents

   1. Admin Guide

        1.1. Overview
        1.2. Dependencies

              1.2.1. OpenSIPS Modules
              1.2.2. External Libraries or Applications

        1.3. Exported Parameters

              1.3.1. alloc_limit (integer)
              1.3.2. load_extension (string)
              1.3.3. busy_timeout (integer)
              1.3.4. exec_pragma (string)

        1.4. Exported Functions
        1.5. Installation

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

   1.1. Set alloc_limit parameter
   1.2. Set load_extension parameter
   1.3. Set busy_timeout parameter
   1.4. Set exec_pragma parameter

Chapter 1. Admin Guide

1.1. Overview

   This is a module which provides SQLite support for OpenSIPS. It
   implements the DB API defined in OpenSIPS.

1.2. Dependencies

1.2.1. OpenSIPS Modules

   The following modules must be loaded before this module:
     * No dependencies on other OpenSIPS modules.

   Also this module provides two ways of creating the query. One
   is to use sqlite3_bind_* functions after opensips creates the
   prepared statement query. The second one directly uses only
   sqlite3_snprintf function to print the values into the opensips
   created query. In theory, the second one should be faster and
   should allow you to make more queries to the database in the
   same time, so by default this one will be active. You can use
   the sqlite3_bind_* interface by simply uncommenting the
   SQLITE_BIND line the Makefile.

1.2.2. External Libraries or Applications

   The following libraries or applications must be installed
   before running OpenSIPS with this module loaded:
     * libsqlite3-dev - the development libraries of sqlite.

1.3. Exported Parameters

1.3.1. alloc_limit (integer)

   Since the library does not support a function to return the
   number of rows in a query, this number is obtained using
   "count(*)" query. If we use multiple processes there is the
   risk ,since "count(*)" query and the actual "select" query, the
   number of rows in the result query to have changed, so realloc
   will be needed if the number is bigger. Using alloc_limit
   parameter you can specify the number with which the number of
   allocated rows in the result is raised.

   Default value is 10.

   Example 1.1. Set alloc_limit parameter
...
modparam("db_sqlite", "alloc_limit", 25)
...

1.3.2. load_extension (string)

   This parameter enables extension loading, similiar to ".load"
   functionality in sqlite3, extenions like sqlite3-pcre which
   enables REGEX function. In order to use this functionality you
   must specify the library path (.so file) and the entry point
   which represents the function to be called by the sqlite
   library (read more at sqlite load_extension official
   documentation), separated by ";" delimiter. The entry point
   paramter can miss, so you won't need to use the delimitier in
   this case.

   By default, no extension is loaded.

   Example 1.2. Set load_extension parameter
...
modparam("db_sqlite", "load_extension", "/usr/lib/sqlite3/pcre.so")
modparam("db_sqlite", "load_extension", "/usr/lib/sqlite3/pcre.so;sqlite
3_extension_init")
...

1.3.3. busy_timeout (integer)

   This parameter sets the default busy_handler for the SQLite
   library, that sleeps for a specified amount of time when a
   table is locked. The handler will sleep multiple times until at
   least the specified "busy_timeout" duration (in milliseconds)
   has been reached. Setting this parameter to a value less than
   or equal to zero turns off all busy handlers. (read more in the
   SQLite official documentation)

   Default value is 500.

   Example 1.3. Set busy_timeout parameter
...
modparam("db_sqlite", "busy_timeout", 5000)
...

1.3.4. exec_pragma (string)

   This parameter allows configuring an SQLite database with
   "PRAGMA" statements, (read more in the SQLite official
   documentation) To use this functionality you must specify the
   exec_pragma parameter value as "pragma-name=pragma-value".
   Multiple parameters with the same name can be specified, and
   they will be executed one by one on every database connection.
   If a parameter has an incorrect name or syntax, it will be
   ignored by SQLite without any error messages.

   By default, no PRAGMA statements are executed.

   Example 1.4. Set exec_pragma parameter
...
modparam("db_sqlite", "exec_pragma", "journal_mode=wal")
modparam("db_sqlite", "exec_pragma", "synchronous=normal")
modparam("db_sqlite", "exec_pragma", "cache_size=-2000")
...

1.4. Exported Functions

   No function exported to be used from configuration file.

1.5. Installation

   Because it dependes on an external library, the sqlite module
   is not compiled and installed by default. You can use one of
   the next options.
     * - edit the "Makefile" and remove "db_sqlite" from
       "excluded_modules" list. Then follow the standard procedure
       to install OpenSIPS: "make all; make install".
     * - from command line use: 'make all
       include_modules="db_sqlite"; make install
       include_modules="db_sqlite"'.

Chapter 2. Contributors

2.1. By Commit Statistics

   Table 2.1. Top contributors by DevScore^(1), authored
   commits^(2) and lines added/removed^(3)
                  Name                DevScore Commits Lines ++ Lines --
1.  Ionut Ionita (@ionutrazvanionita)    81      28      3744     1276
2.  Razvan Crainea (@razvancrainea)      19      17      115       42
3.  Alexey Vasilyev (@vasilevalex)       13       9      165       96
4.  Liviu Chircu (@liviuchircu)          12      10       32       60
5.  Jarrod Baumann (@jarrodb)            5        3       7        4
6.  Vlad Patrascu (@rvlad-patrascu)      4        2       3        2
7.  Alexandra Titoc                      4        2       2        3
8.  Aron Podrigal (@ar45)                3        1       10       1
9.  Daniel Fussia                        3        1       4        22
10. Maksym Sobolyev (@sobomax)           3        1       2        2

   All remaining contributors: Bogdan-Andrei Iancu
   (@bogdan-iancu), Eric Green, Peter Lemenkov (@lemenkov).

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
                      Name                   Commit Activity
   1.  Razvan Crainea (@razvancrainea)     Aug 2015 - Jan 2025
   2.  Alexey Vasilyev (@vasilevalex)      Dec 2024 - Dec 2024
   3.  Liviu Chircu (@liviuchircu)         May 2016 - Sep 2024
   4.  Alexandra Titoc                     Sep 2024 - Sep 2024
   5.  Maksym Sobolyev (@sobomax)          Feb 2023 - Feb 2023
   6.  Eric Green                          Aug 2020 - Aug 2020
   7.  Bogdan-Andrei Iancu (@bogdan-iancu) Apr 2019 - Apr 2019
   8.  Vlad Patrascu (@rvlad-patrascu)     May 2017 - Apr 2019
   9.  Peter Lemenkov (@lemenkov)          Jun 2018 - Jun 2018
   10. Ionut Ionita (@ionutrazvanionita)   Apr 2015 - Feb 2017

   All remaining contributors: Daniel Fussia, Jarrod Baumann
   (@jarrodb), Aron Podrigal (@ar45).

   (1) including any documentation-related commits, excluding
   merge commits

Chapter 3. Documentation

3.1. Contributors

   Last edited by: Alexey Vasilyev (@vasilevalex), Liviu Chircu
   (@liviuchircu), Peter Lemenkov (@lemenkov), Ionut Ionita
   (@ionutrazvanionita).

   Documentation Copyrights:

   Copyright © 2015 www.opensips-solutions.com
