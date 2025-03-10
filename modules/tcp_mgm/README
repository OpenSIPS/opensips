TCP Management Module (tcp_mgm)
     __________________________________________________________

   Table of Contents

   1. Admin Guide

        1.1. Overview
        1.2. Dependencies

              1.2.1. OpenSIPS Modules
              1.2.2. External Libraries or Applications

        1.3. Exported Parameters

              1.3.1. db_url (string)
              1.3.2. db_table (string)
              1.3.3. [column-name]_col (string)

        1.4. Exported MI Functions

              1.4.1. tcp_reload

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

   1.1. Setting the db_url parameter
   1.2. Setting the db_table parameter
   1.3. Setting the [column-name]_col parameter

Chapter 1. Admin Guide

1.1. Overview

   This module provides optional, SQL-based support for
   fine-grained management of all TCP connections taking place on
   OpenSIPS.

1.2. Dependencies

1.2.1. OpenSIPS Modules

   At least one SQL database module must be loaded (e.g.
   "db_xxx").

1.2.2. External Libraries or Applications

   None.

1.3. Exported Parameters

1.3.1. db_url (string)

   Mandatory URL to the SQL database.

   Example 1.1. Setting the db_url parameter

modparam("tcp_mgm", "db_url", "mysql://opensips:opensipsrw@localhost/ope
nsips")


1.3.2. db_table (string)

   The name of the table holding the TCP paths (rules).

   Default value is "tcp_mgm".

   Example 1.2. Setting the db_table parameter

modparam("tcp_mgm", "db_table", "tcp_mgm")


1.3.3. [column-name]_col (string)

   Use a different name for column "column-name".

   Example 1.3. Setting the [column-name]_col parameter

modparam("tcp_mgm", "connect_timeout_col", "connect_to")


1.4. Exported MI Functions

1.4.1.  tcp_reload

   Reload all TCP paths from the tcp_mgm table without disrupting
   ongoing traffic. Note that the reloaded rules will NOT
   immediately apply to existing TCP connections, rather only to
   newly established ones.

   Example:

# reload all TCP paths
$ opensips-cli -x mi tcp_reload
$ "OK"

Chapter 2. Contributors

2.1. By Commit Statistics

   Table 2.1. Top contributors by DevScore^(1), authored
   commits^(2) and lines added/removed^(3)
                 Name             DevScore Commits Lines ++ Lines --
   1. Liviu Chircu (@liviuchircu)    21       8      1281      62
   2. Maksym Sobolyev (@sobomax)     5        3       9        10

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
                 Name               Commit Activity
   1. Maksym Sobolyev (@sobomax)  Feb 2023 - Nov 2023
   2. Liviu Chircu (@liviuchircu) Apr 2022 - Jul 2022

   (1) including any documentation-related commits, excluding
   merge commits

Chapter 3. Documentation

3.1. Contributors

   Last edited by: Liviu Chircu (@liviuchircu).

   Documentation Copyrights:

   Copyright © 2022 www.opensips-solutions.com
