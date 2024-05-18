Status/Reports Module
     __________________________________________________________

   Table of Contents

   1. Admin Guide

        1.1. Overview
        1.2. Dependencies

              1.2.1. OpenSIPS Modules
              1.2.2. External Libraries or Applications

        1.3. Exported Parameters

              1.3.1. script_sr_group (string)

        1.4. Exported Functions

              1.4.1. sr_set_status( group, status, [details])
              1.4.2. sr_add_report( group, report)

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

   1.1. script_sr_group example
   1.2. sr_set_status usage
   1.3. sr_add_report usage

Chapter 1. Admin Guide

1.1. Overview

   The Status/Report module is a wrapper over the internal
   status/report framework, allowing the script writer to
   dynamically define and use of SR groups.

   By bringing the Status/Report support into the script, it opens
   the possibility to create custom reports from script, depending
   on the logic you have there.

1.2. Dependencies

1.2.1. OpenSIPS Modules

   The following modules must be loaded before this module:
     * No dependencies on other OpenSIPS modules.

1.2.2. External Libraries or Applications

   The following libraries or applications must be installed
   before running OpenSIPS with this module loaded:
     * None.

1.3. Exported Parameters

1.3.1. script_sr_group (string)

   Name of a new Status/Report group to be created and later used
   from script level.

   This parameter may be defined multiple times, in order to
   define multiple groups.

   Example 1.1. script_sr_group example
modparam("status_report", "script_sr_group", "security")
modparam("status_report", "script_sr_group", "alarms")

1.4. Exported Functions

1.4.1.  sr_set_status( group, status, [details])

   Sets a new status (and details) for a Status/Report group.

   Meaning of the parameters is as follows:
     * group (string) - the name of the SR group; you can change
       the status only for the groups defined via this module (as
       parameter).
     * status (int) - the new status value ( strict positive
       meaning OK, strict negative meaning NOT OK, 0 is not
       accepts, it is converted to 1 automatically).
     * details (string, optional) - a descripting text to detail
       the status value

   This function can be used from any route.

   Example 1.2. sr_set_status usage
...
sr_set_status( "script_caching", 1, "completed");
...

1.4.2.  sr_add_report( group, report)

   Adds a new report/log to a Status/Report group.This must have
   been defined via this module too.

   Meaning of the parameters is as follows:
     * group (string) - the name of the SR group; you can change
       the status only for the groups defined via this module (as
       parameter).
       report (string) - the log to be added.

   This function can be used from any route.

   Example 1.3. sr_add_report usage
...
sr_add_report("security","IP $si detected as attacker");
...

Chapter 2. Contributors

2.1. By Commit Statistics

   Table 2.1. Top contributors by DevScore^(1), authored
   commits^(2) and lines added/removed^(3)
     Name DevScore Commits Lines ++ Lines --
   1. Bogdan-Andrei Iancu (@bogdan-iancu) 7 3 339 7
   2. Liviu Chircu (@liviuchircu) 5 3 8 6
   3. Maksym Sobolyev (@sobomax) 4 2 2 3

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
   1. Liviu Chircu (@liviuchircu)         May 2024 - May 2024
   2. Maksym Sobolyev (@sobomax)          Feb 2023 - Feb 2023
   3. Bogdan-Andrei Iancu (@bogdan-iancu) Feb 2022 - Feb 2022

   (1) including any documentation-related commits, excluding
   merge commits

Chapter 3. Documentation

3.1. Contributors

   Last edited by: Bogdan-Andrei Iancu (@bogdan-iancu).

   Documentation Copyrights:

   Copyright © 2022 OpenSIPS Solutions
