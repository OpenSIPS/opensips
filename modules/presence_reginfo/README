presence_reginfo Module

Carsten Bock

   <carsten@ng-voice.com>

Edited by

Carsten Bock

   <carsten@ng-voice.com>
     __________________________________________________________

   Table of Contents

   1. Admin Guide

        1.1. Overview
        1.2. Dependencies

              1.2.1. OpenSIPS Modules
              1.2.2. External Libraries or Applications

        1.3. Parameters

              1.3.1. default_expires (int)
              1.3.2. aggregate_presentities (int)

        1.4. Functions

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

   1.1. Set default_expires parameter
   1.2. Set aggregate_presentities parameter

Chapter 1. Admin Guide

1.1. Overview

   The module enables the handling of "Event: reg" (as defined in
   RFC 3680) inside of the presence module. This can be used
   distribute the registration-info status to the subscribed
   watchers.

   The module does not currently implement any authorization
   rules. It assumes that publish requests are only issued by an
   authorized application and subscribe requests only by
   authorized users. Authorization can thus be easily done in
   OpenSIPS configuration file before calling handle_publish() and
   handle_subscribe() functions.

   Note: This module only activates the processing of the "reg" in
   the presence module. To send dialog-info to watchers you also
   need a source which PUBLISH the reg info to the presence
   module. For example you can use the pua_reginfo module or any
   external component. This approach allows to have the presence
   server and the reg-info aware publisher (e.g. the main proxy)
   on different OpenSIPS instances.

1.2. Dependencies

1.2.1. OpenSIPS Modules

   The following modules must be loaded before this module:
     * presence.

1.2.2. External Libraries or Applications

   None.

1.3. Parameters

1.3.1. default_expires (int)

   The default expires value used when missing from SUBSCRIBE
   message (in seconds).

   Default value is “3600”.

   Example 1.1. Set default_expires parameter
        ...
        modparam("presence_reginfo", "default_expires", 3600)
        ...

1.3.2. aggregate_presentities (int)

   Whether to aggregate in a single notify body all registration
   presentities. Useful to have all registrations on first NOTIFY
   following initial SUBSCRIBE.

   Default value is “0” (disabled).

   Example 1.2. Set aggregate_presentities parameter
                                        ...
                                        modparam("presence_reginfo", "ag
gregate_presentities", 1)
                                        ...

1.4. Functions

   None to be used in configuration file.

Chapter 2. Contributors

2.1. By Commit Statistics

   Table 2.1. Top contributors by DevScore^(1), authored
   commits^(2) and lines added/removed^(3)
     Name DevScore Commits Lines ++ Lines --
   1. Carsten Bock 8 1 771 0
   2. Bogdan-Andrei Iancu (@bogdan-iancu) 4 2 14 17

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
   1. Bogdan-Andrei Iancu (@bogdan-iancu) Apr 2024 - Apr 2024
   2. Carsten Bock                        Mar 2024 - Mar 2024

   (1) including any documentation-related commits, excluding
   merge commits

Chapter 3. Documentation

3.1. Contributors

   Last edited by: Bogdan-Andrei Iancu (@bogdan-iancu), Carsten
   Bock.

   Documentation Copyrights:

   Copyright © 2011-2023 Carsten Bock, carsten@ng-voice.com,
   http://www.ng-voice.com
