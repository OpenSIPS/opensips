RTP.io Module
     __________________________________________________________

   Table of Contents

   1. Admin Guide

        1.1. Overview
        1.2. Dependencies
        1.3. Exported Parameters

              1.3.1. rtpproxy_args(string)

        1.4. Exported Functions

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

   1.1. Set rtpproxy_args parameter

Chapter 1. Admin Guide

1.1. Overview

   The RTP.io module provides an integrated solution for handling
   RTP traffic within OpenSIPS, enabling RTP relaying and
   processing directly inside the OpenSIPS process. This
   eliminates the need for external processes such as RTPProxy,
   resulting in a more streamlined, efficient, and manageable
   system for certain use cases.

   The rtp.io module starts RTP handling threads in the main
   OpenSIPS process and allows the rtpproxy module to access these
   threads via a one-to-one socket pair. This tight integration
   facilitates efficient RTP traffic management within OpenSIPS
   without relying on external RTP handling services.

   The module requires RTPProxy™ version 3.1 or higher, compiled
   with the --enable-librtpproxy option to build. It utilizes the
   librtpproxy library to manage RTP traffic and interfaces with
   the existing rtpproxy module to generate commands, parse
   responses, and process SIP messages.

   When the rtpproxy module is loaded without arguments and the
   rtp.io module is also loaded, the sockets exported by rtp.io
   are used automatically in set 0. Alternatively, these sockets
   can be incorporated into other sets by using the "rtp.io:auto"
   moniker.

1.2. Dependencies

1.3. Exported Parameters

1.3.1. rtpproxy_args(string)

   Command-line parameteres passed down to the embedded RTPProxy
   module upon initialization. Refer to the RTPProxy documentation
   for the full list.

   Parameter has no default value.

   Example 1.1. Set rtpproxy_args parameter
...
modparam("rtp.io", "rtpproxy_args", "-m 12000 -M 15000 -l 0.0.0.0 -6 /::
")
...

1.4. Exported Functions

Chapter 2. Contributors

2.1. By Commit Statistics

   Table 2.1. Top contributors by DevScore^(1), authored
   commits^(2) and lines added/removed^(3)
                 Name            DevScore Commits Lines ++ Lines --
   1. Maksym Sobolyev (@sobomax)    7        1      660       0

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
                 Name              Commit Activity
   1. Maksym Sobolyev (@sobomax) Jun 2024 - Jun 2024

   (1) including any documentation-related commits, excluding
   merge commits

Chapter 3. Documentation

3.1. Contributors

   Last edited by: Maksym Sobolyev (@sobomax).

   Documentation Copyrights:

   Copyright © 2023 Sippy Software, Inc.
