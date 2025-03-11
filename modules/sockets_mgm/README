Example Module
     __________________________________________________________

   Table of Contents

   1. Admin Guide

        1.1. Overview
        1.2. Dependencies

              1.2.1. OpenSIPS Modules
              1.2.2. External Libraries or Applications

        1.3. Exported Parameters

              1.3.1. default_str (string)
              1.3.2. default_int (integer)

        1.4. Exported Functions

              1.4.1. example()
              1.4.2. example_str([string])
              1.4.3. example_int([int])

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

   1.1. Set “default_str” parameter
   1.2. Set “default_int” parameter
   1.3. example usage
   1.4. example_str() usage
   1.5. example_int() usage

Chapter 1. Admin Guide

1.1. Overview

   This module serves as an example of how to write a module in
   OpenSIPS. Its primary goal is to simplify the development of
   new modules for newcomers, providing a clear and accessible
   starting point.

1.2. Dependencies

1.2.1. OpenSIPS Modules

   The following modules must be loaded before this module:
     * No dependencies on other OpenSIPS modules.

1.2.2. External Libraries or Applications

   The following libraries or applications must be installed
   before running OpenSIPS with this module loaded:
     * None.

1.3. Exported Parameters

1.3.1. default_str (string)

   The default parameter used when the example_str() function is
   called without any parameter.

   Default value is “” (empty sring).

   Example 1.1. Set “default_str” parameter
...
modparam("example", "default_str", "TEST")
...

1.3.2. default_int (integer)

   The default parameter used when the example_int() function is
   called without any parameter.

   Default value is “0”.

   Example 1.2. Set “default_int” parameter
...
modparam("example", "default_int", -1)
...

1.4. Exported Functions

1.4.1.  example()

   Function that simply prints a message to log, saying that it
   has been called.

   This function can be used from any route.

   Example 1.3. example usage
...
example();
...

1.4.2.  example_str([string])

   Function that simply prints a message to log, saying that it
   has been called. If a parameter is passed, it is printed in the
   log, otherwise the value of default_str parameter is used.

   Meaning of the parameters is as follows:
     * string (string, optional) - parameter to be logged

   This function can be used from any route.

   Example 1.4. example_str() usage
...
example_str("test");
...

1.4.3.  example_int([int])

   Function that simply prints a message to log, saying that it
   has been called. If a parameter is passed, it is printed in the
   log, otherwise the value of default_int parameter is used.

   Meaning of the parameters is as follows:
     * int (integer, optional) - parameter to be logged

   This function can be used from any route.

   Example 1.5. example_int() usage
...
example_int(10);
...

Chapter 2. Contributors

2.1. By Commit Statistics

   Table 2.1. Top contributors by DevScore^(1), authored
   commits^(2) and lines added/removed^(3)
                   Name               DevScore Commits Lines ++ Lines --
   1. Razvan Crainea (@razvancrainea)    4        1      349       0

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
   1. Razvan Crainea (@razvancrainea) Jul 2024 - Jul 2024

   (1) including any documentation-related commits, excluding
   merge commits

Chapter 3. Documentation

3.1. Contributors

   Last edited by: Razvan Crainea (@razvancrainea).

   Documentation Copyrights:

   Copyright © 2024 OpenSIPS Solutions;
