UAC Module
     __________________________________________________________

   Table of Contents

   1. Admin Guide

        1.1. Overview
        1.2. Dependencies

              1.2.1. OpenSIPS Modules
              1.2.2. External Libraries or Applications

        1.3. Exported Parameters

              1.3.1. restore_mode (string)
              1.3.2. restore_passwd (string)
              1.3.3. rr_from_store_param (string)
              1.3.4. rr_to_store_param (string)
              1.3.5. force_dialog (int)

        1.4. Exported Functions

              1.4.1. uac_replace_from([display],uri)
                      uac_replace_to([display],uri)

              1.4.2. uac_restore_from() uac_restore_to()
              1.4.3. uac_auth()
              1.4.4. uac_inc_cseq()

   2. Frequently Asked Questions
   3. Contributors

        3.1. By Commit Statistics
        3.2. By Commit Activity

   4. Documentation

        4.1. Contributors

   List of Tables

   3.1. Top contributors by DevScore^(1), authored commits^(2) and
          lines added/removed^(3)

   3.2. Most recently active contributors^(1) to this module

   List of Examples

   1.1. Set restore_mode parameter
   1.2. Set restore_passwd parameter
   1.3. Set rr_from_store_param parameter
   1.4. Set rr_to_store_param parameter
   1.5. Set force_dialog parameter
   1.6. uac_replace_from/uac_replace_to usage
   1.7. uac_restore_from/uac_restore_to usage
   1.8. uac_auth usage
   1.9. uac_inc_cseq usage

Chapter 1. Admin Guide

1.1. Overview

   UAC (User Agent Client) module provides some basic UAC
   functionalities like FROM / TO header manipulation
   (anonymization) or client authentication.

   If the dialog module is loaded and a dialog can be created,
   then the auto mode can be done more efficiently.

1.2. Dependencies

1.2.1. OpenSIPS Modules

   The following modules must be loaded before this module:
     * TM - Transaction Module.
     * RR - Record-Route Module, but only if restore mode for FROM
       URI is set to “auto”.
     * UAC_AUTH - UAC Authentication Module.
     * Dialog Module, if “force_dialog” module parameter is
       enabled, or a dialog is created from the configuration
       script.

1.2.2. External Libraries or Applications

   The following libraries or applications must be installed
   before running OpenSIPS with this module loaded:
     * None

1.3. Exported Parameters

1.3.1. restore_mode (string)

   There are 3 mode of restoring the original headers (FROM/TO)
   URI:
     * “none” - no information about original URI is stored;
       restoration is not possible.
     * “manual” - all following replies will be restored, except
       for the sequential requests - these must be manually
       updated based on original URI.
     * “auto” - all sequential requests and replies will be
       automatically updated based on stored original URI.

   This parameter is optional, it's default value being “auto”.

   Example 1.1. Set restore_mode parameter
...
modparam("uac","restore_mode","auto")
...

1.3.2. restore_passwd (string)

   String password to be used to encrypt the RR storing parameter
   (when replacing the TO/FROM headers). If empty, no encryption
   will be used.

   Default value of this parameter is empty.

   Example 1.2. Set restore_passwd parameter
...
modparam("uac","restore_passwd","my_secret_passwd")
...

1.3.3. rr_from_store_param (string)

   Name of Record-Route header parameter that will be used to
   store (encoded) the original FROM URI.

   This parameter is optional, it's default value being “vsf”.

   Example 1.3. Set rr_from_store_param parameter
...
modparam("uac","rr_from_store_param","my_Fparam")
...

1.3.4. rr_to_store_param (string)

   Name of Record-Route header parameter that will be used to
   store (encoded) the original TO URI.

   This parameter is optional, it's default value being “vst”.

   Example 1.4. Set rr_to_store_param parameter
...
modparam("uac","rr_to_store_param","my_Tparam")
...

1.3.5. force_dialog (int)

   Force create dialog if it is not created from the configuration
   script.

   Default value is no.

   Example 1.5. Set force_dialog parameter
...
modparam("uac", "force_dialog", yes)
...

1.4. Exported Functions

1.4.1.  uac_replace_from([display],uri) uac_replace_to([display],uri)

   Replace in FROM/TO header the display name or/and the URI part.

   Both parameters are string. The display is optional. If
   missing, only the URI will be changed in the message.

   IMPORTANT: calling the function more than once per branch will
   lead to inconsistent changes over the request.Be sure you do
   the change only ONCE per branch. Note that calling the function
   from REQUEST ROUTE affects all the branches!, so no other
   change will be possible in the future. For per branch changes
   use BRANCH and FAILURE route.

   This function can be used from REQUEST_ROUTE, BRANCH_ROUTE and
   FAILURE_ROUTE.

   Example 1.6. uac_replace_from/uac_replace_to usage
...
# replace both display and uri
uac_replace_from($avp(display),$avp(uri));
# replace only display and do not touch uri
uac_replace_from("batman","");
# remove display and replace uri
uac_replace_from("","sip:robin@gotham.org");
# remove display and do not touch uri
uac_replace_from("","");
# replace the URI without touching the display
uac_replace_from( , "sip:batman@gotham.org");
...

1.4.2.  uac_restore_from() uac_restore_to()

   This function will check if the FROM/TO URI was modified and
   will use the information stored in header parameter to restore
   the original FROM/TO URI value.

   NOTE - this function should be used only if you configured
   MANUAL restoring of the headers (see restore_mode param). For
   AUTO and NONE, there is no need to use this function.

   This function can be used from REQUEST_ROUTE.

   Example 1.7. uac_restore_from/uac_restore_to usage
...
uac_restore_from();
...

1.4.3.  uac_auth()

   This function can be called only from failure route and will
   build the authentication response header and insert it into the
   request without sending anything. Credentials for buiding the
   authentication response will be taken from the list of
   credentials provided by the uac_auth module (static or via
   AVPs).

   As optional parameter, the function may receive a list of auth
   algorithms to be considered / supported during authentication:
     * MD5, MD5-sess
     * SHA-256, SHA-256-sess (may be missing, depends on lib
       support)
     * SHA-512-256, SHA-512-256-sess (may be missing, depends on
       lib support)

   Note that the CSeq is automatically increased during
   authentication.

   This function can be used from FAILURE_ROUTE.

   NOTE: when used without dialog support, the uac_auth() function
   cannot be used for authenticating in-dialog requests, as there
   is no mechanism to store the CSeq changes that are required for
   ensuring the correctness of the dialog. The only exception are
   BYE messages, which are the last messages within a call, hence
   no further adjustments are needed. The function can still be
   used for authenticating the initial INVITE though.

   Example 1.8. uac_auth usage
...
uac_auth();
...
failure_route[check_auth] {
    ...
    if ($T_reply_code==407) {
        if (uac_auth("MD5,MD5-sess")) {
            # auth is succesful, just relay
            t_relay();
            exit;
        }
        # auth failed (no credentials maybe)
        # so continue handling the 407 reply
    }
    ...
}
...

1.4.4.  uac_inc_cseq()

   This function can be called to increase the CSeq of an ongoing
   request.

   It receives as the cseq parameter the value that the CSeq
   should be incremented with.

   This function can be used from REQUEST_ROUTE, BRANCH_ROUTE and
   FAILURE_ROUTE.

   Example 1.9. uac_inc_cseq usage
...
uac_inc_cseq(1);
...

Chapter 2. Frequently Asked Questions

   2.1.

   What happened with auth_username_avp, auth_realm_avp and
   auth_password_avp parameters

   Due some restructuring of the UAC auth modules, these
   parameters were moved into the "uac_auth" module. This module
   is now responsible for handling all the credentials (static
   defined or dynamically defined via AVPs). The UAC module will
   still see the credentials defined via the AVPs.
   $

   2.2.

   Where can I find more about OpenSIPS?

   Take a look at https://opensips.org/.

   2.3.

   Where can I post a question about this module?

   First at all check if your question was already answered on one
   of our mailing lists:
     * User Mailing List -
       http://lists.opensips.org/cgi-bin/mailman/listinfo/users
     * Developer Mailing List -
       http://lists.opensips.org/cgi-bin/mailman/listinfo/devel

   E-mails regarding any stable OpenSIPS release should be sent to
   <users@lists.opensips.org> and e-mails regarding development
   versions should be sent to <devel@lists.opensips.org>.

   If you want to keep the mail private, send it to
   <users@lists.opensips.org>.

   2.4.

   How can I report a bug?

   Please follow the guidelines provided at:
   https://github.com/OpenSIPS/opensips/issues.

Chapter 3. Contributors

3.1. By Commit Statistics

   Table 3.1. Top contributors by DevScore^(1), authored
   commits^(2) and lines added/removed^(3)
     Name DevScore Commits Lines ++ Lines --
   1. Bogdan-Andrei Iancu (@bogdan-iancu) 129 75 4208 1076
   2. Ovidiu Sas (@ovidiusas) 34 8 403 1351
   3. Razvan Crainea (@razvancrainea) 32 24 560 148
   4. Liviu Chircu (@liviuchircu) 27 19 305 298
   5. Daniel-Constantin Mierla (@miconda) 15 11 138 88
   6. Vlad Patrascu (@rvlad-patrascu) 10 5 150 175
   7. Maksym Sobolyev (@sobomax) 10 3 168 294
   8. Vlad Paiu (@vladpaiu) 9 5 243 18
   9. Andreas Heise 7 3 105 129
   10. Edson Gellert Schubert 5 1 0 201

   All remaining contributors: Elena-Ramona Modroiu, Henning
   Westerholt (@henningw), Konstantin Bokarius, Peter Lemenkov
   (@lemenkov), Dan Pascu (@danpascu), Dusan Klinec (@ph4r05),
   Jesus Rodrigues, Sergio Gutierrez.

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

3.2. By Commit Activity

   Table 3.2. Most recently active contributors^(1) to this module
                      Name                   Commit Activity
   1.  Liviu Chircu (@liviuchircu)         Mar 2014 - Oct 2024
   2.  Razvan Crainea (@razvancrainea)     Aug 2010 - Aug 2023
   3.  Ovidiu Sas (@ovidiusas)             Mar 2011 - Jun 2023
   4.  Bogdan-Andrei Iancu (@bogdan-iancu) Jun 2005 - Apr 2023
   5.  Vlad Patrascu (@rvlad-patrascu)     May 2017 - Mar 2023
   6.  Maksym Sobolyev (@sobomax)          Mar 2021 - Feb 2023
   7.  Peter Lemenkov (@lemenkov)          Jun 2018 - Jun 2018
   8.  Dusan Klinec (@ph4r05)              Dec 2015 - Dec 2015
   9.  Vlad Paiu (@vladpaiu)               Aug 2011 - Sep 2015
   10. Sergio Gutierrez                    Nov 2008 - Nov 2008

   All remaining contributors: Dan Pascu (@danpascu),
   Daniel-Constantin Mierla (@miconda), Konstantin Bokarius, Edson
   Gellert Schubert, Henning Westerholt (@henningw), Jesus
   Rodrigues, Andreas Heise, Elena-Ramona Modroiu.

   (1) including any documentation-related commits, excluding
   merge commits

Chapter 4. Documentation

4.1. Contributors

   Last edited by: Razvan Crainea (@razvancrainea), Bogdan-Andrei
   Iancu (@bogdan-iancu), Vlad Patrascu (@rvlad-patrascu), Peter
   Lemenkov (@lemenkov), Liviu Chircu (@liviuchircu), Ovidiu Sas
   (@ovidiusas), Daniel-Constantin Mierla (@miconda), Konstantin
   Bokarius, Edson Gellert Schubert, Jesus Rodrigues, Elena-Ramona
   Modroiu.

   Documentation Copyrights:

   Copyright © 2005-2009 Voice Sistem SRL
