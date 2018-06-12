#ifndef _CPL_TREE_DEFINITION_H
#define _CPL_TREE_DEFINITION_H



#define              CPL_NODE   1
#define         INCOMING_NODE   2
#define         OUTGOING_NODE   3
#define        ANCILLARY_NODE   4
#define        SUBACTION_NODE   5
#define   ADDRESS_SWITCH_NODE   6
#define          ADDRESS_NODE   7
#define             BUSY_NODE   8
#define          DEFAULT_NODE   9
#define          FAILURE_NODE  10
#define              LOG_NODE  11
#define           LOOKUP_NODE  12
#define         LOCATION_NODE  13
#define         LANGUAGE_NODE  14
#define  LANGUAGE_SWITCH_NODE  15
#define             MAIL_NODE  16
#define         NOTFOUND_NODE  17
#define         NOANSWER_NODE  18
#define            PROXY_NODE  19
#define         PRIORITY_NODE  20
#define  PRIORITY_SWITCH_NODE  21
#define           REJECT_NODE  22
#define         REDIRECT_NODE  23
#define      REDIRECTION_NODE  24
#define  REMOVE_LOCATION_NODE  25
#define              SUB_NODE  26
#define          SUCCESS_NODE  27
#define           STRING_NODE  28
#define    STRING_SWITCH_NODE  29
#define             TIME_NODE  30
#define      TIME_SWITCH_NODE  31
#define        OTHERWISE_NODE  32



/* attributs and values fro ADDRESS-SWITCH node */
#define  FIELD_ATTR                  0       /*shared with STRING_SWITCH*/
#define  SUBFIELD_ATTR               1
#define  ORIGIN_VAL                  0
#define  DESTINATION_VAL             1
#define  ORIGINAL_DESTINATION_VAL    2
#define  ADDRESS_TYPE_VAL            0
#define  USER_VAL                    1
#define  HOST_VAL                    2
#define  PORT_VAL                    3
#define  TEL_VAL                     4
#define  DISPLAY_VAL                 5

/* attributs and values for ADDRESS node */
#define  IS_ATTR                     0    /*shared with STRING*/
#define  CONTAINS_ATTR               1    /*shared with STRING*/
#define  SUBDOMAIN_OF_ATTR           2

/* attributs and values for STRING-SWITCH node */
#define  SUBJECT_VAL                 0
#define  ORGANIZATION_VAL            1
#define  USER_AGENT_VAL              2
#define  DISPALY_VAL                 3

/* attributs and values for LANGUAGE node */
#define  MATCHES_ATTR                0

/* attributs and values for TIME-SWITCH node */
#define  TZID_ATTR                   0
#define  TZURL_ATTR                  1

/* attributs and values for TIME node */
#define  DTSTART_ATTR                0
#define  DTEND_ATTR                  1
#define  DURATION_ATTR               2
#define  FREQ_ATTR                   3
#define  INTERVAL_ATTR               4
#define  UNTIL_ATTR                  5
#define  COUNT_ATTR                  6
#define  BYSECOND_ATTR               7
#define  BYMINUTE_ATTR               8
#define  BYHOUR_ATTR                 9
#define  BYDAY_ATTR                 10
#define  BYMONTHDAY_ATTR            11
#define  BYYEARDAY_ATTR             12
#define  BYWEEKNO_ATTR              13
#define  BYMONTH_ATTR               14
#define  WKST_ATTR                  15
#define  BYSETPOS_ATTR              16

/* attributs and values for PRIORITY node */
#define  LESS_ATTR                   0
#define  GREATER_ATTR                1
#define  EQUAL_ATTR                  2
#define  EMERGENCY_VAL               0
#define  URGENT_VAL                  1
#define  NORMAL_VAL                  2
#define  NON_URGENT_VAL              3

/* attributs and values for LOCATION node */
#define  URL_ATTR                    0
#define  PRIORITY_ATTR               1
#define  CLEAR_ATTR                  2    /*shared with LOOKUP node*/
#define  NO_VAL                      0    /*shared with LOOKUP node*/
#define  YES_VAL                     1    /*shared with LOOKUP node*/

/* attributs and values for LOOKUP node */
#define  SOURCE_ATTR                 0
#define  TIMEOUT_ATTR                1
#define  USE_ATTR                    2
#define  IGNORE_ATTR                 3

/* attributs and values for REMOVE_LOCATION node */
#define  LOCATION_ATTR               0
#define  PARAM_ATTR                  1
#define  VALUE_ATTR                  2

/* attributs and values for PROXY node */
#define  RECURSE_ATTR                0
#define  ORDERING_ATTR               1
#define  PARALLEL_VAL                0
#define  SEQUENTIAL_VAL              1
#define  FIRSTONLY_VAL               2

/* attributs and values for REDIRECT node */
#define  PERMANENT_ATTR              0

/* attributs and values for REJECT node */
#define  STATUS_ATTR                 0
#define  REASON_ATTR                 1

/* attributs and values for LOG node */
#define  NAME_ATTR                   0
#define  COMMENT_ATTR                1




#define      NODE_TYPE(_buf)        ( *(_buf) )
#define      NR_OF_KIDS(_buf)       ( *((_buf)+1) )
#define      KID_OFFSET(_buf,_nr)   ( *((unsigned short*)((_buf)+2+2*(_nr))) )
#define      ATTR_PTR(_buf)         ( (_buf)+2+2*NR_OF_KIDS(_buf)+1 )
#define      NR_OF_ATTR(_buf)       ( *((_buf)+2+2*NR_OF_KIDS(_buf)) )


#endif
