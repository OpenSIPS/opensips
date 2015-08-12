#ifndef CLUSTERER_H
#define	CLUSTERER_H

#include "../../str.h"

#define INT_VALS_CLUSTER_ID_COL     0
#define INT_VALS_MACHINE_ID_COL     1
#define INT_VALS_STATE_COL          2
#define STR_VALS_DESCRIPTION_COL    0
#define STR_VALS_URL_COL            1
#define INT_VALS_CLUSTERER_ID_COL   3
#define INT_VALS_FAILED_ATTEMPTS_COL    4
#define INT_VALS_NO_TRIES_COL           5
#define INT_VALS_DURATION_COL           6

extern str clusterer_db_url;
extern str db_table;
extern str cluster_id_col;
extern str machine_id_col;
extern int server_id;
extern int persistent_state;
extern str clusterer_id_col;
extern str last_attempt_col;
extern str duration_col;
extern str failed_attempts_col;
extern str no_tries_col;

typedef struct table_entry_ table_entry_t;

struct module_list{
   str mod_name;
   int proto;
   void (*cb)(int, struct receive_info *, int);
   int timeout;
   int duration;
   int auth_check;
   int accept_cluster_id;
   struct module_list *next;
};

struct module_timestamp{
    int state;
    uint64_t timestamp;
    struct module_list *up;
    struct module_timestamp *next;
};

/* data list */
struct table_entry_ {
    /*clusterer_id*/
    int clusterer_id;
    /* machine id */
    int machine_id;
    /* cluster id */
    int cluster_id;
    /* state */
    int state;
    int in_state;
    /* dirty bit */
    int dirty_bit;
    /* description string */
    str description;
    /* path */
    str path;
    /* protocol */
    int proto;
    /* timestamp */
    uint64_t last_attempt;
    /* duration */
    int duration;
    /* previous number of tries */
    int prev_no_tries;
    /* no of tries */
    int no_tries;
    /* failed attempts */
    int failed_attempts;
    /* sock address */   
    union sockaddr_union addr;
    /* module list */
    struct module_timestamp *in_timestamps;
    /* linker in list */
    table_entry_t *next;
};

#endif	/* CLUSTERER_H */

