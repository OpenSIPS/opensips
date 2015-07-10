/* 
 * File:   clusterer.h
 * Author: cristi
 *
 * Created on July 7, 2015, 3:40 PM
 */

#ifndef CLUSTERER_H
#define	CLUSTERER_H

#include "../../str.h"

#define INT_VALS_CLUSTER_ID_COL     0
#define INT_VALS_MACHINE_ID_COL     1
#define INT_VALS_STATE_COL          2
#define STR_VALS_DESCRIPTION_COL    0
#define STR_VALS_URL_COL            1
#define INT_VALS_CLUSTERER_ID_COL   3

extern str db_url;
extern str db_table;
extern str cluster_id_col;
extern str machine_id_col;
extern int server_id;
extern int persistent_state;
extern str clusterer_id_col;

typedef struct table_entry_ table_entry_t;

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
    /* dirty bit */
    int dirty_bit;
    /* description string */
    str description;
    /* protocol user */
    str proto;
    /* path */
    str path;
    /* linker in list */
    table_entry_t *next;
};

#endif	/* CLUSTERER_H */

