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

extern str db_url;
extern str db_table;
extern str cluster_id_col;
extern str machine_id_col;
extern int server_id;

enum machine_state {
    UP,
    DOWN
};

typedef struct table_entry_ table_entry_t;
/* list of clusters */
struct table_entry_ {
	/* machine id */
	int machine_id;
	/* cluster id */
	int cluster_id;
	/* state */
        int state;
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

