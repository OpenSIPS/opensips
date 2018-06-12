#ifndef __DB_ROW_H__
#define __DB_ROW_H__

#include "db_val.h"
#include "db_con.h"
#include "db_res.h"

struct db_res;

/*
 * Structure holding result of query_table function (ie. table row)
 */
typedef struct db_row {
	db_val_t* values;  /* Columns in the row */
	int n;             /* Number of columns in the row */
} db_row_t;


int convert_row(db_con_t* _h, struct db_res* _res, db_row_t* _r);
int free_row(db_row_t* _r);


#endif
