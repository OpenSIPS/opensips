#ifndef _FOOBAR_DB_H_
#define _FOOBAR_DB_H_

#include "../../db/db.h"
#include "../../str.h"

int smpp_db_bind(const str *db_url);
int smpp_db_init(const str *db_url);
int smpp_query(const str *smpp_table, db_key_t *cols, int col_nr, db_res_t **res);
void smpp_free_results(db_res_t *res);
void smpp_db_close(void);

#endif
