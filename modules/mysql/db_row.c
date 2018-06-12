#include "db_row.h"
#include "defs.h"
#include <mysql/mysql.h>
#include "../../mem.h"
#include "../../dprint.h"


int convert_row(db_con_t* _h, db_res_t* _res, db_row_t* _r)
{
	int i;
#ifndef PARANOID
	if ((!_h) || (!_r) || (!_n)) {
		log(L_ERR, "convert_row(): Invalid parameter value\n");
		return FALSE;
	}
#endif

        ROW_VALUES(_r) = (db_val_t*)pkg_malloc(sizeof(db_val_t) * RES_COL_N(_res));
	ROW_N(_r) = RES_COL_N(_res);
	if (!ROW_VALUES(_r)) {
		log(L_ERR, "convert_row(): No memory left\n");
		return FALSE;
	}

	for(i = 0; i < RES_COL_N(_res); i++) {
		if (str2val(RES_TYPES(_res)[i], &(ROW_VALUES(_r)[i]), CON_ROW(_h)[i]) == FALSE) {
			log(L_ERR, "convert_row(): Error while converting value\n");
			free_row(_r);
			return FALSE;
		}
	}
	return TRUE;
}


int free_row(db_row_t* _r)
{
#ifndef PARANOID
	if (!_r) {
		log(L_ERR, "free_row(): Invalid parameter value\n");
		return FALSE;
	}
#endif
	pkg_free(ROW_VALUES(_r));
	return TRUE;
}

