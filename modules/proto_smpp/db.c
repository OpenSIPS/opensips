#include "../../db/db.h"
#include "../../str.h"
#include "db.h"

static db_con_t* smpp_db_handle;
static db_func_t smpp_dbf;

int smpp_db_bind(const str *db_url)
{
	if (db_bind_mod(db_url, &smpp_dbf)) {
		LM_ERR("cannot bind module database\n");
		return -1;
	}
	return 0;
}

int smpp_db_init(const str *db_url)
{
	if (smpp_dbf.init == 0) {
		LM_ERR("unbound database module\n");
		return -1;
	}
	smpp_db_handle = smpp_dbf.init(db_url);
	if (smpp_db_handle == 0){
		LM_ERR("cannot initialize database connection\n");
		return -1;
	}
	return 0;
}

int smpp_query(const str *smpp_table, db_key_t *cols, int col_nr, db_res_t **res)
{
	if (smpp_dbf.use_table(smpp_db_handle, smpp_table) < 0) {
		LM_ERR("error while trying to use smpp table\n");
		return -1;
	}

	if (smpp_dbf.query(smpp_db_handle, NULL, 0, NULL, cols, 0, col_nr, 0, res) < 0) {
		LM_ERR("error while querying database\n");
		return -1;
	}

	return 0;
}

void smpp_free_results(db_res_t *res)
{
	smpp_dbf.free_result(smpp_db_handle, res);
}

void smpp_db_close(void)
{
	if (smpp_db_handle && smpp_dbf.close) {
		smpp_dbf.close(smpp_db_handle);
		smpp_db_handle = 0;
	}
}
