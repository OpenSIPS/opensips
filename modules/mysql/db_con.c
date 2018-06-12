#include "db_con.h"
#include "defs.h"
#include "../../mem.h"
#include "../../dprint.h"
#include <string.h>


int use_table(db_con_t* _h, const char* _t)
{
	char* ptr;
	int l;
#ifdef PARANOID
	if ((!_h) || (!_t)) {
		log(L_ERR, "use_table(): Invalid parameter value\n");
		return FALSE;
	}
#endif
	l = strlen(_t) + 1;
	ptr = (char*)pkg_malloc(l);
	if (!ptr) {
		log(L_ERR, "use_table(): No memory left\n");
		return FALSE;
	}
	memcpy(ptr, _t, l);

	if (CON_TABLE(_h)) free(CON_TABLE(_h));
	CON_TABLE(_h) = ptr;
	return TRUE;
}


