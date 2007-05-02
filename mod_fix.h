/*
 *$Id$
 *
 */


#ifndef _modfix_h
#define _modfix_h

#include "mem/mem.h"
#include "str.h"
#include "ut.h"
#include "error.h"


/*  
 * Convert char* parameter to str* parameter   
 */
static inline int str_fixup(void** param, int param_no)
{
	str* s;
	
	if (param_no == 1 || param_no == 2 ) {
		s = (str*)pkg_malloc(sizeof(str));
		if (!s) {
			LOG(L_ERR, "str_fixup(): No memory left\n");
			return E_UNSPEC;
		}
		
		s->s = (char*)*param;
		s->len = strlen(s->s);
		*param = (void*)s;
	}
	
	return 0;
}

/*  
 * Convert char* parameter to int parameter
 */
static inline int fixup_str2int( void** param, int param_no)
{
	unsigned long go_to;
	int err;

	if (param_no==1) {
		go_to=str2s(*param, strlen(*param), &err );
		if (err==0) {
			pkg_free(*param);
			*param=(void *)go_to;
			return 0;
		} else {
			LOG(L_ERR, "ERROR:fixup_str2int: bad number <%s>\n",
				(char *)(*param));
			return E_CFG;
		}
	}
	return 0;
}

#endif
