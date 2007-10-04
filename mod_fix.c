/*
 *$Id: mod_fix.h 2845 2007-10-04 11:21:22Z miconda $
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <regex.h>

#include "mem/mem.h"
#include "str.h"
#include "ut.h"
#include "error.h"
#include "mod_fix.h"


/*  
 * Convert char* parameter to str* parameter   
 */
int str_fixup(void** param, int param_no)
{
	str* s;
	
	if (param_no == 1 || param_no == 2 ) {
		s = (str*)pkg_malloc(sizeof(str));
		if (!s) {
			LM_ERR("no more pkg memory\n");
			return E_UNSPEC;
		}
		
		s->s = (char*)*param;
		s->len = strlen(s->s);
		*param = (void*)s;
	}
	
	return 0;
}

/*  
 * free tje str* parameter   
 */
int free_str_fixup(void** param, int param_no)
{
	if (param_no == 1 || param_no == 2 ) {
		if(*param) {
			pkg_free(*param);
			*param = 0;
		}
	}
	
	return 0;
}


/*  
 * Convert char* parameter to int
 * - the input parameter must be pkg_allocated and will be freed by function
 */
int fixup_str2int( void** param, int param_no)
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
			LM_ERR("bad number <%s>\n", (char *)(*param));
			return E_CFG;
		}
	}
	return 0;
}


/*  
 * Convert char* parameter to regexp
 * - the input parameter must be pkg_allocated and will be freed by function
 */
int fixup_str2regexp(void** param, int param_no)
{
	regex_t* re;
	LM_DBG("fixing %s\n", (char*)(*param));

	if (param_no==1) {
		if ((re=pkg_malloc(sizeof(regex_t)))==0) {
			LM_ERR("no more pkg memory\n");
			return E_OUT_OF_MEM;
		}
		if (regcomp(re, *param, REG_EXTENDED|REG_ICASE|REG_NEWLINE) ) {
			pkg_free(re);
			LM_ERR("bad re %s\n", (char*)*param);
			return E_BAD_RE;
		}
		/* free string */
		pkg_free(*param);
		/* replace it with the compiled re */
		*param=re;
	}
	return 0;
}

int free_fixup_str2regexp(void** param, int param_no)
{
	if (param_no==1) {
		if(*param)
		{
			regfree((regex_t*)(*param));
			pkg_free(*param);
			*param = 0;
		}
	}
	return 0;
}

