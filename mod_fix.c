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
#include "pvar.h"
#include "mod_fix.h"

/**
 * NAMING FORMAT
 * === fixup functions ===
 * + fixup_type1_type2(...)
 * - type1 - is the type the fist parameter gets converted to
 * - type2 - is the type the second parameter gets converted to
 * + if the parameter is missing, then use 'null'
 *
 * === fixup free functions ===
 * + free_fixup_type1_type2(...)
 * - type1 and type2 are same as for fixup function
 *
 * === helper functions ===
 * + functions to be used internaly for fixup/free functions
 * + fixup_type(...)
 * + fixup_free_type(...)
 * - type - is the type of the parameter that gets converted to/freed
 */


/**
 * - helper function
 * Convert char* parameter to str* parameter   
 */
int fixup_str(void** param)
{
	str* s;
	
	s = (str*)pkg_malloc(sizeof(str));
	if (!s) {
		LM_ERR("no more pkg memory\n");
		return E_UNSPEC;
	}
		
	s->s = (char*)*param;
	s->len = strlen(s->s);
	*param = (void*)s;
	
	return 0;
}

/**
 * - helper fuinction
 * free the str* parameter   
 */
int fixup_free_str(void** param)
{
	if(*param) {
		pkg_free(*param);
		*param = 0;
	}
	return 0;
}

/**
 * fixup for functions that get one parameter
 * - first paramter is converted to str*
 */
int fixup_str_null(void** param, int param_no)
{
	if(param_no != 1)
	{
		LM_ERR("invalid parameter number %d\n", param_no);
		return E_UNSPEC;
	}
	return fixup_str(param);
}

/**
 * fixup for functions that get two parameters
 * - first paramter is converted to str*
 * - second paramter is converted to str*
 */
int fixup_str_str(void** param, int param_no)
{
	if (param_no != 1 && param_no != 2 )
	{
		LM_ERR("invalid parameter number %d\n", param_no);
		return E_UNSPEC;
	}
	return fixup_str(param);
}

/**
 * fixup free for functions that get one parameter
 * - first paramter was converted to str*
 */
int fixup_free_str_null(void** param, int param_no)
{
	if(param_no != 1)
	{
		LM_ERR("invalid parameter number %d\n", param_no);
		return E_UNSPEC;
	}
	return fixup_free_str(param);
}

/**
 * fixup free for functions that get two parameters
 * - first paramter was converted to str*
 * - second paramter was converted to str*
 */
int fixup_free_str_str(void** param, int param_no)
{
	if (param_no != 1 && param_no != 2 )
	{
		LM_ERR("invalid parameter number %d\n", param_no);
		return E_UNSPEC;
	}
	return fixup_free_str(param);
}

/**
 * - helper function
 * Convert char* parameter to unsigned int
 * - the input parameter must be pkg-allocated and will be freed by function
 *   (it is how it comes from the config parser)
 */
int fixup_uint(void** param)
{
	unsigned int ui;
	str s;

	s.s = (char*)*param;
	s.len = strlen(s.s);
	if(str2int(&s, &ui)==0)
	{
		pkg_free(*param);
		*param=(void *)ui;
		return 0;
	}
	LM_ERR("bad number <%s>\n", (char *)(*param));
	return E_CFG;
}

/**
 * fixup for functions that get one parameter
 * - first paramter is converted to unsigned int
 */
int fixup_uint_null(void** param, int param_no)
{
	if(param_no != 1)
	{
		LM_ERR("invalid parameter number %d\n", param_no);
		return E_UNSPEC;
	}
	return fixup_uint(param);
}

/**
 * fixup for functions that get two parameters
 * - first paramter is converted to unsigned int
 * - second paramter is converted to unsigned int
 */
int fixup_uint_uint(void** param, int param_no)
{
	if (param_no != 1 && param_no != 2 )
	{
		LM_ERR("invalid parameter number %d\n", param_no);
		return E_UNSPEC;
	}
	return fixup_uint(param);
}

#if 0
/**
 * - helper function
 * Convert char* parameter to signed int
 * - the input parameter must be pkg-allocated and will be freed by function
 *   (it is how it comes from the config parser)
 */
int fixup_sint( void** param)
{
	int si;
	str s;

	s.s = (char*)*param;
	s.len = strlen(s.s);
	if(str2sint(&s, &si)==0)
	{
		pkg_free(*param);
		*param=(void *)si;
		return 0;
	}
	LM_ERR("bad number <%s>\n", (char *)(*param));
	return E_CFG;
}

/**
 * fixup for functions that get one parameter
 * - first paramter is converted to signed int
 */
int fixup_sint_null(void** param, int param_no)
{
	if(param_no != 1)
	{
		LM_ERR("invalid parameter number %d\n", param_no);
		return E_UNSPEC;
	}
	return fixup_sint(param);
}

/**
 * fixup for functions that get two parameters
 * - first paramter is converted to signed int
 * - second paramter is converted to signed int
 */
int fixup_sint_sint(void** param, int param_no)
{
	if (param_no != 1 && param_no != 2 )
	{
		LM_ERR("invalid parameter number %d\n", param_no);
		return E_UNSPEC;
	}
	return fixup_sint(param);
}

/**
 * fixup for functions that get two parameters
 * - first paramter is converted to signed int
 * - second paramter is converted to unsigned int
 */
int fixup_sint_uint(void** param, int param_no)
{
	if (param_no != 1 && param_no != 2 )
	{
		LM_ERR("invalid parameter number %d\n", param_no);
		return E_UNSPEC;
	}
	if (param_no == 1)
		return fixup_sint(param);
	return fixup_uint(param);
}

/**
 * fixup for functions that get two parameters
 * - first paramter is converted to unsigned int
 * - second paramter is converted to signed int
 */
int fixup_uint_sint(void** param, int param_no)
{
	if (param_no != 1 && param_no != 2 )
	{
		LM_ERR("invalid parameter number %d\n", param_no);
		return E_UNSPEC;
	}
	if (param_no == 1)
		return fixup_uint(param);
	return fixup_sint(param);
}
#endif

/******************* OLD FUNCTIONS *************************/

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


/*
 * Convert pvar string into parsed speudo variable specification
 */
int pvar_fixup(void **param, int param_no)
{
    pv_spec_t *sp;
    str s;

    if ((param_no == 1) && *param) {
	sp = (pv_spec_t*)pkg_malloc(sizeof(pv_spec_t));
	if (sp == 0) {
	    LM_ERR("no pkg memory left for parameter\n");
	    return E_UNSPEC;
	}
	s.s = (char*)*param; s.len = strlen(s.s);
	if (pv_parse_spec(&s, sp) == 0) {
	    LM_ERR("parsing of pseudo variable %s failed!\n", (char*)*param);
	    pkg_free(sp);
	    return E_UNSPEC;
	}
	if (sp->type == PVT_NULL) {
	    LM_ERR("bad pseudo variable\n");
	    pkg_free(sp);
	    return E_UNSPEC;
	}
	*param = (void*)sp;
    }

    return 0;
}

/*  
 * free pvap spec
 */
int free_pvar_fixup(void** param, int param_no)
{
    if ((param_no == 1) && *param) {
	pkg_free(*param);
	*param = 0;
    }

    return 0;
}
