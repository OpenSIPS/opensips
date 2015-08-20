/*
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 * 2003-02-28 scratchpad compatibility abandoned (jiri)
 * 2003-01-22 zero-termination in CSeq eliminated (jiri)
 */


#include "../dprint.h"
#include "parse_cseq.h"
#include "parser_f.h"  /* eat_space_end and so on */
#include "parse_def.h"
#include "parse_methods.h"
#include "../mem/mem.h"

/*
 * Parse CSeq header field
 */

char* parse_cseq(char *buf, char* end, struct cseq_body* cb)
{
	char *t, *m, *m_end;

	cb->error=PARSE_ERROR;
	t=buf;

	cb->number.s=t;
	t=eat_token_end(t, end);
	if (t>=end) goto error;
	cb->number.len=t-cb->number.s;

	m=eat_space_end(t, end);
	m_end=eat_token_end(m, end);

	if (m_end>=end) {
			LM_ERR("method terminated unexpectedly\n");
			goto error;
	}
	if (m_end==m){
		/* null method*/
		LM_ERR("no method found\n");
		goto error;
	}
	cb->method.s=m;
	t=m_end;
	cb->method.len=t-cb->method.s;

	/* cache the method id */
	if(parse_method(cb->method.s, t, (unsigned int*)&cb->method_id)==0)
	{
		LM_ERR("cannot parse the method\n");
		goto error;
	}

	/* there may be trailing LWS
	 * (it was not my idea to put it in SIP; -jiri )
	 */
	t=eat_lws_end(t, end);
	/*check if the header ends here*/
	if (t>=end) {
		LM_ERR("strange EoHF\n");
		goto error;
	}
	if (*t=='\r' && t+1<end && *(t+1)=='\n') {
			cb->error=PARSE_OK;
			return t+2;
	}
	if (*t=='\n') {
			cb->error=PARSE_OK;
			return t+1;
	}
	LM_ERR("expecting CSeq EoL\n");

error:
	LM_ERR("bad cseq\n");
	return t;
}


void free_cseq(struct cseq_body* cb)
{
	pkg_free(cb);
}
