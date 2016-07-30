/*
 * mangler module
 *
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
 *  2003-04-07 first version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>

#include "sdp_mangler.h"
#include "ip_helper.h"
#include "utils.h"
#include "common.h"
#include "../../mem/mem.h"
#include "../../data_lump.h"
#include "../../parser/hf.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_uri.h"
#include "../../parser/contact/parse_contact.h"
#include "../../ut.h"
#include "../../parser/msg_parser.h"	/* struct sip_msg */

//#define DEBUG 1

int
sdp_mangle_port (struct sip_msg *msg, char *offset, char *unused)
{
	int old_content_length, new_content_length, oldlen, err, oldPort, newPort,
		diff, offsetValue,len,off,ret,need_to_deallocate;
	struct lump *l;
	regmatch_t pmatch;
	regex_t *re;
	char *s, *pos,*begin,*key;
	char buf[6];
	str body;


	key = PORT_REGEX;
	/*
	 * Checking if msg has a payload
	 */
	if (msg == NULL)
	{
		LM_ERR("received NULL msg\n");
		return -1;
	}

	if ( get_body(msg,&body)!=0 || body.len==0)
	{
		LM_ERR(" failed to get a body \n");
		return -2;
	}

	old_content_length = get_content_length(msg);

	if (offset == NULL)
		return -14;
	if (sscanf (offset, "%d", &offsetValue) != 1)
	{
		LM_ERR("invalid value for offset \n");
		return -13;
	}

	//offsetValue = (int)offset;
#ifdef DEBUG
	fprintf (stdout,"---START--------MANGLE PORT-----------------\n");
	fprintf(stdout,"===============OFFSET = %d\n",offsetValue);
#endif

	if ((offsetValue < MIN_OFFSET_VALUE) || (offsetValue > MAX_OFFSET_VALUE))
	{
		LM_ERR("invalid value %d for offset \n",offsetValue);
		return -3;
	}

	begin = body.s;
	ret = -1;

	/* try to use pre-compiled expressions */
	need_to_deallocate = 0;
	if (portExpression != NULL)
		{
		re = portExpression;
#ifdef DEBUG
		fprintf(stdout,"Using PRECOMPILED expression for port ...\n");
#endif
		}
		else /* we are not using pre-compiled expressions */
			{
			re = pkg_malloc(sizeof(regex_t));
			if (re == NULL)
				{
				LM_ERR("unable to allocate re\n");
				return -4;
				}
			need_to_deallocate = 1;
			if ((regcomp (re, key, REG_EXTENDED)) != 0)
				{
				LM_ERR("unable to compile %s \n",key);
				return -5;
				}
#ifdef DEBUG
		fprintf(stdout,"Using ALLOCATED expression for port ...\n");
#endif

			}

	diff = 0;
	while ((begin < msg->buf + msg->len) && (regexec (re, begin, 1, &pmatch, 0) == 0))
	{
		off = begin - msg->buf;
		if (pmatch.rm_so == -1)
		{
			LM_ERR("offset unknown\n");
			return -6;
		}

#ifdef STRICT_CHECK
		pmatch.rm_eo --; /* return with one space */
#endif

		/*
                for BSD and Solaris we avoid memrchr
                pos = (char *) memrchr (begin + pmatch.rm_so, ' ',pmatch.rm_eo - pmatch.rm_so);
                */
                pos = begin+pmatch.rm_eo;
#ifdef DEBUG
                printf("begin=%c pos=%c rm_so=%d rm_eo=%d\n",*begin,*pos,pmatch.rm_so,pmatch.rm_eo);
#endif
                do pos--; while (*pos != ' '); /* we should find ' ' because we matched m=audio port */

		pos++;		/* jumping over space */
		oldlen = (pmatch.rm_eo - pmatch.rm_so) - (pos - (begin + pmatch.rm_so));	/* port length */

		/* convert port to int */
		oldPort = str2s (pos, oldlen, &err);
#ifdef DEBUG
                printf("port to convert [%.*s] to int\n",oldlen,pos);
#endif
		if (err)
			{
			LM_ERR("failed to convert [%.*s] to int\n",oldlen,pos);
#ifdef STRICT_CHECK
			return -7;
#else
			goto continue1;
#endif
			}
		if ((oldPort < MIN_ORIGINAL_PORT) || (oldPort > MAX_ORIGINAL_PORT))	/* we silently fail,we ignore this match or return -11 */
		{
#ifdef DEBUG
                printf("WARNING: sdp_mangle_port: Silent fail for not matching old port %d\n",oldPort);
#endif

			LM_WARN("silent fail for not matching old port %d\n",oldPort);
#ifdef STRICT_CHECK
			return -8;
#else
			goto continue1;
#endif
		}
                if ((offset[0] != '+')&&(offset[0] != '-')) newPort = offsetValue;//fix value
		else newPort = oldPort + offsetValue;
		/* new port is between 1 and 65536, or so should be */
		if ((newPort < MIN_MANGLED_PORT) || (newPort > MAX_MANGLED_PORT))	/* we silently fail,we ignore this match */
		{
#ifdef DEBUG
                printf("WARNING: sdp_mangle_port: Silent fail for not matching new port %d\n",newPort);
#endif

			LM_WARN("silent fail for not matching new port %d\n",newPort);
#ifdef STRICT_CHECK
			return -9;
#else
			goto continue1;
#endif
		}

#ifdef DEBUG
		fprintf(stdout,"Extracted port is %d and mangling to %d\n",oldPort,newPort);
#endif

		/*
		len = 1;
		while ((newPort = (newPort / 10)) != 0)	len++;
		newPort = oldPort + offsetValue;
		*/
		if (newPort >= 10000) len = 5;
			else
				if (newPort >= 1000) len = 4;
					else
						if (newPort >= 100) len = 3;
							else
								if (newPort >= 10) len = 2;
									else len = 1;

		/* replaced five div's + 1 add with most probably 1 comparison or 2 */

		/* deleting old port */
		if ((l = del_lump (msg, pmatch.rm_so + off +
						(pos -(begin + pmatch.rm_so)),oldlen, 0)) == 0)
		{
			LM_ERR("del_lump failed\n");
			return -10;
		}
		s = pkg_malloc (len);
		if (s == 0)
		{
			LM_ERR("no more pkg memory\n");
			return -11;
		}
		snprintf (buf, len + 1, "%u", newPort);	/* converting to string */
		memcpy (s, buf, len);

		if (insert_new_lump_after (l, s, len, 0) == 0)
		{
			LM_ERR("could not insert new lump\n");
			pkg_free (s);
			return -12;
		}
		diff = diff + len /*new length */  - oldlen;
		/* new cycle */
		ret++;
#ifndef STRICT_CHECK
continue1:
#endif
		begin = begin + pmatch.rm_eo;

	}			/* while  */
	if (need_to_deallocate)
		{
		regfree (re);
		pkg_free(re);
#ifdef DEBUG
		fprintf(stdout,"Deallocating expression for port ...\n");
#endif
		}

	if (diff != 0)
	{
		new_content_length = old_content_length + diff;
		patch_content_length (msg, new_content_length);
	}

#ifdef DEBUG
	fprintf (stdout,"---END--------MANGLE PORT-----------------\n");
#endif

	return ret+2;
}


int
sdp_mangle_ip (struct sip_msg *msg, char *oldip, char *newip)
{
	int i, old_content_length, new_content_length;
	int diff, oldlen, len, off, ret, need_to_deallocate;
	unsigned int mask, address, locatedIp;
	struct lump *l;
	regmatch_t pmatch;
	regex_t *re;
	char *s, *pos, *begin, *key;
	char buffer[16];	/* 123.456.789.123\0 */
	str body;

#ifdef DEBUG
	fprintf (stdout,"---START--------MANGLE IP-----------------\n");
#endif


	key = IP_REGEX;

	/*
	 * Checking if msg has a payload
	 */
	if (msg == NULL)
	{
		LM_ERR("msg null\n");
		return -1;
	}

	if ( get_body(msg,&body)!=0 || body.len==0)
	{
		LM_ERR(" failed to get a body \n");
		return -2;
	}

	old_content_length = get_content_length(msg);

	/* checking oldip */
	if (oldip == NULL)
		{
		LM_ERR("received NULL for oldip\n");
		return -3;
		}
	/* checking newip */
	if (newip == NULL)
		{
		LM_ERR("received NULL for newip\n");
		return -4;
		}
	i = parse_ip_netmask (oldip, &pos, &mask);

	if (i == -1)
	{
		/* invalid value for the netmask specified in oldip */
		LM_ERR("invalid value for the netmask specified in oldip\n");
		return -5;
	}
	else
	{
		i = parse_ip_address (pos, &address);
		if (pos != NULL) free (pos);
		if (i == 0)
			{
			LM_ERR("invalid value for the ip specified in oldip\n");
			return -6;	/* parse error in ip */
			}
	}

	/* now we have in address/netmask binary values */

	begin = body.s;
	ret = -1;
	len = strlen (newip);

	/* try to use pre-compiled expressions */
	need_to_deallocate = 0;
	if (ipExpression != NULL)
		{
		re = ipExpression;
#ifdef DEBUG
		fprintf(stdout,"Using PRECOMPILED expression for ip ...\n");
#endif

		}
		else /* we are not using pre-compiled expressions */
			{
			re = pkg_malloc(sizeof(regex_t));
			if (re == NULL)
				{
				LM_ERR("unable to allocate re in pkg mem\n");
				return -7;
				}
			need_to_deallocate = 1;
			if ((regcomp (re, key, REG_EXTENDED)) != 0)
				{
				LM_ERR("unable to compile %s \n",key);
				return -8;
				}
#ifdef DEBUG
		fprintf(stdout,"Using ALLOCATED expression for ip ...\n");
#endif
			}

	diff = 0;
	while ((begin < msg->buf + msg->len) && (regexec (re, begin, 1, &pmatch, 0) == 0))
	{
		off = begin - msg->buf;
		if (pmatch.rm_so == -1)
		{
			LM_ERR("offset unknown\n");
			return -9;
		}

#ifdef STRICT_CHECK
		pmatch.rm_eo --; /* return with one space,\n,\r */
#endif

		/*
                for BSD and Solaris we avoid memrchr
                pos = (char *) memrchr (begin + pmatch.rm_so, ' ',pmatch.rm_eo - pmatch.rm_so);
                */
                pos = begin+pmatch.rm_eo;
                do pos--; while (*pos != ' '); /* we should find ' ' because we matched c=IN IP4 ip */

		pos++;		/* jumping over space */
		oldlen = (pmatch.rm_eo - pmatch.rm_so) - (pos - (begin + pmatch.rm_so));	/* ip length */
		if (oldlen > 15)
		{
			LM_WARN("silent fail because oldlen > 15\n");
#ifdef STRICT_CHECK
			return -10;
#else
			goto continue2;	/* silent fail return -10; invalid ip format ,probably like 1000.3.12341.2 */
#endif


		}
		buffer[0] = '\0';
		strncat ((char *) buffer, pos, oldlen);
		buffer[oldlen] = '\0';
		i = parse_ip_address (buffer, &locatedIp);
		if (i == 0)
		{
			LM_WARN("silent fail on parsing matched address \n");

#ifdef STRICT_CHECK
			return -11;
#else
			goto continue2;
#endif
		}
		if (same_net (locatedIp, address, mask) == 0)
		{
			LM_WARN("silent fail because matched address is not in network\n");
#ifdef DEBUG
		fprintf(stdout,"Extracted ip is %s and not mangling \n",buffer);
#endif
			goto continue2;	/* not in the same net, skipping */
		}
#ifdef DEBUG
		fprintf(stdout,"Extracted ip is %s and mangling to %s\n",buffer,newip);
#endif


		/* replacing ip */

		/* deleting old ip */
		if ((l = del_lump (msg,pmatch.rm_so + off +
						(pos - (begin + pmatch.rm_so)),oldlen, 0)) == 0)
		{
			LM_ERR("del_lump failed\n");
			return -12;
		}
		s = pkg_malloc (len);
		if (s == 0)
		{
			LM_ERR("no more pkg mem\n");
			return -13;
		}
		memcpy (s, newip, len);

		if (insert_new_lump_after (l, s, len, 0) == 0)
		{
			LM_ERR("could not insert new lump\n");
			pkg_free (s);
			return -14;
		}
		diff = diff + len /*new length */  - oldlen;
		/* new cycle */
		ret++;
continue2:
		begin = begin + pmatch.rm_eo;

	}			/* while */
	if (need_to_deallocate)
	{
		regfree (re);		/* if I am going to use pre-compiled expressions to be removed */
		pkg_free(re);
#ifdef DEBUG
		fprintf(stdout,"Deallocating expression for ip ...\n");
#endif
	}

	if (diff != 0)
	{
		new_content_length = old_content_length + diff;
		patch_content_length (msg, new_content_length);
	}

#ifdef DEBUG
	fprintf (stdout,"---END--------MANGLE IP-----------------\n");
#endif

	return ret+2;

}

int compile_expresions(char *port,char *ip)
{
	portExpression = NULL;
	portExpression = pkg_malloc(sizeof(regex_t));
	if (portExpression != NULL)
		{
		if ((regcomp (portExpression,port, REG_EXTENDED)) != 0)
			{
			LM_ERR("unable to compile portExpression [%s]\n",port);
			pkg_free(portExpression);
			portExpression = NULL;
			}
		}
	else
		{
			LM_ERR("unable to alloc portExpression in pkg mem\n");
		}

	ipExpression = NULL;
	ipExpression = pkg_malloc(sizeof(regex_t));
	if (ipExpression != NULL)
		{
		if ((regcomp (ipExpression,ip, REG_EXTENDED)) != 0)
			{
			LM_ERR("unable to compile ipExpression [%s]\n",ip);
			pkg_free(ipExpression);
			ipExpression = NULL;
			}
		}
	else
		{
			LM_ERR("unable to alloc ipExpression in pkg mem\n");
		}

	return 0;
}

int free_compiled_expresions(void)
{
	if (portExpression != NULL)
		{
		regfree(portExpression);
		pkg_free(portExpression);
		portExpression = NULL;
		}
	if (ipExpression != NULL)
		{
		regfree(ipExpression);
		pkg_free(ipExpression);
		ipExpression = NULL;
		}
	return 0;
}

