/*
 * XMPP Module
 * This file is part of opensips, a free SIP server.
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 * Author: Andreea Spirea
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "xmpp.h"
#include "../../parser/parse_uri.h"
/*
 sip_uri:  sip:user@xmpp_domain ->
 xmpp_uri: user@sip_domain
 ( it is assumed that the domain in sip = xmpp_domain, only then
 the sip_domain parameter has utility )
*/
char* uri_sip2xmpp(str* uri)
{
	static char buf[256];
	struct sip_uri suri;
	int len;

	if(parse_uri(uri->s, uri->len, &suri) < 0)
	{
		LM_ERR("Failed to parse SIP uri\n");
		return 0;
	}

	if(sip_domain.s)
	{
		len = sprintf(buf, "%.*s@%s", suri.user.len, suri.user.s, sip_domain.s);
		if(suri.user.len + 2 + sip_domain.len > 256)
		{
			LM_ERR("Buffer overflow\n");
			return 0;
		}
	}
	else
	{
		if(uri->len > 256)
		{
			LM_ERR("Buffer overflow\n");
			return 0;
		}

		len = sprintf(buf, "%.*s@%.*s", suri.user.len, suri.user.s, suri.host.len, suri.host.s);
	}

	buf[len] = '\0';
	return buf;
}

/*
   xmpp uri: user@sip_domain/resource ->
   sip_uri: sip:user@xmpp_domain
*/
char* uri_xmpp2sip(char* uri, int* len)
{
	static char buf[256];
	char* arond, *slash;
	str user;

	if(sip_domain.s == 0)
	{
		user.s = uri;
		slash = strchr(uri, '/');
		if(slash)
		{
			user.len = slash - uri;
		}
		else
			user.len = strlen(uri);

		if(5 + user.len > 256)
		{
			LM_ERR("Buffer overflow\n");
			return 0;
		}

		*len = sprintf(buf, "sip:%.*s", user.len, user.s);
		buf[*len] = '\0';
		return buf;
	}

	arond = strchr(uri, '@');
	if(arond == NULL)
	{
		LM_ERR("Bad formatted uri %s\n", uri);
		return 0;
	}
	slash = strchr(uri, '/');
	if(slash && slash < arond)
	{
		LM_ERR("Bad formatted uri %s\n", uri);
		return 0;
	}
	user.s = uri;
	user.len = arond - uri;

	if(6 + user.len + strlen(xmpp_domain) > 256)
	{
		LM_ERR("Buffer overflow\n");
		return 0;
	}

	*len = sprintf(buf, "sip:%.*s@%s", user.len, user.s, xmpp_domain);
	buf[*len] = '\0';
	return buf;
}

char *extract_domain(char *jid)
{
	char *p;

	if ((p = strchr(jid, '/')))
		*p = 0;
	if ((p = strchr(jid, '@'))) {
		*p++ = 0;
		return p;
	}
	return p;
}

char *random_secret(void)
{
	static char secret[41];
	int i, r;

        for (i = 0; i < 40; i++) {
            r = (int) (36.0 * rand() / RAND_MAX);
            secret[i] = (r >= 0 && r <= 9) ? (r + 48) : (r + 87);
        }
        secret[40] = '\0';

	return secret;
}

char *db_key(char *secret, char *domain, char *id)
{
	char buf[1024];
	char *hash;

	snprintf(buf, sizeof(buf), "%s", secret);
	hash = shahash(buf);

	snprintf(buf, sizeof(buf), "%s%s", hash, domain);
	hash = shahash(buf);

	snprintf(buf, sizeof(buf), "%s%s", hash, id);
	hash = shahash(buf);
	return hash;
}

