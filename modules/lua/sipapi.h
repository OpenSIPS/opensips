/*
 * Copyright (c) 2008, 2009
 * 	     Eric Gouyer <folays@folays.net>
 * Copyright (c) 2008, 2009, 2010, 2011
 *	     Arnaud Chong <shine@achamo.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

struct sip_msg;

#include <lua.h>

#ifndef SIPAPI_H_
# define SIPAPI_H_

void siplua_register_api_cclosures(lua_State *L);

struct sipapi_object
{
  int finalized;
  int ref;
  struct sip_msg *msg;
};

struct sipapi_object *sipapi_create_object(lua_State *L);
void sipapi_delete_object(struct sipapi_object *o);
void sipapi_set_object(struct sipapi_object *o, struct sip_msg *msg);
int sipapi_get_object_ref(struct sipapi_object *o);

#endif /* !SIPAPI_H_ */
