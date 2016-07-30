/*
 * Copyright (c) 2009
 * 	     Eric Gouyer <folays@folays.net>
 * Copyright (c) 2009, 2010, 2011
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

#include <lua.h>
#include <lauxlib.h>

#include "../../locking.h"

#ifndef SIPWATCH_H_
# define SIPWATCH_H_

struct siplua_watch_ext;

struct siplua_watch
{
  gen_lock_t lock;
  struct siplua_watch_ext *ext;
  int nb;
};

struct siplua_watch_ext
{
  char *str;
  u_int32_t crc;
};

extern struct siplua_watch *siplua_watch;

int sipwatch_create_object(void);

void siplua_register_watch_cclosures(lua_State *L);

void sipwatch_lock(void);
void sipwatch_unlock(void);

void sipwatch_add(const char *s, int len);
void sipwatch_delete(const char *s, int len);

#endif /* !SIPWATCH_H_ */
