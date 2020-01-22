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

#include <string.h>

#include <lua.h>
#include <lauxlib.h>

#include "../../mem/shm_mem.h"
#include "../../locking.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"

#include "crc32.h"
#include "sipapi.h"
#include "sipwatch.h"
#include "compat.h"

struct siplua_watch *siplua_watch;

int sipwatch_create_object(void)
{
  siplua_watch = shm_malloc(sizeof(*siplua_watch));
  if (!siplua_watch)
    return -1;
  memset(siplua_watch, '\0', sizeof(*siplua_watch));
  if (!lock_init(&siplua_watch->lock))
    return -1;
  return 0;
}

void sipwatch_lock(void)
{
  lock_get(&siplua_watch->lock);
}

void sipwatch_unlock(void)
{
  lock_release(&siplua_watch->lock);
}

/* XXX: realloc() is not checked! */
void sipwatch_add(const char *str, int len)
{
  char *ext;

  lock_get(&siplua_watch->lock);
  ext = shm_malloc(len + 1);
  if (ext)
    {
      memcpy(ext, str, len);
      ext[len] = '\0';
      siplua_watch->ext = shm_realloc(siplua_watch->ext,
				      (siplua_watch->nb + 1) * sizeof(struct siplua_watch_ext));
      siplua_watch->ext[siplua_watch->nb].str = ext;
      siplua_watch->ext[siplua_watch->nb].crc = ssh_crc32((unsigned char *)str, len);
      ++siplua_watch->nb;
  }
  lock_release(&siplua_watch->lock);
}

void sipwatch_delete(const char *str, int len)
{
  int i;
  u_int32_t crc;

  crc = ssh_crc32((unsigned char *)str, len);
  lock_get(&siplua_watch->lock);
  for (i = 0; i < siplua_watch->nb; ++i)
    {
      if (siplua_watch->ext[i].crc == crc)
	{
	  memmove(&siplua_watch->ext[i], &siplua_watch->ext[i + 1],
		  siplua_watch->nb - i - 1);
	  siplua_watch->ext = shm_realloc(siplua_watch->ext,
					  (siplua_watch->nb - 1) * sizeof(struct siplua_watch_ext));
	  --siplua_watch->nb;
	  --i;
	}
    }
  lock_release(&siplua_watch->lock);
}

static int sipwatch_getFlagFromExtension(const char *str, int len)
{
  int i;
  u_int32_t crc;
  int flag = 0;

  crc = ssh_crc32((unsigned char *)str, len);
  lock_get(&siplua_watch->lock);
  for (i = 0; i < siplua_watch->nb; ++i)
    {
      if (siplua_watch->ext[i].crc == crc)
	{
	  flag = 1;
	  break;
	}
    }
  lock_release(&siplua_watch->lock);
  return flag;
}

static int l_sipwatch_getFlag(lua_State *L)
{
  struct sipapi_object *o;
  struct sip_uri *myuri;

  o = luaL_checkudata(L, 1, "siplua.api");
  myuri = parse_from_uri(o->msg);
  if (myuri)
    {
      if (sipwatch_getFlagFromExtension(myuri->user.s, myuri->user.len))
	{
	  lua_pushboolean(L, 1);
	  return 1;
	}
    }
  myuri = parse_to_uri(o->msg);
  if (myuri)
    {
      if (sipwatch_getFlagFromExtension(myuri->user.s, myuri->user.len))
	{
	  lua_pushboolean(L, 1);
	  return 1;
	}
    }
  lua_pushnil(L);
  return 1;
}

static int l_sipwatch_getFlagFromExtension(lua_State *L)
{
  const char *str;
  size_t len;

  str = luaL_checklstring(L, 1, &len);
  lua_pushboolean(L, sipwatch_getFlagFromExtension(str, len));
  return 1;
}

static const struct luaL_Reg siplua_watch_mylib [] =
  {
    {"watch_getFlag", l_sipwatch_getFlag},
    {"watch_getFlagFromExtension", l_sipwatch_getFlagFromExtension},
    {NULL, NULL} /* sentinel */
  };

void siplua_register_watch_cclosures(lua_State *L)
{
  lua_pushglobaltable(L);
  luaL_openlib(L, NULL, siplua_watch_mylib, 0);
  lua_remove(L, -1);
}
