/*
 *
 * Copyright (c) 2007, 2008, 2009
 * 	     Eric Gouyer <folays@folays.net>
 * Copyright (c) 2007, 2008, 2009, 2010, 2011
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

#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <memcache.h>

#include "../../mem/mem.h"

#include "sipluafunc.h"

struct sipmemcache
{
  int finalized;
  struct memcache *mc;
  struct memcache_req *req;
  struct memcache_res **res;
};

/* Ouhla dis-donc, c'est dangereux ca! */
static struct sipmemcache *coin;

static int32_t sipmemcache_error(MCM_ERR_FUNC_ARGS)
{
  struct memcache_err_ctxt *err = MCM_ERR_FUNC_ERR_CTXT;

  err->cont = 'y';
  coin->finalized = 1;
  return 0;
}

static int l_sipmemcache_new(lua_State *L)
{
  struct sipmemcache *o;

  o = lua_newuserdata(L, sizeof(*o));
  memset(o, '\0', sizeof(*o));
  luaL_getmetatable(L, "siplua.memcache");
  lua_setmetatable(L, -2);
  o->mc = mc_new();
  if (!o->mc)
    {
      lua_remove(L, -1);
      lua_pushnil(L);
    }
  mcErrSetup(sipmemcache_error);
  coin = o;
  return 1;
}

static int l_sipmemcache_server_add(lua_State *L)
{
  struct sipmemcache *o;
  const char *host;
  const char *port;
  int ret;

  o = luaL_checkudata(L, 1, "siplua.memcache");
  host = luaL_checkstring(L, 2);
  port = luaL_checkstring(L, 3);
  if (o->finalized || !o->mc)
    {
      lua_pushnil(L);
    }
  else
    {
      ret = mc_server_add(o->mc, host, port);
      if (ret)
	lua_pushboolean(L, 0);
      else
	lua_pushboolean(L, 1);
    }
  return 1;
}

static int sipmemcache_storage_cmds(lua_State *L,
				    int (*f)(struct memcache *mc,
					     char *key, const size_t key_len,
					     const void *val, const size_t bytes,
					     const time_t expire, const u_int16_t flags))
{
  struct sipmemcache *o;
  const char *key, *val;
  size_t keylen, bytes;
  int ret;
  int expire;

  o = luaL_checkudata(L, 1, "siplua.memcache");
  key = luaL_checklstring(L, 2, &keylen);
  val = luaL_checklstring(L, 3, &bytes);
  expire = luaL_optinteger(L, 4, 3600);
  if (o->finalized || !o->mc)
    {
      lua_pushnil(L);
    }
  else
    {
      int flags = 0;
      ret = f(o->mc, (char *)key, keylen, val, bytes, expire, flags);
      lua_pushinteger(L, ret);
    }
  return 1;
}

static int l_sipmemcache_add(lua_State *L)
{
  return sipmemcache_storage_cmds(L, mc_add);
}

static int l_sipmemcache_replace(lua_State *L)
{
  return sipmemcache_storage_cmds(L, mc_replace);
}

static int l_sipmemcache_set(lua_State *L)
{
  return sipmemcache_storage_cmds(L, mc_set);
}

static int sipmemcache_atomic_opts(lua_State *L, u_int32_t (*f)(struct memcache *mc,
								char *key, const size_t key_len,
								const u_int32_t val))
{
  struct sipmemcache *o;
  const char *key;
  size_t keylen;
  int nb;
  
  o = luaL_checkudata(L, 1, "siplua.memcache");
  key = luaL_checklstring(L, 2, &keylen);
  nb = luaL_checkinteger(L, 3);
  if (o->finalized || !o->mc)
    {
      lua_pushnil(L);
    }
  else
    {
      nb = f(o->mc, (char *)key, keylen, nb);
      lua_pushinteger(L, nb);
    }
  return 1;
}

static int l_sipmemcache_incr(lua_State *L)
{
  return sipmemcache_atomic_opts(L, mc_incr);
}

static int l_sipmemcache_decr(lua_State *L)
{
  return sipmemcache_atomic_opts(L, mc_decr);
}

static int l_sipmemcache_delete(lua_State *L)
{
  struct sipmemcache *o;
  const char *key;
  size_t keylen;
  int ret;
  
  o = luaL_checkudata(L, 1, "siplua.memcache");
  key = luaL_checklstring(L, 2, &keylen);
  if (o->finalized || !o->mc)
    {
      lua_pushnil(L);
    }
  else
    {
      int hold_timer = 0;
      ret = mc_delete(o->mc, (char *)key, keylen, hold_timer);
      lua_pushinteger(L, ret);
    }
  return 1;
}

static int l_sipmemcache_get(lua_State *L)
{
  struct sipmemcache *o;
  const char *key;
  size_t keylen;
  void *blah;
  size_t retlen;
  
  o = luaL_checkudata(L, 1, "siplua.memcache");
  key = luaL_checklstring(L, 2, &keylen);
  if (o->finalized || !o->mc)
    {
      lua_pushnil(L);
    }
  else
    {
      blah = mc_aget2(o->mc, (char *)key, keylen, &retlen);
      if (retlen && blah)
	{
	  lua_pushlstring(L, blah, retlen);
	  free(blah);
	}
      else
	lua_pushnil(L);
    }
  return 1;
}

static void sipmemcache_close(lua_State *L)
{
  struct sipmemcache *o;

  o = luaL_checkudata(L, 1, "siplua.memcache");
  if (!o->finalized && o->mc)
    {
      if (o->res)
	{
	  pkg_free(o->res);
	  o->res = NULL;
	}
      if (o->req)
	{
	  mc_req_free(o->req);
	  o->req = NULL;
	}
      mc_free(o->mc);
      o->mc = NULL;
      o->finalized = 1;
    }
}

int l_sipmemcache_close(lua_State *L)
{
  sipmemcache_close(L);
  return 0;
}

int l_sipmemcache___gc(lua_State *L)
{
  sipmemcache_close(L);
  return 0;
}

int l_sipmemcache___index(lua_State *L)
{
  luaL_checkudata(L, 1, "siplua.memcache");
  lua_getmetatable(L, 1);
  luaL_checkstring(L, 2);
  lua_pushvalue(L, 2);
  lua_rawget(L, -2);
  lua_remove(L, -2);
  return 1;
}

int l_sipmemcache_multi_get(lua_State *L)
{
  struct sipmemcache *o;
  const char *key;
  size_t key_len;
  int i, n;

  o = luaL_checkudata(L, 1, "siplua.memcache");
  if (o->finalized || !o->mc)
    {
      lua_pushnil(L);
      return 1;
    }
  n = lua_gettop(L);
  lua_newtable(L);
  if (n < 2)
    return 1;
  o->req = mc_req_new();
  o->res = pkg_malloc((n - 1) * sizeof(struct memcache_res *));
  for (i = 0; i < n - 1; ++i)
    {
      key = luaL_checklstring(L, i + 2, &key_len);
      o->res[i] = mc_req_add(o->req, (char *)key, key_len);
/*       o->res[i]->size = 1024; */
/*       o->res[i]->val = malloc(o->res[i]->size); */
/*       mc_res_free_on_delete(o->res[i], 1); */
    }
  mc_get(o->mc, o->req);
  for (i = 0; i < n - 1; ++i)
    {
      if (o->res[i]->bytes)
	{
	  lua_pushvalue(L, i + 2);
	  lua_pushlstring(L, o->res[i]->val, o->res[i]->bytes);
	  lua_rawset(L, -3);
	}
/*       mc_res_free(o->req, o->res[i]); */
    }
  pkg_free(o->res);
  o->res = NULL;
  mc_req_free(o->req);
  o->req = NULL;
  return 1;
}

static const struct luaL_reg siplua_memcache_mylib [] =
  {
    {"server_add", l_sipmemcache_server_add},
    {"add", l_sipmemcache_add},
    {"replace", l_sipmemcache_replace},
    {"set", l_sipmemcache_set},
    {"get", l_sipmemcache_get},
    {"delete", l_sipmemcache_delete},
    {"incr", l_sipmemcache_incr},
    {"decr", l_sipmemcache_decr},
    {"close", l_sipmemcache_close},
    {"multi_get", l_sipmemcache_multi_get},
    {NULL, NULL} /* sentinel */
  };

void siplua_register_memcache_cclosures(lua_State *L)
{
  luaL_newmetatable(L, "siplua.memcache");
  luaL_openlib(L, NULL, siplua_memcache_mylib, 0);
  lua_pushstring(L, "__gc");
  lua_pushcclosure(L, l_sipmemcache___gc, 0);
  lua_rawset(L, -3);
  lua_pushstring(L, "__index");
  lua_pushcclosure(L, l_sipmemcache___index, 0);
  lua_rawset(L, -3);
  lua_remove(L, -1);
  lua_pushcclosure(L, l_sipmemcache_new, 0);
  lua_setglobal(L, "mc_new");
}
