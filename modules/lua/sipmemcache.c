/*
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
#include <netinet/in.h>
#include <libmemcached/memcached.h>

#include "../../mem/mem.h"
#include "../../ut.h"

#include "sipluafunc.h"
#include "compat.h"

#if !defined(LIBMEMCACHED_VERSION_HEX) || LIBMEMCACHED_VERSION_HEX < 0x00037000
typedef memcached_return memcached_return_t;
#endif

struct sipmemcache
{
  int finalized;
  memcached_st memc;
  const char **keys;
  size_t *keyslen;
};

static int l_sipmemcache_new(lua_State *L)
{
  struct sipmemcache *o;

  o = lua_newuserdata(L, sizeof(*o));
  memset(o, '\0', sizeof(*o));
  luaL_getmetatable(L, "siplua.memcache");
  lua_setmetatable(L, -2);
  if (!memcached_create(&o->memc) ||
      memcached_behavior_set(&o->memc,
          MEMCACHED_BEHAVIOR_NO_BLOCK,1) != MEMCACHED_SUCCESS
    )
    {
      lua_remove(L, -1);
      lua_pushnil(L);
    }
  return 1;
}

static int l_sipmemcache_server_add(lua_State *L)
{
  memcached_server_st *servers = NULL;
  memcached_return_t rc;
  struct sipmemcache *o;
  const char *host;
  const char *port;
  in_port_t iport;
  str s;

  o = luaL_checkudata(L, 1, "siplua.memcache");
  host = luaL_checkstring(L, 2);
  port = luaL_checkstring(L, 3);
  if (o->finalized)
    {
      lua_pushnil(L);
    }
  else
    {
		s.len = strlen(port);
		s.s = (char *)port;
		if (str2int(&s, (unsigned int *)&iport) < 0)
			lua_pushboolean(L, 0);
		else
			lua_pushboolean(L, 1);
		servers = memcached_server_list_append(servers, host, iport, &rc);
		if (rc != MEMCACHED_SUCCESS) {
			LM_ERR("cannot add server: %s\n", memcached_strerror(&o->memc, rc));
			lua_pushboolean(L, 0);
		} else
			lua_pushboolean(L, 1);
		rc = memcached_server_push(&o->memc, servers);
		if (rc != MEMCACHED_SUCCESS) {
			LM_ERR("cannot push server: %s\n", memcached_strerror(&o->memc, rc));
			lua_pushboolean(L, 0);
		} else
			lua_pushboolean(L, 1);
	}
  return 1;
}

static int sipmemcache_storage_cmds(lua_State *L,
		memcached_return_t (*f)(memcached_st *ptr,
			const char *key,
			size_t key_length,
			const char *value,
			size_t value_length,
			time_t expiration,
			uint32_t flags))
{
  struct sipmemcache *o;
  const char *key, *val;
  size_t keyslen, bytes;
  time_t expire;

  o = luaL_checkudata(L, 1, "siplua.memcache");
  key = luaL_checklstring(L, 2, &keyslen);
  val = luaL_checklstring(L, 3, &bytes);
  expire = luaL_optinteger(L, 4, 3600);
  if (o->finalized)
    {
      lua_pushnil(L);
    }
  else
    {
		if (f(&o->memc, key, keyslen, val, bytes, expire, 0) == MEMCACHED_SUCCESS)
			lua_pushinteger(L, 0);
		else
			lua_pushinteger(L, -1);
    }
  return 1;
}

static int l_sipmemcache_add(lua_State *L)
{
  return sipmemcache_storage_cmds(L, memcached_add);
}

static int l_sipmemcache_replace(lua_State *L)
{
  return sipmemcache_storage_cmds(L, memcached_replace);
}

static int l_sipmemcache_set(lua_State *L)
{
  return sipmemcache_storage_cmds(L, memcached_set);
}

static int sipmemcache_atomic_opts(lua_State *L, u_int32_t (*f)(memcached_st *st,
								const char *key, size_t key_len,
								const uint32_t offset, uint64_t *value))
{
  struct sipmemcache *o;
  const char *key;
  size_t keyslen;
  uint64_t res;
  int nb;

  o = luaL_checkudata(L, 1, "siplua.memcache");
  key = luaL_checklstring(L, 2, &keyslen);
  nb = luaL_checkinteger(L, 3);
  if (o->finalized)
    {
      lua_pushnil(L);
    }
  else
    {
		if (f(&o->memc, key, keyslen, nb, &res) == MEMCACHED_SUCCESS)
			lua_pushinteger(L, (int)res);
    }
  return 1;
}

static int l_sipmemcache_incr(lua_State *L)
{
  return sipmemcache_atomic_opts(L, memcached_increment);
}

static int l_sipmemcache_decr(lua_State *L)
{
  return sipmemcache_atomic_opts(L, memcached_decrement);
}

static int l_sipmemcache_delete(lua_State *L)
{
  struct sipmemcache *o;
  const char *key;
  size_t keyslen;
  memcached_return_t ret;

  o = luaL_checkudata(L, 1, "siplua.memcache");
  key = luaL_checklstring(L, 2, &keyslen);
  if (o->finalized)
    {
      lua_pushnil(L);
    }
  else
    {
      ret = memcached_delete(&o->memc, (char *)key, keyslen, 0);
      lua_pushinteger(L, ret);
    }
  return 1;
}

static int l_sipmemcache_get(lua_State *L)
{
  struct sipmemcache *o;
  const char *key;
  size_t keyslen;
  char *blah;
  size_t retlen;
  memcached_return_t rc;

  o = luaL_checkudata(L, 1, "siplua.memcache");
  key = luaL_checklstring(L, 2, &keyslen);
  if (o->finalized)
    {
      lua_pushnil(L);
    }
  else
    {
      blah = memcached_get(&o->memc, (char *)key, keyslen, &retlen, 0, &rc);
      if (rc == MEMCACHED_SUCCESS && blah)
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
  if (!o->finalized)
    {
      if (o->keys)
	{
	  pkg_free(o->keys);
	  o->keys = NULL;
	}
      if (o->keyslen)
	{
	  pkg_free(o->keyslen);
	  o->keyslen = NULL;
	}
	  memcached_quit(&o->memc);
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
  int i, n;
  memcached_return_t  rc;
  memcached_result_st res;

  o = luaL_checkudata(L, 1, "siplua.memcache");
  if (o->finalized)
    {
      lua_pushnil(L);
      return 1;
    }
  n = lua_gettop(L);
  lua_newtable(L);
  if (n < 2)
    return 1;
  o->keys = pkg_malloc((n - 1) * sizeof(char *));
  o->keyslen = pkg_malloc((n - 1) * sizeof(size_t));
  for (i = 0; i < n - 1; ++i)
    {
      o->keys[i] = luaL_checklstring(L, i + 2, &o->keyslen[i]);
/*       o->res[i]->size = 1024; */
/*       o->res[i]->val = malloc(o->res[i]->size); */
/*       mc_res_free_on_delete(o->res[i], 1); */
    }
  if (memcached_mget(&o->memc, o->keys, o->keyslen, n) == MEMCACHED_SUCCESS) {
  for (i = 0; i < n - 1; ++i)
    {
		if (memcached_fetch_result(&o->memc, &res, &rc))
		{
			lua_pushvalue(L, i + 2);
			lua_pushlstring(L, memcached_result_value(&res), memcached_result_length(&res));
			lua_rawset(L, -3);
		}
/*       mc_res_free(o->req, o->res[i]); */
    }
  }
  pkg_free(o->keys);
  o->keys = NULL;
  pkg_free(o->keyslen);
  o->keyslen = NULL;
  return 1;
}

static const struct luaL_Reg siplua_memcache_mylib [] =
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
