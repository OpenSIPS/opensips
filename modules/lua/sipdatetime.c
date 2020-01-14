/*
 * Copyright (c) 2006, 2007, 2008, 2009
 * 	     Eric Gouyer <folays@folays.net>
 * Copyright (c) 2006, 2007, 2008, 2009, 2010, 2011
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

#define _XOPEN_SOURCE
#include <stdlib.h>
#include <string.h>
#define __USE_MISC /* for timegm() */
#include <time.h>

#include <lua.h>
#include <lauxlib.h>
#include "compat.h"

struct sipdatetime
{
  int finalized;
  time_t v;
};


static int l_sipdatetime_now(lua_State *L)
{
  struct sipdatetime *o;

  o = lua_newuserdata(L, sizeof(*o));
  memset(o, '\0', sizeof(*o));
  luaL_getmetatable(L, "siplua.datetime");
  lua_setmetatable(L, -2);
  o->v = time(NULL); /* UTC */
  return 1;
}

static int l_sipdatetime_duplicate(lua_State *L)
{
  struct sipdatetime *o;
  struct sipdatetime *o2;

  o = luaL_checkudata(L, 1, "siplua.datetime");
  if (o->finalized)
    {
      lua_pushnil(L);
      return 1;
    }
  o2 = lua_newuserdata(L, sizeof(*o2));
  memset(o2, '\0', sizeof(*o2));
  luaL_getmetatable(L, "siplua.datetime");
  lua_setmetatable(L, -2);
  o2->v = o->v;
  return 1;
}

static int sipdatetime_strftime(struct sipdatetime *o, lua_State *L, const char *format)
{
  struct tm tm;
  char buf[256];
  int ret;

  gmtime_r(&o->v, &tm); /* UTC */
  ret = strftime(buf, sizeof(buf), format, &tm);
  if (!ret || ret >= sizeof(buf))
    {
      lua_pushnil(L);
      return 1;
    }
  lua_pushlstring(L, buf, ret);
  return 1;
}

static int l_sipdatetime_strftime(lua_State *L)
{
  struct sipdatetime *o;
  const char *str;

  o = luaL_checkudata(L, 1, "siplua.datetime");
  str = luaL_checkstring(L, 2);
  if (o->finalized)
    {
      lua_pushnil(L);
      return 1;
    }
  return sipdatetime_strftime(o, L, str);
}

static int l_sipdatetime_str(lua_State *L)
{
  struct sipdatetime *o;

  o = luaL_checkudata(L, 1, "siplua.datetime");
  if (o->finalized)
    {
      lua_pushnil(L);
      return 1;
    }
  return sipdatetime_strftime(o, L, "%Y-%m-%d %H:%M:%S");
}

static int l_sipdatetime_add(lua_State *L)
{
  struct sipdatetime *o;
  int n;

  o = luaL_checkudata(L, 1, "siplua.datetime");
  n = luaL_checkinteger(L, 2);
  if (o->finalized)
    {
      lua_pushnil(L);
      return 1;
    }
  o->v += n;
  lua_pushvalue(L, 1);
  return 1;
}

static int l_sipdatetime_compare(lua_State *L)
{
  struct sipdatetime *o;
  struct sipdatetime *o2;
  int cmp;

  o = luaL_checkudata(L, 1, "siplua.datetime");
  o2 = luaL_checkudata(L, 2, "siplua.datetime");
  if (o->finalized || o2->finalized)
    {
      lua_pushnil(L);
      return 1;
    }
  cmp = difftime(o->v, o2->v);
  lua_pushinteger(L, cmp);
  return 1;
}

static int l_sipdatetime_parse_str(lua_State *L)
{
  const char *str;
  struct tm tm;
  char *ret;
  struct sipdatetime *o;

  str = luaL_checkstring(L, 1);
  ret = strptime(str, "%Y-%m-%d %H:%M:%S", &tm);
  if (!ret || *ret != '\0')
    {
      lua_pushnil(L);
      return 1;
    }
  o = lua_newuserdata(L, sizeof(*o));
  memset(o, '\0', sizeof(*o));
  luaL_getmetatable(L, "siplua.datetime");
  lua_setmetatable(L, -2);
  o->v = timegm(&tm); /* UTC */
  return 1;
}

static int l_sipdatetime___gc(lua_State *L)
{
  return 0;
}

static int l_sipdatetime___index(lua_State *L)
{
  luaL_checkudata(L, 1, "siplua.datetime");
  lua_getmetatable(L, 1);
  luaL_checkstring(L, 2);
  lua_pushvalue(L, 2);
  lua_rawget(L, -2);
  lua_remove(L, -2);
  return 1;
}

static const struct luaL_Reg siplua_datetime_mylib [] =
  {
    {"duplicate", l_sipdatetime_duplicate},
    {"strftime", l_sipdatetime_strftime},
    {"str", l_sipdatetime_str},
    {"add", l_sipdatetime_add},
    {"compare", l_sipdatetime_compare},
    {"parse_str", l_sipdatetime_parse_str},
    {"__gc", l_sipdatetime___gc},
    {"__index", l_sipdatetime___index},
    {NULL, NULL} /* sentinel */
  };

void siplua_register_datetime_cclosures(lua_State *L)
{
  luaL_newmetatable(L, "siplua.datetime");
  luaL_openlib(L, NULL, siplua_datetime_mylib, 0);
  lua_remove(L, -1);
  lua_pushcclosure(L, l_sipdatetime_now, 0);
  lua_setglobal(L, "datetime_now");
  lua_pushcclosure(L, l_sipdatetime_parse_str, 0);
  lua_setglobal(L, "datetime_parse_str");
}
