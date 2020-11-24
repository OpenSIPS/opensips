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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"

#include "siplua.h"
#include "sipluafunc.h"
#include "sipapi.h"
#include "sipmysql.h"
#include "sipmemcache.h"
#include "sipwatch.h"
#include "sipdatetime.h"
#include "sipstate.h"
#include "compat.h"

static const char *sipstate_filename;
static int sipstate_time;
static lua_State *siplua_L;
static struct sipapi_object *siplua_msg;

static size_t total_size;
static int total_frags;

static void *siplua_lua_Alloc(void *ud,
			      void *ptr,
			      size_t osize,
			      size_t nsize)
{
  char *p;

  total_size += nsize - osize;
  if (nsize == 0)
    {
      if (osize != 0 && ptr)
	{
	  pkg_free(ptr);
	  --total_frags;
	}
      return NULL;
    }
  else
    {
      if (osize == 0 || !ptr)
	{
	  p = pkg_malloc(nsize);
	  ++total_frags;
	}
      else
	{
	  p = pkg_realloc(ptr, nsize);
	}
      if (!p)
	LM_ERR("cannot allocate pkg memory\n");
      return p;
    }
}

static void *siplua_lua_Alloc2(void *ud,
			      void *ptr,
			      size_t osize,
			      size_t nsize)
{
  (void)ud;  (void)osize;  /* not used */
  total_size += nsize - osize;
  if (nsize == 0)
    {
      if (ptr)
	--total_frags;
    }
  else
    {
      if (!ptr)
	++total_frags;
    }
  if (nsize == 0) {
    free(ptr);
    return NULL;
  }
  else
    return realloc(ptr, nsize);
}

static int l_sipstate_xlog(lua_State *L)
{
  const char *level;
  const char *str;
  int lev = L_ERR;
  size_t len;
  int n;

  n = lua_gettop(L);
  if (n < 2)
    str = luaL_checklstring(L, 1, &len);
  else
    {
      level = luaL_checkstring(L, 1);
      if (strlen(level) < 3)
	return luaL_error(L, "wrong log level %s", level);
      switch (level[2])
	{
	case 'A': lev = L_ALERT; break;
	case 'C': lev = L_CRIT; break;
	case 'E': lev = L_ERR; break;
	case 'W': lev = L_WARN; break;
	case 'N': lev = L_NOTICE; break;
	case 'I': lev = L_INFO; break;
	case 'D': lev = L_DBG; break;
	default:
	  return luaL_error(L, "unknown log level %s", level);
	}
      str = luaL_checklstring(L, 2, &len);
    }
  siplua_log(lev, "%.*s", (int)len, str);
  return 0;
}

static int l_sipstate_xdbg(lua_State *L)
{
  const char *str;
  size_t len;

  str = luaL_checklstring(L, 1, &len);
  siplua_log(L_DBG, "%.*s", (int)len, str);
  return 0;
}

/* I was tired of not seing output when i wrongly used print() instead of xlog() */
static int l_sipstate_print(lua_State *L)
{
  const char *str;
  size_t len;
  int top;
  int i;

  top = lua_gettop(L);
  for (i = 0; i < top; ++i)
    {
      str = luaL_checklstring(L, i + 1, &len);
      siplua_log(L_ALERT, "%.*s\n", (int)len, str);
    }
  return 0;
}

static int l_sipstate_notice(lua_State *L)
{
  int nargs;
  int local = 0;
  const char *str;
  size_t len;

  nargs = lua_gettop(L);
  if (!(nargs >= 1 && nargs <= 2))
    return luaL_error(L, "wrong number of arguments ([local], str)");
  if (nargs >= 2)
    local = luaL_checkinteger(L, 1);
  str = luaL_checklstring(L, nargs, &len);
  siplua_notice(local, "%.*s", (int)len, str);
  return 0;
}

static int l_sipstate_setUserDebug(lua_State *L)
{
  int n;

  n = luaL_checkinteger(L, 1);
  lua_user_debug = n;
  return 0;
}

static int l_sipstate_getpid(lua_State *L)
{
  int pid;

  pid = getpid();
  lua_pushinteger(L, pid);
  return 1;
}

static int l_sipstate_getmem(lua_State *L)
{
  lua_newtable(L);
  lua_pushstring(L, "total_size");
  lua_pushinteger(L, total_size);
  lua_rawset(L, -3);
  lua_pushstring(L, "total_frags");
  lua_pushinteger(L, total_frags);
  lua_rawset(L, -3);
  return 1;
}

static int sipstate_getmeminfo(lua_State *L, struct mem_info *info)
{
  lua_newtable(L);
  lua_pushstring(L, "total_size");
  lua_pushinteger(L, info->total_size);
  lua_rawset(L, -3);
  lua_pushstring(L, "free");
  lua_pushinteger(L, info->free);
  lua_rawset(L, -3);
  lua_pushstring(L, "used");
  lua_pushinteger(L, info->used);
  lua_rawset(L, -3);
  lua_pushstring(L, "real_used");
  lua_pushinteger(L, info->real_used);
  lua_rawset(L, -3);
  lua_pushstring(L, "max_used");
  lua_pushinteger(L, info->max_used);
  lua_rawset(L, -3);
  lua_pushstring(L, "min_frag");
  lua_pushinteger(L, info->min_frag);
  lua_rawset(L, -3);
  lua_pushstring(L, "total_frags");
  lua_pushinteger(L, info->total_frags);
  lua_rawset(L, -3);
  return 1;
}

static int l_sipstate_getpkginfo(lua_State *L)
{
  struct mem_info info;

  SHM_INFO(mem_block, &info);
  return sipstate_getmeminfo(L, &info);
}

static int l_sipstate_getshminfo(lua_State *L)
{
  struct mem_info info;

  shm_info(&info);
  return sipstate_getmeminfo(L, &info);
}

static int l_sipstate_gethostname(lua_State *L)
{
  char name[MAXHOSTNAMELEN];
  int ret;

  ret = gethostname(name, sizeof(name));
  if (!ret)
    lua_pushstring(L, name);
  else
    lua_pushnil(L);
  return 1;
}

static int l_sipstate_filemtime(lua_State *L)
{
  const char *str;
  struct stat sb;
  int ret;

  str = luaL_checkstring(L, 1);
  ret = stat(str, &sb);
  if (!ret)
    lua_pushinteger(L, sb.st_mtime);
  else
    lua_pushnil(L);
  return 1;
}

static int l_sipstate_setCoreDebug(lua_State *L)
{
  int n;

  n = luaL_checkinteger(L, 1);
  set_proc_log_level(n);

  return 0;
}

static const struct luaL_Reg siplua_state_mylib [] =
  {
    {"xlog", l_sipstate_xlog},
    {"xdbg", l_sipstate_xdbg},
    {"print", l_sipstate_print},
    {"notice", l_sipstate_notice},
    {"setUserDebug", l_sipstate_setUserDebug},
    {"getpid", l_sipstate_getpid},
    {"getmem", l_sipstate_getmem},
    {"getmeminfo", l_sipstate_getpkginfo},
    {"getpkginfo", l_sipstate_getpkginfo},
    {"getshminfo", l_sipstate_getshminfo},
    {"gethostname", l_sipstate_gethostname},
    {"filemtime", l_sipstate_filemtime},
    {"setCoreDebug", l_sipstate_setCoreDebug},
    {NULL, NULL} /* sentinel */
  };

static void siplua_register_state_cclosures(lua_State *L)
{
  lua_pushglobaltable(L);
  luaL_openlib(L, "opensips", siplua_state_mylib, 0);
  lua_remove(L, -1);
}

int sipstate_open(char *allocator)
{
  lua_State *L;
  if (!strcmp(allocator, "opensips"))
    L = lua_newstate(siplua_lua_Alloc, NULL);
  else if (!strcmp(allocator, "malloc"))
    L = lua_newstate(siplua_lua_Alloc2, NULL);
  else
    {
      siplua_log(L_ERR, "Unknown Lua memory allocator\n");
      return -1;
    }
  if (!(siplua_L = L))
    {
      siplua_log(L_ERR, "Failed to open Lua state\n");
      return -1;
    }
  else
    siplua_log(L_DBG, "Lua state opened\n");
  luaL_openlibs(L);
  siplua_register_state_cclosures(L);
  siplua_register_api_cclosures(L);
  siplua_register_mysql_cclosures(L);
  siplua_register_memcache_cclosures(L);
  siplua_register_watch_cclosures(L);
  siplua_register_datetime_cclosures(L);
  siplua_msg = sipapi_create_object(L);
  return 0;
}

void sipstate_close(void)
{
  sipapi_delete_object(siplua_msg);
  lua_close(siplua_L);
  siplua_L = 0;
}

int sipstate_load(const char *filename)
{
  lua_State *L = siplua_L;
  struct stat sb;
  int ret;
  const char *errmsg;

  if (!filename)
    filename = sipstate_filename;
  if (!filename)
    {
      siplua_log(L_ERR, "siplua Lua filename is NULL\n");
      return -1;
    }
  ret = stat(filename, &sb);
  if (!ret && sipstate_filename &&
      sb.st_mtime == sipstate_time)
    return 0;
  if (luaL_loadfile(L, filename) || lua_pcall(L, 0, 0, 0))
    {
      errmsg = lua_tostring(L, -1);
      siplua_log(L_ERR, "siplua error loading file %s: %s\n", filename, errmsg);
      lua_remove(L, -1);
      return -1;
    }
  else
    {
      siplua_log(L_INFO, "siplua file %s successfully reloaded\n", filename);
      sipstate_filename = filename;
      sipstate_time = sb.st_mtime;
      return 0;
    }
}

int sipstate_call(struct sip_msg *msg, const str *_fnc_s, const str *_mystr_s)
{
  lua_State *L = siplua_L;
  int ref;
  const char *errmsg;
  int n;
  char *fnc, *mystr = NULL;

  fnc = pkg_malloc(_fnc_s->len+1);
  if (!fnc) {
    LM_ERR("No more pkg mem!\n");
    return -1;
  }
  memcpy(fnc, _fnc_s->s, _fnc_s->len);
  fnc[_fnc_s->len] = 0;

  if (_mystr_s) {
    mystr = pkg_malloc(_mystr_s->len+1);
    if (!mystr) {
      LM_ERR("No more pkg mem!\n");
      return -1;
    }
    memcpy(mystr, _mystr_s->s, _mystr_s->len);
    mystr[_mystr_s->len] = 0;
  }

  if (lua_auto_reload)
    sipstate_load(NULL);

  lua_getglobal(L, fnc);
  if (lua_isnil(L, -1))
    {
      siplua_log(L_ERR, "siplua Lua function %s is nil\n", fnc);
      lua_remove(L, -1);
      return -1;
    }
  sipapi_set_object(siplua_msg, msg);
  ref = sipapi_get_object_ref(siplua_msg);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
  if (mystr)
    lua_pushstring(L, mystr);
  if (lua_pcall(siplua_L, (mystr ? 2 : 1), 1, 0))
    {
      errmsg = lua_tostring(L, -1);
      siplua_log(L_ERR, "siplua error running function %s: %s\n", fnc, errmsg);
      lua_remove(L, -1);
      n = -1;
    }
  else
    {
      n = lua_tointeger(L, -1);
      lua_remove(L, -1);
/*       siplua_log(L_DBG , "siplua Lua function %s returned %d\n", fnc, n); */
    }

  pkg_free(fnc);
  if (mystr)
    pkg_free(mystr);

  return n;
}
