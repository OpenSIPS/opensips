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

#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <mysql/mysql.h>
#if (defined LIBMYSQL_VERSION_ID) && (LIBMYSQL_VERSION_ID >= 80000)
# define my_bool bool
#endif

#include "../../mem/mem.h"

#include "sipluafunc.h"
#include "compat.h"

#define SIPMYSQL_FETCH_NUM (1 << 0)
#define SIPMYSQL_FETCH_ASSOC (1 << 1)
#define SIPMYSQL_FETCH_BOTH (SIPMYSQL_FETCH_NUM | SIPMYSQL_FETCH_ASSOC)

struct sipmysql
{
  int finalized;
  MYSQL *my;
  int num_fields;
  int num_rows;
  MYSQL_RES *result;
  MYSQL_FIELD *fields;
  MYSQL_ROW row;
  int ref; /* luaL_ref() */
};

struct sipmysql_stmt
{
  int finalized;
  MYSQL_STMT *stmt;
  int param_count;
  int num_fields;
  MYSQL_BIND *bind;
  MYSQL_BIND *result;
  my_bool *is_null; /* param `is null' array */
  unsigned long *length; /* param lengths */
  unsigned long *real_length; /* result non-truncated lengths */
  MYSQL_RES *meta_result;
  MYSQL_FIELD *fields;
  int result_set_exist;
  int num_rows;
};

static int l_sipmysql_connect(lua_State *L)
{
  struct sipmysql *o;
  void *ptr;
  const char *host, *user, *password, *db;
  my_bool reconnect = 1;

  host = luaL_checkstring(L, 1);
  user = luaL_checkstring(L, 2);
  password = luaL_checkstring(L, 3);
  db = luaL_checkstring(L, 4);
  o = lua_newuserdata(L, sizeof(*o));
  memset(o, '\0', sizeof(*o));
  luaL_getmetatable(L, "siplua.mysql");
  lua_setmetatable(L, -2);
  o->ref = LUA_NOREF;
  mysql_library_init(0, NULL, NULL);
  o->my = mysql_init(NULL);
  mysql_options(o->my, MYSQL_OPT_RECONNECT, &reconnect);
  ptr = mysql_real_connect(o->my, host, user, password, db, 0, NULL, 0);
  if (!ptr)
    {
      lua_remove(L, -1);
      lua_pushnil(L);
    }
/*   printf("ptr: %p\n", ptr); */
  lua_newtable(L);
  lua_newtable(L);
  lua_pushliteral(L, "__mode");
  lua_pushliteral(L, "k");
  lua_rawset(L, -3);
  lua_setmetatable(L, -2);
  o->ref = luaL_ref(L, LUA_REGISTRYINDEX);
  return 1;
}

static void sipmysql_free_result(struct sipmysql *o)
{
  if (!o->finalized && o->result)
    {
      o->fields = NULL;
      mysql_free_result(o->result);
      o->result = NULL;
    }
}

static void sipmysql_close(lua_State *L)
{
  struct sipmysql *o;

  o = luaL_checkudata(L, 1, "siplua.mysql");
  if (!o->finalized && o->my)
    {
      if (o->ref != LUA_NOREF)
	{
	  lua_rawgeti(L, LUA_REGISTRYINDEX, o->ref);
	  lua_pushnil(L);
	  while (lua_next(L, -2) != 0)
	    {
	      if (luaL_callmeta(L, -2, "close"))
		lua_pop(L, 1);
	      lua_pop(L, 1);
	    }
	  lua_pop(L, 1);
	  luaL_unref(L, LUA_REGISTRYINDEX, o->ref);
	  o->ref = LUA_NOREF;
	}
      sipmysql_free_result(o);
      mysql_close(o->my);
      o->my = NULL;
      mysql_library_end(); /* could crash other opened mysql libraries? */
      o->finalized = 1;
    }
}

static int l_sipmysql_close(lua_State *L)
{
  sipmysql_close(L);
  return 0;
}

static int l_sipmysql_query(lua_State *L)
{
  struct sipmysql *o;
  const char *str;
  int ret;

  o = luaL_checkudata(L, 1, "siplua.mysql");
  if (o->finalized)
    {
      lua_pushnil(L);
    }
  else
    {
      sipmysql_free_result(o);
      str = luaL_checkstring(L, 2);
      ret = mysql_query(o->my, str);
      if (ret)
	{
	  lua_pushnil(L);
	}
      else
	{
	  o->result = mysql_store_result(o->my);
	  if (o->result)
	    {
	      o->num_fields = mysql_num_fields(o->result);
	      o->num_rows = mysql_num_rows(o->result);
/* 	      siplua_log(L_DBG, "mysql query return a table of %d fields and %d rows", */
/* 			 o->num_fields, o->num_rows); */
	      lua_pushboolean(L, 1);
	    }
	  else
	    {
	      if (mysql_field_count(o->my) == 0)
		{
		  o->num_fields = 0;
		  o->num_rows = mysql_affected_rows(o->my);
		  lua_pushboolean(L, 1);
		}
	      else
		{
		  lua_pushnil(L);
		}
	    }
	}
    }
  return 1;
}

static int l_sipmysql_affected_rows(lua_State *L)
{
  struct sipmysql *o;

  o = luaL_checkudata(L, 1, "siplua.mysql");
  if (o->finalized)
    {
      lua_pushnil(L);
    }
  else
    {
      lua_pushinteger(L, o->num_rows);
    }
  return 1;
}

static int sipmysql_fetch(lua_State *L, int result_type)
{
  struct sipmysql *o;
  int n;

  o = luaL_checkudata(L, 1, "siplua.mysql");
  if (o->finalized || !o->result)
    {
      lua_pushnil(L);
    }
  else
    {
      if (result_type & SIPMYSQL_FETCH_ASSOC && !o->fields)
	o->fields = mysql_fetch_fields(o->result);
      n = lua_gettop(L);
      if (n < 2)
	lua_newtable(L);
      else
	{
	  luaL_checktype(L, 2, LUA_TTABLE);
	  lua_pushvalue(L, -1);
	}
      o->row = mysql_fetch_row(o->result);
      if (!o->row) /* we should check for a server error here */
	{
	  lua_remove(L, -1);
	  lua_pushnil(L);
	}
      else
	{
	  unsigned long *lengths;
	  int i;

	  lengths = mysql_fetch_lengths(o->result);
	  for (i = 0; i < o->num_fields; ++i)
	    {
	      if (result_type & SIPMYSQL_FETCH_NUM)
		{
		  lua_pushinteger(L, i + 1);
		  lua_pushlstring(L, o->row[i], lengths[i]);
		  lua_rawset(L, -3);
		}
	      if (result_type & SIPMYSQL_FETCH_ASSOC)
		{
		  lua_pushstring(L, o->fields[i].name);
		  lua_pushlstring(L, o->row[i], lengths[i]);
		  lua_rawset(L, -3);
		}
	    }
	}
    }
  return 1;
}

int l_sipmysql_fetch_row(lua_State *L)
{
  return sipmysql_fetch(L, SIPMYSQL_FETCH_NUM);
}

int l_sipmysql_fetch_assoc(lua_State *L)
{
  return sipmysql_fetch(L, SIPMYSQL_FETCH_ASSOC);
}

int l_sipmysql_fetch_array(lua_State *L)
{
  return sipmysql_fetch(L, SIPMYSQL_FETCH_BOTH);
}

int l_sipmysql_free_result(lua_State *L)
{
  struct sipmysql *o;

  o = luaL_checkudata(L, 1, "siplua.mysql");
  sipmysql_free_result(o);
  return 0;
}

static int l_sipmysql_escape(lua_State *L)
{
  struct sipmysql *o;
  const char *str;
  size_t len;
  char *to;

  o = luaL_checkudata(L, 1, "siplua.mysql");
  str = luaL_checklstring(L, 2, &len);
  to = pkg_malloc(2 * len + 1);
  if (!to)
    {
      siplua_log(L_CRIT, "malloc of %d bytes failed\n", 2 * len + 1);
      lua_pushnil(L);
      return 1;
    }
  len = mysql_real_escape_string(o->my, to, str, len);
  lua_pushlstring(L, to, len);
  pkg_free(to);
  return 1;
}

static int l_sipmysql_insert_id(lua_State *L)
{
  struct sipmysql *o;
  long long id;

  o = luaL_checkudata(L, 1, "siplua.mysql");
  id = mysql_insert_id(o->my);
  lua_pushinteger(L, id);
  return 1;
}

static int l_sipmysql_prepare(lua_State *L)
{
  struct sipmysql *o;
  struct sipmysql_stmt *o_stmt;
  const char *str;
  size_t len;
  int ret;
  int i;
/*   my_bool arg; */

  o = luaL_checkudata(L, 1, "siplua.mysql");
  if (o->finalized)
    {
      lua_pushnil(L);
    }
  else
    {
      str = luaL_checklstring(L, 2, &len);
      o_stmt = lua_newuserdata(L, sizeof(*o_stmt));
      memset(o_stmt, '\0', sizeof(*o_stmt));
      luaL_getmetatable(L, "siplua.mysql_stmt");
      lua_setmetatable(L, -2);
      lua_rawgeti(L, LUA_REGISTRYINDEX, o->ref);
      lua_pushvalue(L, -2);
      lua_pushboolean(L, 1);
      lua_rawset(L, -3);
      lua_pop(L, 1);
      o_stmt->stmt = mysql_stmt_init(o->my); /* should be free'ed with
						mysql_stmt_close(MYSQL_STMT *) */
/*       arg = 1; */
/*       mysql_stmt_attr_set(MYSQL_STMT, STMT_ATTR_UPDATE_MAX_LENGTH, &arg); */
      ret = mysql_stmt_prepare(o_stmt->stmt, str, len);
      if (ret)
	{
	  lua_remove(L, -1);
	  lua_pushnil(L);
	  lua_pushstring(L, mysql_stmt_error(o_stmt->stmt));
	  return 2;
	}
      else
	{
	  o_stmt->param_count = mysql_stmt_param_count(o_stmt->stmt);
	  if (o_stmt->param_count)
	    {
	      o_stmt->bind = pkg_malloc(o_stmt->param_count * sizeof(MYSQL_BIND));
	      if (!o_stmt->bind)
		{
		  siplua_log(L_CRIT, "malloc of %d bytes failed\n",
			     o_stmt->param_count * sizeof(MYSQL_BIND));
		  lua_remove(L, -1);
		  lua_pushnil(L);
		  return 1;
		}
	      memset(o_stmt->bind, '\0', o_stmt->param_count * sizeof(MYSQL_BIND));
	      o_stmt->is_null = pkg_malloc(o_stmt->param_count * sizeof(my_bool));
	      if (!o_stmt->is_null)
		{
		  siplua_log(L_CRIT, "malloc of %d bytes failed\n",
			     o_stmt->param_count * sizeof(my_bool));
		  lua_remove(L, -1);
		  lua_pushnil(L);
		  return 1;
		}
	      memset(o_stmt->is_null, '\0', o_stmt->param_count * sizeof(my_bool));
	      o_stmt->length = pkg_malloc(o_stmt->param_count * sizeof(unsigned long));
	      if (!o_stmt->length)
		{
		  siplua_log(L_CRIT, "malloc of %d bytes failed\n",
			     o_stmt->param_count * sizeof(unsigned long));
		  lua_remove(L, -1);
		  lua_pushnil(L);
		  return 1;
		}
	      memset(o_stmt->length, '\0', o_stmt->param_count * sizeof(unsigned long));
	      for (i = 0; i < o_stmt->param_count; ++i)
		{
/* 		  *(o_stmt->bind[i].is_null = &o_stmt->is_null[i]) = 1; */
		  o_stmt->bind[i].is_null = &o_stmt->is_null[i];
		  *o_stmt->bind[i].is_null = 1;
		  o_stmt->bind[i].buffer_type = MYSQL_TYPE_NULL;
		  o_stmt->bind[i].length = &o_stmt->length[i];
		}
	    }
	  o_stmt->num_fields = mysql_stmt_field_count(o_stmt->stmt);
	  if (o_stmt->num_fields)
	    {
	      o_stmt->result = pkg_malloc(o_stmt->num_fields * sizeof(MYSQL_BIND));
	      if (!o_stmt->result)
		{
		  siplua_log(L_CRIT, "malloc of %d bytes failed\n",
			     o_stmt->num_fields * sizeof(MYSQL_BIND));
		  lua_remove(L, -1);
		  lua_pushnil(L);
		  return 1;
		}
	      memset(o_stmt->result, '\0', o_stmt->num_fields * sizeof(MYSQL_BIND));
	      o_stmt->real_length = pkg_malloc(o_stmt->num_fields * sizeof(unsigned long));
	      if (!o_stmt->real_length)
		{
		  siplua_log(L_CRIT, "malloc of %d bytes failed\n",
			     o_stmt->num_fields * sizeof(unsigned long));
		  lua_remove(L, -1);
		  lua_pushnil(L);
		  return 1;
		}
	      memset(o_stmt->real_length, '\0', o_stmt->num_fields * sizeof(unsigned long));
	      for (i = 0; i < o_stmt->num_fields; ++i)
		o_stmt->result[i].length = &o_stmt->real_length[i];
	    }
	  o_stmt->meta_result = mysql_stmt_result_metadata(o_stmt->stmt);
	  if (o_stmt->meta_result)
	    {
	      o_stmt->fields = mysql_fetch_fields(o_stmt->meta_result);
	    }
	}
    }
  return 1;
}

/*
 * XXX result_set_exist is set even when there is no meta_result.
 * http://dev.mysql.com/doc/refman/5.1/en/mysql-stmt-store-result.html
 *
 * [...]
 * It is unnecessary to call mysql_stmt_store_result() after executing
 * an SQL statement that does not produce a result set, but if you do,
 * it does not harm or cause any notable performance problem.
 * [...]
 *
 * It seems this does no harm either to call stmt_free_result(). Just useless.
 *
 * On the other hand, it's still desirable to clear o->num_rows.
 */
static void sipmysql_stmt_free_result(struct sipmysql_stmt *o)
{
  int ret;

  if (!o->finalized && o->result_set_exist)
    {
      o->num_rows = 0;
      ret = mysql_stmt_free_result(o->stmt);
      if (ret)
	siplua_log(L_CRIT, "mysql_stmt_free_result failed: [%d] %s\n",
		   mysql_stmt_errno(o->stmt), mysql_stmt_error(o->stmt));
      o->result_set_exist = 0;
    }
}

static void sipmysql_stmt_close(lua_State *L)
{
  struct sipmysql_stmt *o;
  int i;

  o = luaL_checkudata(L, 1, "siplua.mysql_stmt");
  if (!o->finalized && o->stmt)
    {
      sipmysql_stmt_free_result(o);
      for (i = 0; i < o->param_count; ++i)
	{
	  if (o->bind[i].buffer)
	    {
	      pkg_free(o->bind[i].buffer);
	      o->bind[i].buffer = NULL;
	      *o->bind[i].length = 0;
	    }
	}
      for (i = 0; i < o->num_fields; ++i)
	{
	  if (o->result[i].buffer)
	    {
	      pkg_free(o->result[i].buffer);
	      o->result[i].buffer = NULL;
	      o->result[i].buffer_length = 0;
	    }
	}
      if (o->meta_result)
	mysql_free_result(o->meta_result);
      o->meta_result = NULL;
      if (o->real_length)
	{
	  pkg_free(o->real_length);
	  o->real_length = NULL;
	}
      if (o->result)
	{
	  pkg_free(o->result);
	  o->result = NULL;
	  o->num_fields = 0;
	}
      if (o->length)
	{
	  pkg_free(o->length);
	  o->length = NULL;
	}
      if (o->is_null)
	{
	  pkg_free(o->is_null);
	  o->is_null = NULL;
	}
      if (o->bind)
	{
	  pkg_free(o->bind);
	  o->bind = NULL;
	  o->param_count = 0;
	}
      mysql_stmt_close(o->stmt);
      o->stmt = NULL;
      o->finalized = 1;
    }
}

static int l_sipmysql_stmt_close(lua_State *L)
{
  sipmysql_stmt_close(L);
  return 0;
}

/*
 * n : position of placeholder starting at 0
 * index : position onto the Lua stack
 */
static int sipmysql_stmt_bind(struct sipmysql_stmt *o, lua_State *L, int n, int index)
{
  if (!(n >= 0 && n < o->param_count))
    return luaL_error(L, "invalid bind parameter #%d", n);
  luaL_checkany(L, index);
  if (!*o->bind[n].is_null)
    {
      if (o->bind[n].buffer_type != MYSQL_TYPE_NULL)
	{
	  if (o->bind[n].buffer)
	    {
	      pkg_free(o->bind[n].buffer);
	      o->bind[n].buffer = NULL;
	      *o->bind[n].length = 0;
	    }
	  o->bind[n].buffer_type = MYSQL_TYPE_NULL;
	}
      *o->bind[n].is_null = 1;
    }
  switch (lua_type(L, index))
    {
    case LUA_TNIL:
      lua_pushboolean(L, 1);
      break;
    case LUA_TNUMBER:
    case LUA_TBOOLEAN:
      {
	long number;

	number = luaL_checklong(L, index);
	*o->bind[n].is_null = 0;
	o->bind[n].buffer_type = MYSQL_TYPE_LONG;
	o->bind[n].buffer = pkg_malloc(sizeof(number));
	if (!o->bind[n].buffer)
	  {
	    siplua_log(L_CRIT, "malloc of %d bytes failed\n", sizeof(number));
	    lua_pushnil(L);
	    return 1;
	  }
	memcpy(o->bind[n].buffer, &number, sizeof(number));
	lua_pushboolean(L, 1);
      }
      break;
    case LUA_TSTRING:
      {
	const char *str;
	size_t len;

	str = luaL_checklstring(L, index, &len);
	*o->bind[n].is_null = 0;
	o->bind[n].buffer_type = MYSQL_TYPE_STRING;
	o->bind[n].buffer = pkg_malloc(len);
	if (!o->bind[n].buffer)
	  {
	    siplua_log(L_CRIT, "malloc of %d bytes failed\n", len);
	    lua_pushnil(L);
	    return 1;
	  }
	memcpy(o->bind[n].buffer, str, len);
	*o->bind[n].length = len;
	lua_pushboolean(L, 1);
      }
      break;
    default:
      /* light & full userdata */
      siplua_log(L_CRIT, "invalid bind parameter #%d, Lua type %s not yet handled\n",
		 n, lua_typename(L, lua_type(L, index)));
      lua_pushnil(L);
    }
  return 1;
}

static int l_sipmysql_stmt_bind(lua_State *L)
{
  struct sipmysql_stmt *o;
  int n;

  o = luaL_checkudata(L, 1, "siplua.mysql_stmt");
  if (o->finalized || !o->bind)
    {
      lua_pushnil(L);
      return 1;
    }
  n = luaL_checkinteger(L, 2);
  return sipmysql_stmt_bind(o, L, n - 1, 3);
}

static int l_sipmysql_stmt_bind_all(lua_State *L)
{
  struct sipmysql_stmt *o;
  int n;
  int i;
  int ret;

  o = luaL_checkudata(L, 1, "siplua.mysql_stmt");
  if (o->finalized || !o->bind)
    {
      lua_pushnil(L);
      return 1;
    }
  n = lua_gettop(L) - 1;
  if (n != o->param_count)
    return luaL_error(L, "invalid number of bind parameter #%d (expected %d)",
		      n, o->param_count);
  for (i = 0; i < o->param_count; ++i)
    {
      ret = sipmysql_stmt_bind(o, L, i, i + 2);
      if (!(lua_isboolean(L, -1) && lua_toboolean(L, -1)))
	return ret;
      lua_pop(L, ret);
    }
  lua_pushboolean(L, 1);
  return 1;
}

static int l_sipmysql_stmt_execute(lua_State *L)
{
  struct sipmysql_stmt *o;
  int ret;

  o = luaL_checkudata(L, 1, "siplua.mysql_stmt");
  if (o->finalized)
    {
      lua_pushnil(L);
    }
  else
    {
      sipmysql_stmt_free_result(o);
      if (o->param_count)
	mysql_stmt_bind_param(o->stmt, o->bind); /* try to execute it only once */
      ret = mysql_stmt_execute(o->stmt);
      if (ret)
	{
	  lua_pushnil(L);
	}
      else
	{
	  /* XXX: result_set_exist might be set only if meta_result is true, see stmt_free_result */
	  o->result_set_exist = 1;
	  if (o->meta_result)
	    {
	      ret = mysql_stmt_bind_result(o->stmt, o->result); /* try to execute it only once */
	      if (ret) /* failure */
		{
		  siplua_log(L_CRIT, "mysql_stmt_bind_result failed: [%d] %s\n",
			     mysql_stmt_errno(o->stmt), mysql_stmt_error(o->stmt));
		  sipmysql_stmt_free_result(o);
		  lua_pushnil(L);
		}
	      else
		{
		  ret = mysql_stmt_store_result(o->stmt);
		  if (ret) /* failure */
		    {
		      /* unlike without prepared statement, store_result will succeed even with
			 a result set of 0 rows. We thus do not need to check mysql_field_count */
		      siplua_log(L_CRIT, "mysql_stmt_store_result failed: [%d] %s\n",
				 mysql_stmt_errno(o->stmt), mysql_stmt_error(o->stmt));
		      sipmysql_stmt_free_result(o);
		      lua_pushnil(L);
		    }
		  else
		    {
		      o->num_rows = mysql_stmt_affected_rows(o->stmt);
		    }
		}
	    }
	  else
	    {
	      /* XXX: check the API, we should maybe use mysql_stmt_num_rows() */
	      o->num_rows = mysql_stmt_affected_rows(o->stmt);
	    }
	  lua_pushboolean(L, 1);
	}
    }
  return 1;
}

static int l_sipmysql_stmt_affected_rows(lua_State *L)
{
  struct sipmysql_stmt *o;

  o = luaL_checkudata(L, 1, "siplua.mysql_stmt");
  if (o->finalized)
    {
      lua_pushnil(L);
    }
  else
    {
      lua_pushinteger(L, o->num_rows);
    }
  return 1;
}

static int sipmysql_stmt_fetch(lua_State *L, int result_type)
{
  struct sipmysql_stmt *o;
  int n;
  int ret;
  int i;

  o = luaL_checkudata(L, 1, "siplua.mysql_stmt");
  if (o->finalized || !o->meta_result || !o->result_set_exist)
    {
      lua_pushnil(L);
    }
  else
    {
      n = lua_gettop(L);
      if (n < 2)
	lua_newtable(L);
      else
	{
	  luaL_checktype(L, 2, LUA_TTABLE);
	  lua_pushvalue(L, -1);
	}
      ret = mysql_stmt_fetch(o->stmt);
      if (ret == 1) /* an error occurred */
	{
	  siplua_log(L_CRIT, "mysql_stmt_fetch failed: [%d] %s\n",
		     mysql_stmt_errno(o->stmt), mysql_stmt_error(o->stmt));
	  lua_remove(L, -1);
	  lua_pushnil(L);
	  return 1;
	}
      else if (ret == MYSQL_NO_DATA)
	{
	  lua_remove(L, -1);
	  lua_pushnil(L);
	  return 1;
	}
      else if (ret == MYSQL_DATA_TRUNCATED)
	{
	  char *buf;

	  for (i = 0; i < o->num_fields; ++i)
	    {
	      if (o->real_length[i] <= o->result[i].buffer_length)
		continue;
	      buf = pkg_realloc(o->result[i].buffer, o->real_length[i]);
	      if (!buf)
		{
		  siplua_log(L_CRIT, "realloc of %d bytes failed\n", o->real_length[i]);
		  lua_remove(L, -1);
		  lua_pushnil(L);
		  return 1;
		}
	      o->result[i].buffer_type = MYSQL_TYPE_STRING;
	      o->result[i].buffer = buf;
	      o->result[i].buffer_length = *o->result[i].length;
	      ret = mysql_stmt_fetch_column(o->stmt, &o->result[i], i, 0);
	      if (ret)
		{
		  siplua_log(L_CRIT, "mysql_stmt_fetch_column failed: [%d] %s\n",
			     mysql_stmt_errno(o->stmt), mysql_stmt_error(o->stmt));
		  lua_remove(L, -1);
		  lua_pushnil(L);
		  return 1;
		}
	    }
	  ret = mysql_stmt_bind_result(o->stmt, o->result);
	}
      /* ret == 0 */
      for (i = 0; i < o->num_fields; ++i)
	{
	  if (result_type & SIPMYSQL_FETCH_NUM)
	    {
	      lua_pushinteger(L, i + 1);
	      lua_pushlstring(L, o->result[i].buffer, o->real_length[i]);
	      lua_rawset(L, -3);
	    }
	  if (result_type & SIPMYSQL_FETCH_ASSOC)
	    {
	      lua_pushstring(L, o->fields[i].name);
	      lua_pushlstring(L, o->result[i].buffer, o->real_length[i]);
	      lua_rawset(L, -3);
	    }
	}
    }
  return 1;
}

static int l_sipmysql_stmt_fetch_row(lua_State *L)
{
  return sipmysql_stmt_fetch(L, SIPMYSQL_FETCH_NUM);
}

static int l_sipmysql_stmt_fetch_assoc(lua_State *L)
{
  return sipmysql_stmt_fetch(L, SIPMYSQL_FETCH_ASSOC);
}

static int l_sipmysql_stmt_fetch_array(lua_State *L)
{
  return sipmysql_stmt_fetch(L, SIPMYSQL_FETCH_BOTH);
}

static int l_sipmysql_stmt_free_result(lua_State *L)
{
  struct sipmysql_stmt *o;

  o = luaL_checkudata(L, 1, "siplua.mysql_stmt");
  sipmysql_stmt_free_result(o);
  return 0;
}

int l_sipmysql___gc(lua_State *L)
{
  sipmysql_close(L);
  return 0;
}

int l_sipmysql_stmt___gc(lua_State *L)
{
  sipmysql_stmt_close(L);
  return 0;
}

int l_sipmysql___index(lua_State *L)
{
  luaL_checkudata(L, 1, "siplua.mysql");
  lua_getmetatable(L, 1);
  luaL_checkstring(L, 2);
  lua_pushvalue(L, 2);
  lua_rawget(L, -2);
  lua_remove(L, -2);
  return 1;
}

int l_sipmysql_stmt___index(lua_State *L)
{
  luaL_checkudata(L, 1, "siplua.mysql_stmt");
  lua_getmetatable(L, 1);
  luaL_checkstring(L, 2);
  lua_pushvalue(L, 2);
  lua_rawget(L, -2);
  lua_remove(L, -2);
  return 1;
}

static const struct luaL_Reg siplua_mysql_mylib [] =
  {
    {"close", l_sipmysql_close},
    {"query", l_sipmysql_query},
    {"fetch_row", l_sipmysql_fetch_row},
    {"fetch_assoc", l_sipmysql_fetch_assoc},
    {"fetch_array", l_sipmysql_fetch_array},
    {"free_result", l_sipmysql_free_result},
    {"escape", l_sipmysql_escape},
    {"insert_id", l_sipmysql_insert_id},
    {"affected_rows", l_sipmysql_affected_rows},
    {"prepare", l_sipmysql_prepare},
    {"__gc", l_sipmysql___gc},
    {"__index", l_sipmysql___index},
    {NULL, NULL} /* sentinel */
  };

static const struct luaL_Reg siplua_mysql_stmt_mylib [] =
  {
    {"close", l_sipmysql_stmt_close},
    {"bind", l_sipmysql_stmt_bind},
    {"bind_all", l_sipmysql_stmt_bind_all},
    {"execute", l_sipmysql_stmt_execute},
    {"fetch_row", l_sipmysql_stmt_fetch_row},
    {"fetch_assoc", l_sipmysql_stmt_fetch_assoc},
    {"fetch_array", l_sipmysql_stmt_fetch_array},
    {"free_result", l_sipmysql_stmt_free_result},
    {"affected_rows", l_sipmysql_stmt_affected_rows},
    {"__gc", l_sipmysql_stmt___gc},
    {"__index", l_sipmysql_stmt___index},
    {NULL, NULL} /* sentinel */
  };

void siplua_register_mysql_cclosures(lua_State *L)
{
  luaL_newmetatable(L, "siplua.mysql");
  luaL_openlib(L, NULL, siplua_mysql_mylib, 0);
  lua_remove(L, -1);
  luaL_newmetatable(L, "siplua.mysql_stmt");
  luaL_openlib(L, NULL, siplua_mysql_stmt_mylib, 0);
  lua_remove(L, -1);
  lua_pushcclosure(L, l_sipmysql_connect, 0);
  lua_setglobal(L, "mysql_connect");
}
