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
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <lua.h>
#include <lauxlib.h>

#include "../../mem/mem.h"
#include "../../usr_avp.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_expires.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/contact/contact.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_rr.h"
#include "../../socket_info.h"
#include "../../forward.h"
#include "../../route_struct.h"
#include "../../sr_module.h"
#include "../../action.h"
#include "../../pvar.h"
#include "../../script_var.h"
#include "../../data_lump_rpl.h"
#include "../../mod_fix.h"
#include "../../ut.h"

#include "siplua.h"
#include "sipluafunc.h"
#include "sipapi.h"
#include "compat.h"

#if 0
static void siplua_moduleFunc_free(const char *func, cmd_export_t *exp_func_struct,
				   action_elem_t *elems, int nargs);
#endif

/*
 * Warning, should pcall this to prevent exit(1) if being out-of-memory.
 */
struct sipapi_object *sipapi_create_object(lua_State *L)
{
  struct sipapi_object *o;

  o = lua_newuserdata(L, sizeof(*o));
  memset(o, '\0', sizeof(*o));
  luaL_newmetatable(L, "siplua.api");
  lua_setmetatable(L, -2);
  o->ref = luaL_ref(L, LUA_REGISTRYINDEX);
  return o;
}

void sipapi_delete_object(struct sipapi_object *o)
{
}

void sipapi_set_object(struct sipapi_object *o, struct sip_msg *msg)
{
  o->msg = msg;
}

int sipapi_get_object_ref(struct sipapi_object *o)
{
  return o->ref;
}

static int sipapi_getExpires(struct sip_msg *msg)
{
  exp_body_t *_p_expires;

  if (parse_headers(msg, ~0, 0) < 0)
    return -1;
  if (!msg->expires || parse_expires(msg->expires) < 0)
    return -1;
  if (!msg->expires->parsed)
    return -1;
/*   siplua_log(L_DBG, "Step 0"); */
  if (msg->expires)
    {
/*       siplua_log(L_DBG, "Step 1 %p", msg->expires->parsed); */
      _p_expires = msg->expires->parsed;
/*       siplua_log(L_DBG, "Step 2 %p", _p_expires); */
      if (_p_expires->valid)
	{
/* 	  siplua_log(L_DBG, "Step 3"); */
	  return _p_expires->val;
	}
      else
	return -1;
    }
  else
    return -1;
}

static int l_siplua_getType(lua_State *L)
{
  struct sipapi_object *o;

  o = luaL_checkudata(L, 1, "siplua.api");
  if (o->msg)
    {
      switch (o->msg->first_line.type)
	{
	case SIP_REQUEST:
	  lua_pushstring(L, "SIP_REQUEST");
	  break;
	case SIP_REPLY:
	  lua_pushstring(L, "SIP_REPLY");
	  break;
	default:
	  lua_pushnil(L);
	}
    }
  else
    lua_pushnil(L);
  return 1;
}

static int l_siplua_getURI_User(lua_State *L)
{
  struct sipapi_object *o;
  struct sip_uri *myuri;

  o = luaL_checkudata(L, 1, "siplua.api");
  myuri = parse_to_uri(o->msg);
  if (!myuri)
    {
/*       siplua_log(L_WARN, "parse_to_uri returned NULL results"); */
      lua_pushnil(L);
    }
  else
    {
/*       siplua_log(L_DBG, "parse_to_uri returned non-empty results"); */
      lua_pushlstring(L, myuri->user.s, myuri->user.len);
    }
  return 1;
}

static int l_siplua_getExpires(lua_State *L)
{
  struct sipapi_object *o;
  int expires;

  o = luaL_checkudata(L, 1, "siplua.api");
/*   siplua_log(L_DBG, "BEFORE"); */
  expires = sipapi_getExpires(o->msg);
/*   siplua_log(L_DBG, "AFTER"); */
  if (expires != -1)
    lua_pushinteger(L, expires);
  else
    lua_pushnil(L);
  return 1;
}

static int l_siplua_getHeader(lua_State *L)
{
  struct sipapi_object *o;
  const char *str;
  size_t len;
  struct hdr_field *hf;

  o = luaL_checkudata(L, 1, "siplua.api");
  str = luaL_checklstring(L, 2, &len);
  if (parse_headers(o->msg, ~0, 0) < 0)
    return luaL_error(L, "failed to parse headers");
  for (hf = o->msg->headers; hf; hf = hf->next)
    {
      if (len == hf->name.len)
	{
	  if (strncasecmp(str, hf->name.s, len) == 0)
	    {
	      /* Found the right header. */
	      lua_pushlstring(L, hf->body.s, hf->body.len);
	      return 1;
	    }
	}
  }
  lua_pushnil(L);
  return 1;
}

static int l_siplua_getContact(lua_State *L)
{
  struct sipapi_object *o;
  struct hdr_field *_p;
  contact_t *_c;
  int n = 1;
  int found_hf_no_star = 0;
  int found_hf_star = 0;
  int expires;

  o = luaL_checkudata(L, 1, "siplua.api");
  if (!o->msg->contact)
    {
      lua_pushnil(L);
      return 1;
    }
  lua_newtable(L);
  _p = o->msg->contact;
  for (_p = o->msg->contact; _p; _p = _p->next)
    {
/*       siplua_log(L_DBG, "l_siplua_getContact _p/%p", _p); */
      if (_p->type == HDR_CONTACT_T)
	{
	  if (parse_contact(_p) < 0)
	    {
	      return luaL_error(L, "failed to parse Contact body");
	    }
	  if (((contact_body_t *)_p->parsed)->star)
	    {
	      lua_pushinteger(L, n++);
	      lua_newtable(L);
	      lua_pushstring(L, "star");
	      lua_pushboolean(L, 1);
	      lua_rawset(L, -3);
	      lua_pushstring(L, "name");
	      lua_pushstring(L, "*");
	      lua_rawset(L, -3);
	      lua_pushstring(L, "uri");
	      lua_pushstring(L, "*");
	      lua_rawset(L, -3);
	      lua_rawset(L, -3);
	      found_hf_star = 1;
	    }
	  for (_c = ((contact_body_t *)_p->parsed)->contacts; _c; _c = _c->next)
	    {
/* 	  siplua_log(L_DBG, "l_siplua_getContact _c/%p", _c); */
	      lua_pushinteger(L, n++);
	      lua_newtable(L);
	      lua_pushstring(L, "name");
	      lua_pushlstring(L, _c->name.s, _c->name.len);
	      lua_rawset(L, -3);
	      lua_pushstring(L, "uri");
	      lua_pushlstring(L, _c->uri.s, _c->uri.len);
	      lua_rawset(L, -3);
/* 	      siplua_log(L_DBG, "contact q/%p expires/%p", _c->q, _c->expires); */
	      if (_c->q)
		{
		  lua_pushstring(L, "q");
		  lua_pushlstring(L, _c->q->body.s, _c->q->body.len);
		  lua_pushnumber(L, lua_tonumber(L, -1));
		  lua_remove(L, -2);
		  lua_rawset(L, -3);
		}
	      if (_c->expires)
		{
		  lua_pushstring(L, "expires");
		  lua_pushlstring(L, _c->expires->body.s, _c->expires->body.len);
		  lua_pushnumber(L, lua_tonumber(L, -1));
		  lua_remove(L, -2);
		  lua_rawset(L, -3);
		}
	      lua_rawset(L, -3);
	      found_hf_no_star = 1;
	    }
	}
    }
  if (found_hf_star)
    {
      if (found_hf_no_star)
	{
	  lua_remove(L, -1);
	  lua_pushnil(L);
	  siplua_log(L_DBG, "l_siplua_getContact Found Contact HF with both star and no star.\n");
	}
      else
	{
/* 	  siplua_log(L_DBG, "BEFORE"); */
	  expires = sipapi_getExpires(o->msg);
/* 	  siplua_log(L_DBG, "AFTER"); */
	  if (expires != 0 && expires != -1)
	    {
	      lua_remove(L, -1);
	      lua_pushnil(L);
	      siplua_log(L_DBG, "l_siplua_getContact Found Contact HF star with unvalid expires.\n");
	    }
	}
    }
/*   siplua_log(L_DBG, "l_siplua_getContact returned."); */
  return 1;
}

static int l_siplua_getRoute(lua_State *L)
{
  struct sipapi_object *o;
  rr_t *rt;
  str uri;
  struct sip_uri puri;
  int n = 1;

  o = luaL_checkudata(L, 1, "siplua.api");
  if (parse_headers(o->msg, HDR_ROUTE_F, 0) == -1)
    return luaL_error(L, "failed to parse headers");
  if (!o->msg->route)
    {
      lua_pushnil(L);
      return 1;
    }
  if (parse_rr(o->msg->route) < 0)
    return luaL_error(L, "failed to parse route HF");
  lua_newtable(L);
  for (rt = (rr_t *)o->msg->route->parsed; rt; rt = rt->next )
    {
      uri = rt->nameaddr.uri;
      lua_pushinteger(L, n++);
      lua_newtable(L);
      lua_pushliteral(L, "uri");
      lua_pushlstring(L, uri.s, uri.len);
      lua_rawset(L, -3);
      if (parse_uri(uri.s, uri.len, &puri) < 0)
	{
	  if (n == 1)
	    return luaL_error(L, "failed to parse the first route URI");
	  continue;
	}
      lua_pushliteral(L, "user");
      lua_pushlstring(L, puri.user.s, puri.user.len);
      lua_rawset(L, -3);
      lua_pushliteral(L, "host");
      lua_pushlstring(L, puri.host.s, puri.host.len);
      lua_rawset(L, -3);
      lua_pushliteral(L, "port");
      lua_pushinteger(L, puri.port_no);
      lua_rawset(L, -3);
      lua_pushliteral(L, "params");
      lua_pushlstring(L, puri.params.s, puri.params.len);
      lua_rawset(L, -3);
      lua_pushliteral(L, "lr");
      lua_pushlstring(L, puri.lr.s, puri.lr.len);
      lua_rawset(L, -3);
      lua_pushliteral(L, "lr_val");
      lua_pushlstring(L, puri.lr_val.s, puri.lr_val.len);
      lua_rawset(L, -3);
      lua_pushliteral(L, "r2");
      lua_pushlstring(L, puri.r2.s, puri.r2.len);
      lua_rawset(L, -3);
      lua_pushliteral(L, "r2_val");
      lua_pushlstring(L, puri.r2_val.s, puri.r2_val.len);
      lua_rawset(L, -3);
      lua_pushliteral(L, "is_myself");
      if (check_self(&puri.host, puri.port_no ? puri.port_no : SIP_PORT, 0) >= 0)
	lua_pushboolean(L, 1);
      else
	lua_pushboolean(L, 0);
      lua_rawset(L, -3);
      lua_rawset(L, -3);
    }
  return 1;
}

/* does not check user. See ENABLE_USER_CHECK in modules/rr/loose.c:is_myself() */
/* look into the aliases */
static int l_siplua_isMyself(lua_State *L)
{
  struct sip_uri puri;
  size_t len;
  int ret;

  memset(&puri, '\0', sizeof(puri));
  puri.host.s = (char *)luaL_checklstring(L, 1, &len);
  puri.host.len = len;
  puri.port_no = luaL_checkinteger(L, 2);
  set_sip_defaults(puri.port_no, puri.proto);
  ret = check_self(&puri.host, puri.port_no, puri.proto);
  if (!ret)
    lua_pushnil(L);
  else
    lua_pushboolean(L, 1);
  return 1;
}

/* Similar to isMyself, but without taking a look into the aliases */
static int l_siplua_grepSockInfo(lua_State *L)
{
  struct sip_uri puri;
  size_t len;
  struct socket_info *si;

  memset(&puri, '\0', sizeof(puri));
  puri.host.s = (char *)luaL_checklstring(L, 1, &len);
  puri.host.len = len;
  puri.port_no = luaL_checkinteger(L, 2);
  set_sip_defaults(puri.port_no, puri.proto);
  si = grep_sock_info(&puri.host, puri.port_no, puri.proto);
  if (!si)
    lua_pushnil(L);
  else
    {
      lua_newtable(L);
      lua_pushliteral(L, "name");
      lua_pushlstring(L, si->name.s, si->name.len);
      lua_rawset(L, -3);
      lua_pushliteral(L, "port");
      lua_pushinteger(L, si->port_no);
      lua_rawset(L, -3);
      if (si->adv_name_str.s)
	{
	  lua_pushliteral(L, "adv_name");
	  lua_pushlstring(L, si->adv_name_str.s, si->adv_name_str.len);
	  lua_rawset(L, -3);
	}
      if (si->adv_port)
	{
	  lua_pushliteral(L, "adv_port");
	  lua_pushinteger(L, si->adv_port);
	  lua_rawset(L, -3);
	}
    }
  return 1;
}

/*
 * FIXME: Don't work and returns false IPs. Cheers!
 * PS: Probably not in network host order.
 */
static int l_siplua_getSrcIp(lua_State *L)
{
  struct sipapi_object *o;
  struct sockaddr sa;
  char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

  o = luaL_checkudata(L, 1, "siplua.api");
  sa.sa_family = o->msg->rcv.src_ip.af;
  memcpy(sa.sa_data, &o->msg->rcv.src_ip.u, o->msg->rcv.src_ip.len);
  if (getnameinfo(&sa, sizeof(sa), hbuf, sizeof(hbuf), sbuf,
		  sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV))
    {
      siplua_log(L_DBG, "could not get numeric hostname\n");
      lua_pushnil(L);
    }
  else
    {
      siplua_log(L_DBG, "host=%s, serv=%s\n", hbuf, sbuf);
      lua_pushstring(L, hbuf);
    }
  return 1;
}

/*
 * FIXME: Don't work and returns false IPs. Cheers!
 * PS: Probably not in network host order.
 */
static int l_siplua_getDstIp(lua_State *L)
{
  struct sipapi_object *o;
  struct sockaddr sa;
  char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

  o = luaL_checkudata(L, 1, "siplua.api");
  sa.sa_family = o->msg->rcv.dst_ip.af;
  memcpy(sa.sa_data, &o->msg->rcv.dst_ip.u, o->msg->rcv.dst_ip.len);
  if (getnameinfo(&sa, sizeof(sa), hbuf, sizeof(hbuf), sbuf,
		  sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV))
    {
      siplua_log(L_DBG, "could not get numeric hostname\n");
      lua_pushnil(L);
    }
  else
    {
      siplua_log(L_DBG, "host=%s, serv=%s\n", hbuf, sbuf);
      lua_pushstring(L, hbuf);
    }
  return 1;
}

static int l_siplua_getStatus(lua_State *L)
{
  struct sipapi_object *o;

  o = luaL_checkudata(L, 1, "siplua.api");
  if (o->msg->first_line.type != SIP_REPLY)
    lua_pushnil(L);
  else
    lua_pushlstring(L,
		    o->msg->first_line.u.reply.status.s,
		    o->msg->first_line.u.reply.status.len);
  return 1;
}

static int l_siplua_getMethod(lua_State *L)
{
  struct sipapi_object *o;

  o = luaL_checkudata(L, 1, "siplua.api");
  if (o->msg->first_line.type != SIP_REQUEST)
    lua_pushnil(L);
  else
    lua_pushlstring(L,
		    o->msg->first_line.u.request.method.s,
		    o->msg->first_line.u.request.method.len);
  return 1;
}

static int l_siplua_AVP_set(lua_State *L)
{
  int name;
  int_str val;
  str s;
  int retval;
  int flags = 0;

  luaL_checkany(L, 1);
  luaL_checkany(L, 2);
  s.s = (char *) lua_tostring(L, 1);
  s.len = strlen(s.s);
  name = get_avp_id(&s);
  if (lua_type(L, 2) == LUA_TNUMBER)
    val.n = luaL_checkinteger(L, 2);
  else
    {
      val.s.s = (char *)luaL_checkstring(L, 2);
      val.s.len = strlen(val.s.s);
      flags |= AVP_VAL_STR;
    }
  retval = add_avp(flags, name, val);
  if (!retval)
    lua_pushboolean(L, 1);
  else
    lua_pushnil(L);
  return 1;
}

static int l_siplua_AVP_get(lua_State *L)
{
  struct usr_avp *first_avp;
  int name;
  str s;
  int_str val;
  int flags = 0;

  luaL_checkany(L, 1);
  s.s = (char *) lua_tostring(L, 1);
  s.len = strlen(s.s);
  name = get_avp_id(&s);
  first_avp = search_first_avp(flags, name, &val, NULL);
  if (first_avp != NULL)
    {
      if (is_avp_str_val(first_avp))
	  lua_pushlstring(L, val.s.s, val.s.len);
      else
	lua_pushinteger(L, val.n);
    }
  else
    lua_pushnil(L);
  return 1;
}

static int l_siplua_AVP_destroy(lua_State *L)
{
  struct usr_avp *first_avp;
  int name;
  str s;
  int_str val;
  int flags = 0;

  luaL_checkany(L, 1);
  s.s = (char *) lua_tostring(L, 1);
  s.len = strlen(s.s);
  name = get_avp_id(&s);
  first_avp = search_first_avp(flags, name, &val, NULL);
  if (first_avp != NULL)
    {
      destroy_avp(first_avp);
      lua_pushboolean(L, 1);
    }
  else
    lua_pushnil(L);
  return 1;
}

static int l_siplua_pseudoVar(lua_State *L)
{
  struct sipapi_object *o;
  const char *name;
  str s;
  pv_elem_t *model;
  int buf_size = 4096;
  char *out;

  o = luaL_checkudata(L, 1, "siplua.api");
  name = luaL_checkstring(L, 2);
  s.s = (char *)name;
  s.len = strlen(name);
  if (pv_parse_format(&s, &model) < 0)
    {
      lua_pushnil(L);
      return 1;
    }
  out = pkg_malloc(buf_size);
  if (!out)
    {
      pv_elem_free_all(model);
      return luaL_error(L, "Not enough memory");
    }
  if (pv_printf(o->msg, model, out, &buf_size) < 0)
    lua_pushnil(L);
  else
    lua_pushstring(L, out);
  pkg_free(out);
  pv_elem_free_all(model);
  return 1;
}

static int l_siplua_pseudoVarSet(lua_State *L)
{
  struct sipapi_object *o;
  const char *name;
  str s;
  pv_spec_t dspec;
  pv_value_t val;
  int retval;

  o = luaL_checkudata(L, 1, "siplua.api");
  name = luaL_checkstring(L, 2);
  s.s = (char *)name;
  s.len = strlen(name);
  if (!pv_parse_spec(&s, &dspec))
	  return luaL_error(L, "error in parsing pvar `%s'", name);
  if (!pv_is_w(&dspec))
    return luaL_error(L, "read only PV in left expression");
  luaL_checkany(L, 3);
  if (lua_type(L, 3) == LUA_TNIL)
    {
      val.flags = PV_VAL_NULL;
    }
  else if (lua_type(L, 3) == LUA_TNUMBER)
    {
      val.ri = luaL_checkinteger(L, 3);
      val.flags = PV_VAL_INT;
    }
  else
    {
      val.rs.s = (char *)luaL_checkstring(L, 3);
      val.rs.len = strlen(val.rs.s);
      val.flags = PV_VAL_STR;
    }
/*   siplua_log(L_ALERT, "dspec.setf(, , EQ_T, %.*s)", val.rs.len, val.rs.s); */
  retval = pv_set_value(o->msg, &dspec, EQ_T, &val);
  if (retval >= 0)
    lua_pushboolean(L, 1);
  else
    lua_pushnil(L);
  return 1;
}

static int l_siplua_scriptVarGet(lua_State *L)
{
  const char *name;
  str s;
  script_var_t *it;

  name = luaL_checkstring(L, 1);
  if (*name == '$')
    ++name;
  s.s = (char *)name;
  s.len = strlen(name);
  it = get_var_by_name(&s);
  if (!it)
    lua_pushnil(L);
  else
    {
      switch (it->v.flags)
	{
	case 0:
	  lua_pushinteger(L, it->v.value.n);
	  break;
	case VAR_VAL_STR:
	  lua_pushlstring(L, it->v.value.s.s, it->v.value.s.len);
	  break;
	}
    }
  return 1;
}

static int l_siplua_scriptVarSet(lua_State *L)
{
  const char *name;
  str s;
  int_str val;
  int flags = 0;
  script_var_t *it;

  name = luaL_checkstring(L, 1);
  if (*name == '$')
    ++name;
  s.s = (char *)name;
  s.len = strlen(name);
  switch (lua_type(L, 2))
    {
    case LUA_TNIL: /* no way currently exists to drop a script variable */
      /* well, set_var_value(it, NULL, 0) API exists but won't do anything useful */
      val.n = 0;
      break;
    case LUA_TNUMBER:
      val.n = luaL_checkinteger(L, 2);
      break;
    case LUA_TSTRING:
      flags = VAR_VAL_STR;
      val.s.s = (char *)luaL_checkstring(L, 2);
      val.s.len = strlen(val.s.s);
      break;
    default:
      return luaL_error(L, "scriptVarSet %s type value not supported",
			lua_typename(L, lua_type(L, 2)));
    }
  it = get_var_by_name(&s);
  if (!it)
    it = add_var(&s);
  if (!it)
    return luaL_error(L, "add_var of script variable `%s' failed", name);
  if (set_var_value(it, &val, flags))
    lua_pushboolean(L, 1);
  else
    lua_pushboolean(L, 0);
  return 1;
}

static int l_siplua_add_lump_rpl(lua_State *L)
{
  struct sipapi_object *o;
  const char *name;
  size_t len;

  o = luaL_checkudata(L, 1, "siplua.api");
  name = luaL_checklstring(L, 2, &len);
  add_lump_rpl(o->msg, (char *)name, len, LUMP_RPL_HDR);
  return 1;
}

static int lua_do_action(lua_State *L, struct sip_msg* msg,
  struct action *act, cmd_export_t *cmd, int *retval)
{
  void* cmdp[MAX_CMD_PARAMS];
  pv_value_t tmp_vals[MAX_CMD_PARAMS];
  int i;
  struct cmd_param *param;
  gparam_p gp;

  if (fix_cmd(cmd->params, act->elem) < 0) {
    LM_ERR("Failed to fix command <%s>\n", cmd->name);
    return luaL_error(L, "failed to fix command");
  }

  if (get_cmd_fixups(msg, cmd->params, act->elem, cmdp, tmp_vals) < 0) {
    LM_ERR("Failed to get fixups for command <%s>\n", cmd->name);
    return luaL_error(L, "failed to get fixups for command");
  }

  *retval = cmd->function(msg,
    cmdp[0],cmdp[1],cmdp[2],
    cmdp[3],cmdp[4],cmdp[5],
    cmdp[6],cmdp[7]);

  for (param=cmd->params, i=1; param->flags; param++, i++) {
    gp = (gparam_p)act->elem[i].u.data;
    if (!gp)
      continue;

    if (param->free_fixup && param->free_fixup(&cmdp[i-1]) < 0) {
      LM_ERR("Failed to free fixup for param [%d]\n", i);
      return luaL_error(L, "failed to free fixups");
    }

    if (param->flags & CMD_PARAM_REGEX && gp->type != GPARAM_TYPE_PVS) {
      regfree((regex_t*)cmdp[i-1]);
      pkg_free(cmdp[i-1]);
    }
  }

  return 1;
}

static int l_siplua_moduleFunc(lua_State *L)
{
  struct sipapi_object *o;
  const char *func;
  int n, nargs;
  cmd_export_t *exp_func_struct;
  action_elem_t elems[MAX_ACTION_ELEMS];
  const char *msg;
  int i;
  struct action *act;
  int retval, rc;
  pv_spec_t *specs[MAX_CMD_PARAMS];
  struct cmd_param *param;
  char *largs[MAX_CMD_PARAMS];
  str s;

  o = luaL_checkudata(L, 1, "siplua.api");
  func = luaL_checkstring(L, 2);
  n = lua_gettop(L);
  nargs = n - 2;
  if (n - 1 > MAX_ACTION_ELEMS)
    return luaL_error(L, "function '%s' called with too many arguments [%d > %d]",
	       func, nargs, MAX_ACTION_ELEMS - 1);

  exp_func_struct = find_cmd_export_t((char *)func, 0);
  if (!exp_func_struct)
    return luaL_error(L, "function '%s' called, but not available", func);

  elems[0].type = CMD_ST;
  elems[0].u.data = exp_func_struct;

  for (i = 0; i < nargs; ++i) {
    if (lua_isnil(L, 3 + i)) {
      elems[i+1].type = NULLV_ST;
      largs[i] = NULL;
    } else {
      largs[i] = (char*)lua_tostring(L, 3 + i);
      if (!largs[i]) {
	      msg = lua_pushfstring(L, "%s expected, got %s",
				lua_typename(L, LUA_TSTRING), luaL_typename(L, 3 + i));
	      return luaL_argerror(L, 3 + i, msg);
	    }
      elems[i+1].type = NOSUBTYPE;
    }
    specs[i] = NULL;
  }

  retval = check_cmd_call_params(exp_func_struct, elems, nargs);
  if (retval == -1 || retval == -2)
      return luaL_error(L, "to few or too many parameters for function '%s'", func);
  else if (retval == -3)
      return luaL_error(L, "mandatory parameter ommited for function '%s'", func);

  for (param=exp_func_struct->params, i=1; param->flags; param++, i++) {
    if (!largs[i-1])
      continue;

    if (param->flags & CMD_PARAM_INT) {
      elems[i].type = NUMBER_ST;
      s.s = largs[i-1];
      s.len =  strlen(s.s);
      if (str2sint(&s, (int*)&elems[i].u.number) < 0)
        return luaL_error(L, "parameter [%d] should be an integer", i);
    } else if (param->flags & (CMD_PARAM_STR | CMD_PARAM_REGEX)) {
        elems[i].type = STR_ST;
        elems[i].u.data = largs[i-1];
    } else if (param->flags & CMD_PARAM_VAR) {
        elems[i].type = SCRIPTVAR_ST;
        specs[i-1] = pkg_malloc(sizeof *specs[i]);
        if (!specs[i-1]) {
          LM_ERR("oom\n");
          return luaL_error(L, "out of pkg memory");
        }
        s.s = largs[i-1];
        s.len = strlen(s.s);
        if (pv_parse_spec(&s, specs[i-1]) == NULL)
          return luaL_error(L, "unknown script variable '%s'", largs[i-1]);
        elems[i].u.data = specs[i-1];
    }
  }

  act = mk_action(CMD_T, nargs + 1, elems, 0, "lua");
  if (!act)
    return luaL_error(L, "action structure could not be created. Error.");

  if ((rc = lua_do_action(L, o->msg, act, exp_func_struct, &retval)) != 1)
    return rc;

  for (i = 0; i < nargs; ++i)
    pv_spec_free(specs[i]);

  /* free the gparam_t structs allocated by fix_cmd() */
  for (i=1; i < MAX_ACTION_ELEMS; i++)
    if (act->elem[i].u.data)
      pkg_free(act->elem[i].u.data);

  pkg_free(act);

  lua_pushinteger(L, retval);
  return 1;
}

static const struct luaL_Reg siplua_api_mylib [] =
  {
    {"getType", l_siplua_getType},
    {"getURI_User", l_siplua_getURI_User},
    {"getExpires", l_siplua_getExpires},
    {"getHeader", l_siplua_getHeader},
    {"getContact", l_siplua_getContact},
    {"getRoute", l_siplua_getRoute},
    {"isMyself", l_siplua_isMyself},
    {"grepSockInfo", l_siplua_grepSockInfo},
    {"moduleFunc", l_siplua_moduleFunc},
    {"getStatus", l_siplua_getStatus},
    {"getMethod", l_siplua_getMethod},
    {"getSrcIp", l_siplua_getSrcIp},
    {"getDstIp", l_siplua_getDstIp},
    {"AVP_get", l_siplua_AVP_get},
    {"AVP_set", l_siplua_AVP_set},
    {"AVP_destroy", l_siplua_AVP_destroy},
    {"pseudoVar", l_siplua_pseudoVar},
    {"pseudoVarSet", l_siplua_pseudoVarSet},
    {"scriptVarGet", l_siplua_scriptVarGet},
    {"scriptVarSet", l_siplua_scriptVarSet},
    {"add_lump_rpl", l_siplua_add_lump_rpl},
    {NULL, NULL} /* sentinel */
  };

void siplua_register_api_cclosures(lua_State *L)
{
  lua_pushglobaltable(L);
  luaL_openlib(L, NULL, siplua_api_mylib, 0);
  lua_remove(L, -1);
}

/* SV *getStringFromURI(SV *self, enum xs_uri_members what) { */
/* 	struct sip_uri *myuri = sv2uri(self); */
/* 	str *ret = NULL; */

/* 	if (!myuri) { */
/* 		LM_ERR("Invalid URI reference\n"); */
/* 		ret = NULL; */
/* 	} else { */

/* 		switch (what) { */
/* 			case XS_URI_USER:	ret = &(myuri->user); */
/* 						break; */
/* 			case XS_URI_HOST:	ret = &(myuri->host); */
/* 						break; */
/* 			case XS_URI_PASSWD:	ret = &(myuri->passwd); */
/* 						break; */
/* 			case XS_URI_PORT:	ret = &(myuri->port); */
/* 						break; */
/* 			case XS_URI_PARAMS:	ret = &(myuri->params); */
/* 						break; */
/* 			case XS_URI_HEADERS:	ret = &(myuri->headers); */
/* 						break; */
/* 			case XS_URI_TRANSPORT:	ret = &(myuri->transport); */
/* 						break; */
/* 			case XS_URI_TTL:		ret = &(myuri->ttl); */
/* 						break; */
/* 			case XS_URI_USER_PARAM:	ret = &(myuri->user_param); */
/* 						break; */
/* 			case XS_URI_MADDR:	ret = &(myuri->maddr); */
/* 						break; */
/* 			case XS_URI_METHOD:	ret = &(myuri->method); */
/* 						break; */
/* 			case XS_URI_LR:		ret = &(myuri->lr); */
/* 						break; */
/* 			case XS_URI_R2:		ret = &(myuri->r2); */
/* 						break; */
/* 			case XS_URI_TRANSPORT_VAL:	ret = &(myuri->transport_val); */
/* 						break; */
/* 			case XS_URI_TTL_VAL:	ret = &(myuri->ttl_val); */
/* 						break; */
/* 			case XS_URI_USER_PARAM_VAL:	ret = &(myuri->user_param_val); */
/* 						break; */
/* 			case XS_URI_MADDR_VAL:	ret = &(myuri->maddr_val); */
/* 						break; */
/* 			case XS_URI_METHOD_VAL:	ret = &(myuri->method_val); */
/* 						break; */
/* 			case XS_URI_LR_VAL:	ret = &(myuri->lr_val); */
/* 						break; */
/* 			case XS_URI_R2_VAL:	ret = &(myuri->r2_val); */
/* 						break; */

/* 			default:	LM_INFO("Unknown URI element" */
/* 						" requested: %d\n", what); */
/* 					break; */
/* 		} */
/* 	} */

/* 	if ((ret) && (ret->len)) { */
/* 		return sv_2mortal(newSVpv(ret->s, ret->len)); */
/* 	} else { */
/* 		return &PL_sv_undef; */
/* 	} */
/* } */
