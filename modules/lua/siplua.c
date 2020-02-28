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

#include "../../sr_module.h"
#include "../sl/sl_api.h"

#include "siplua.h"
#include "sipluafunc.h"
#include "sipluami.h"
#include "sipwatch.h"
#include "sipstate.h"

char *luafilename = "";
int lua_user_debug = 1;
char *lua_allocator = "opensips";
int lua_auto_reload = 0;

static void destroy(void);
static int child_init(int rank);
static int mod_init(void);

struct sl_binds slb;

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
  {"lua_exec", (cmd_function)siplua_exec, {
    {CMD_PARAM_STR,0,0},
    {CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
    REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE | LOCAL_ROUTE},
  {"lua_meminfo", (cmd_function)siplua_meminfo, {{0,0,0}},
    REQUEST_ROUTE},
  {0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
  { "luafilename", STR_PARAM, &luafilename},
  { "lua_user_debug", INT_PARAM, &lua_user_debug},
  { "lua_allocator", STR_PARAM, &lua_allocator},
  { "lua_auto_reload", INT_PARAM, &lua_auto_reload},
  { 0, 0, 0 }
};

static mi_export_t mi_cmds[] = {
  { "watch", 0,0,0, {
    {siplua_mi_watch, {0}},
    {siplua_mi_watch_2, {"action", "extension", 0}},
    {EMPTY_MI_RECIPE}}
  },
  {EMPTY_MI_EXPORT}
};

/*
 * Module interface
 */
struct module_exports exports = {
  "lua",
  MOD_TYPE_DEFAULT,/* class of this module */
  MODULE_VERSION,
  RTLD_NOW | RTLD_GLOBAL,
  0,
  NULL,     /* OpenSIPS module dependencies */
  cmds,		/* Exported functions */
  0,		/* Exported async functions */
  params,	/* Exported parameters */
  0,		/* exported statistics */
  mi_cmds,	/* exported MI functions */
  0,		/* exported pseudo-variables */
  0,    /* exported transformations */
  0,		/* extra processes */
  0,		/* module pre-initialization function */
  mod_init,	/* module initialization function */
  0,		/* response function */
  destroy,	/* destroy function */
  child_init,	/* child initialization function */
  0				/* reload confirm function */
};

static int child_init(int rank)
{
  siplua_log(L_INFO, "child_init\n");
  if (sipstate_open(lua_allocator))
    {
      siplua_log(L_ERR, "failed to initialize siplua's Lua state\n");
      return -1;
    }

  if (sipstate_load(luafilename))
    {
      siplua_log(L_ERR, "failed to load siplua's file %s\n", luafilename);
      sipstate_close();
      return -1;
    }
  return 0;
}

/*
 * mod_init
 * Called by openser at init time
 */
static int mod_init(void)
{
  int ret = 0;

  siplua_log(L_INFO, "mod_init\n");

  /* load the SL API */
  if (load_sl_api(&slb)!=0) {
    siplua_log(L_CRIT, "can't load SL API\n");
    return -1;
  }

  if (sipwatch_create_object())
    {
      siplua_log(L_CRIT, "failed to initialized siplua's watch object\n");
      return -1;
    }
  return ret;
}

/*
 * destroy
 * called by openser at exit time
 */
static void destroy(void)
{
  siplua_log(L_INFO, "destroy\n");
}
