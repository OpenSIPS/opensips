/*
 *
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
int warn_missing_free_fixup = 1;
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
  { "lua_exec", (cmd_function)siplua_exec1, 1, NULL, 0, REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE },
  { "lua_exec", (cmd_function)siplua_exec2, 2, NULL, 0, REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE },
  { "lua_meminfo", (cmd_function)siplua_meminfo, 0, NULL, 0, REQUEST_ROUTE | FAILURE_ROUTE | ONREPLY_ROUTE | BRANCH_ROUTE },
  { 0, 0, 0, 0, 0, 0 }
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
  { "luafilename", STR_PARAM, &luafilename},
  { "lua_user_debug", INT_PARAM, &lua_user_debug},
  { "warn_missing_free_fixup", INT_PARAM, &warn_missing_free_fixup},
  { "lua_allocator", STR_PARAM, &lua_allocator},
  { "lua_auto_reload", INT_PARAM, &lua_auto_reload},
  { 0, 0, 0 }
};

/*
 * Exported MI functions
 */
static mi_export_t mi_cmds[] = {
  { "lua_reload", 0,siplua_mi_reload, 0, 0, 0 },
  { "bla" , 0,siplua_mi_bla, 0, 0, 0 },
  { "watch", 0,siplua_mi_watch, 0, 0, 0 },
  { 0, 0, 0, 0, 0, 0 }
};

/*
 * Module interface
 */
struct module_exports exports = {
  "lua",
  MODULE_VERSION,
  RTLD_NOW | RTLD_GLOBAL,
  cmds,		/* Exported functions */
  params,	/* Exported parameters */
  0,		/* exported statistics */
  mi_cmds,	/* exported MI functions */
  0,		/* exported pseudo-variables */
  0,		/* extra processes */
  mod_init,	/* module initialization function */
  0,		/* response function */
  destroy,	/* destroy function */
  child_init	/* child initialization function */
};

static int child_init(int rank)
{
  siplua_log(L_INFO, "child_init");
  if (sipstate_open(lua_allocator))
    {
      siplua_log(L_ERR, "failed to initialize siplua's Lua state");
      return -1;
    }

  if (sipstate_load(luafilename))
    {
      siplua_log(L_ERR, "failed to load siplua's file %s", luafilename);
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

  siplua_log(L_INFO, "mod_init");

  /* load the SL API */
  if (load_sl_api(&slb)!=0) {
    siplua_log(L_CRIT, "can't load SL API\n");
    return -1;
  }

  if (sipwatch_create_object())
    {
      siplua_log(L_CRIT, "failed to initialized siplua's watch object");
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
  siplua_log(L_INFO, "destroy");
}
