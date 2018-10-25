/*
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * History:
 * ---------
 *  2013-10-31  first version (shimaore)
 */


#include "../../str.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../config.h"
#include "../../globals.h"
#include "../../locking.h"

#include "http_fnc.h"

extern str http_root;

gen_lock_t* mi_json_lock;

int mi_json_init_async_lock(void)
{
  mi_json_lock = lock_alloc();
  if (mi_json_lock==NULL) {
    LM_ERR("failed to create lock\n");
    return -1;
  }
  if (lock_init(mi_json_lock)==NULL) {
    LM_ERR("failed to init lock\n");
    return -1;
  }
  return 0;
}

void mi_json_destroy_async_lock(void)
{
  if (mi_json_lock) {
    lock_destroy(mi_json_lock);
    lock_dealloc(mi_json_lock);
  }
}

static void mi_json_close_async(mi_response_t *resp, struct mi_handler *hdl, int done)
{
  mi_response_t *shm_resp;
  gen_lock_t* lock;
  mi_json_async_resp_data_t *async_resp_data;
  int x;

  if (hdl==NULL) {
    LM_CRIT("null mi handler\n");
    return;
  }

  LM_DBG("resp [%p], hdl [%p], hdl->param [%p] and done [%u]\n",
    resp, hdl, hdl->param, done);

  if (!done) {
    /* we do not pass provisional stuff (yet) */
    if (resp) free_mi_response( resp );
    return;
  }

  async_resp_data = (mi_json_async_resp_data_t*)(hdl+1);
  lock = async_resp_data->lock;

  if (resp==NULL || (shm_resp=shm_clone_mi_response(resp))==NULL) {
    LM_WARN("Unable to process async reply [%p]\n", resp);
    /* mark it as invalid */
    shm_resp = MI_JSON_ASYNC_FAILED;
  }
  if (resp) free_mi_response(resp);

  lock_get(lock);
  if (hdl->param==NULL) {
    hdl->param = shm_resp;
    x = 0;
  } else {
    x = 1;
  }
  LM_DBG("shm_resp [%p], hdl [%p], hdl->param [%p]\n",
    shm_resp, hdl, hdl->param);
  lock_release(lock);

  if (x) {
    if (shm_resp!=MI_JSON_ASYNC_FAILED)
      free_shm_mi_response(shm_resp);
    shm_free(hdl);
  }


  return;
}

static inline struct mi_handler* mi_json_build_async_handler(void)
{
  struct mi_handler *hdl;
  mi_json_async_resp_data_t *async_resp_data;
  unsigned int len;

  len = sizeof(struct mi_handler)+sizeof(mi_json_async_resp_data_t);
  hdl = (struct mi_handler*)shm_malloc(len);
  if (hdl==NULL) {
    LM_ERR("oom\n");
    return NULL;
  }

  memset(hdl, 0, len);
  async_resp_data = (mi_json_async_resp_data_t*)(hdl+1);

  hdl->handler_f = mi_json_close_async;
  hdl->param = NULL;

  async_resp_data->lock = mi_json_lock;

  LM_DBG("hdl [%p], hdl->param [%p], mi_json_lock=[%p]\n",
    hdl, hdl->param, async_resp_data->lock);

  return hdl;
}

mi_response_t *mi_http_run_mi_cmd(struct mi_cmd *cmd, char *req_method,
                mi_request_t *request, union sockaddr_union *cl_socket,
                struct mi_handler **async_hdl)
{
  mi_response_t *resp = NULL;
  struct mi_handler *hdl = NULL;

  LM_DBG("got command=%s\n", req_method);

  if (cmd && cmd->flags & MI_ASYNC_RPL_FLAG) {
    LM_DBG("command=%s is async\n", req_method);
    /* We need to build an async handler */
    hdl = mi_json_build_async_handler();
    if (hdl==NULL) {
      LM_ERR("failed to build async handler\n");
      goto out;
    }
  }

  resp = handle_mi_request(request, cmd, hdl);
  LM_DBG("got mi response = [%p]\n", resp);

out:
  *async_hdl = hdl;
  trace_json_request(cmd, req_method, cl_socket, request->params);
  return resp;
}
