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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../mi/mi.h"

#include "sipwatch.h"
#include "sipluami.h"

mi_response_t *siplua_mi_watch(const mi_params_t *params,
                struct mi_handler *async_hdl)
{
  int i;
  mi_response_t *resp;
  mi_item_t *resp_arr;

  resp = init_mi_result_object(&resp_arr);
  if (!resp)
    return 0;

  sipwatch_lock();
  for (i = 0; i < siplua_watch->nb; ++i)
    if (add_mi_string_fmt(resp_arr, MI_SSTR("extension"), "%s",
      siplua_watch->ext[i].str) < 0) {
      sipwatch_unlock();
      free_mi_response(resp);
      return 0;
    }

  sipwatch_unlock();
  return resp;
}

mi_response_t *siplua_mi_watch_2(const mi_params_t *params,
                struct mi_handler *async_hdl)
{
  str action, extension;

  if (get_mi_string_param(params, "action", &action.s, &action.len) < 0)
    return init_mi_param_error();
  if (get_mi_string_param(params, "extension", &extension.s, &extension.len) < 0)
    return init_mi_param_error();

  if (action.len == 3 && !strncmp("add", action.s, action.len))
      sipwatch_add(extension.s, extension.len);
  else if (action.len == 6 && !strncmp("delete", action.s, action.len))
      sipwatch_delete(extension.s, extension.len);
  else
    return init_mi_error(400, MI_SSTR("Bad action, should be 'add' or 'delete'"));

  return init_mi_result_ok();
}
