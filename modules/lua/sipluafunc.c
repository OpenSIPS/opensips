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
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>

#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
/* #include "../../data_lump.h" */
/* #include "../../parser/parse_param.h" */
/* #include "../../parser/msg_parser.h" */
/* #include "../../dprint.h" */
/* #include "../../action.h" */
/* #include "../../config.h" */
#include "../../parser/parse_uri.h"

#include "../sl/sl_api.h"

#include "siplua.h"
#include "sipluafunc.h"
#include "sipapi.h"
#include "sipstate.h"

#ifndef LM_GEN1
# define LM_GEN1 LOG	/* 1.3.x backward compatibility */
#endif /* !LM_GEN1 */

void siplua_log(int lev, const char *format, ...)
{
  va_list ap;
  char *ret;
  int priority;
  int rc;

  if (!format)
    return;
  if (!(is_printable(lev) | lua_user_debug))
    return;
  va_start(ap, format);
  rc = vasprintf(&ret, format, ap);
  va_end(ap);
  if (rc < 0)
    return;
  LM_GEN1(lev, "siplua: %s", ret);
  if (lua_user_debug)
    {
      switch (lev)
	{
	case L_ALERT: priority = LOG_ALERT; break;
	case L_CRIT: priority = LOG_CRIT; break;
	case L_ERR: priority = LOG_ERR; break;
	case L_WARN: priority = LOG_WARNING; break;
	case L_NOTICE: priority = LOG_NOTICE; break;
	case L_INFO: priority = LOG_INFO; break;
	case L_DBG: priority = LOG_DEBUG; break;
	default: /* should not happen, no execution path permits it */
	  priority = LOG_ERR;
	}
      syslog(LOG_USER | priority, "siplua: %s", ret);
    }
  free(ret);
}

void siplua_notice(int local, const char *format, ...)
{
  va_list ap;

  if (!(local >= 0 && local <= 7))
    return;
  va_start(ap, format);
  vsyslog((LOG_LOCAL0 + local) | LOG_NOTICE, format, ap);
  va_end(ap);
}

int siplua_exec(struct sip_msg* _msg, const str *fnc, const str *mystr)
{
  str reason;
  int ret;

  if ((_msg->first_line).type != SIP_INVALID)
    if (parse_headers(_msg, ~0, 0) < 0) {
		LM_ERR("failed to parse message\n");
		return -1;
	}
  switch ((_msg->first_line).type) {
  case SIP_REQUEST:
    if (parse_sip_msg_uri(_msg) < 0) {
      LM_ERR("failed to parse Request-URI\n");

      reason.s = "Bad Request-URI";
      reason.len = sizeof("Bad Request-URI")-1;
      if (slb.reply(_msg, 400, &reason, NULL) == -1) {
	LM_ERR("failed to send reply\n");
      }
      return -1;
    }
    break;
  case SIP_REPLY:
    break;
  default:
    LM_ERR("invalid firstline\n");
    return -1;
  }

  ret = sipstate_call(_msg, fnc, mystr);
  return (ret>=0)?1:-1;
}

int siplua_meminfo(struct sip_msg *msg)
{
  struct mem_info info;

  shm_info(&info);
  siplua_log(L_INFO, "free/%d used/%d real_used/%d max_used/%d min_frag/%d total_frags/%d\n",
	     info.free, info.used, info.real_used, info.max_used, info.min_frag, info.total_frags);
  return -1;
}
