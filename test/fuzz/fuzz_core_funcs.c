/*
 * Copyright (c) 2023 Sippy Software, Inc., http://www.sippysoft.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <assert.h>

#include "../parser/sdp/sdp.h"

#include "../cachedb/test/test_cachedb.h"
#include "../lib/test/test_csv.h"
#include "../mem/test/test_malloc.h"
#include "../str.h"

#include "../dprint.h"
#include "../globals.h"
#include "../cmds.h"
#include "../lib/list.h"
#include "../sr_module.h"
#include "../sr_module_deps.h"
#include "../socket_info.h"
#include "../msg_translator.h"

#include "../test/fuzz/fuzz_standalone.h"

static pv_spec_p pv_specs;
static int nspecs;

__attribute__((constructor)) void
pv_specs_fuzz_init()
{
  for (int i = 0; _pv_names_table[i].name.s != NULL; i++) {
    char namebuf[32];
    str name = {.s = namebuf};
    pv_specs = realloc(pv_specs, sizeof(pv_specs[0]) * (nspecs + 1));
    assert(pv_specs != NULL);
    name.len = sprintf(name.s, "$%s", _pv_names_table[i].name.s);
    if (pv_parse_spec(&name, &(pv_specs[nspecs])) == NULL)
      continue;
    pv_specs[nspecs].pvp.pvn.type = PV_NAME_PVAR;
    pv_specs[nspecs].pvp.pvn.u.dname = (void*)&pv_specs[nspecs];
    nspecs += 1;
  }
}

static const int
count_noparam_cmds()
{
  int r = 0;

  for (int i = 0; core_cmds[i].name != NULL; i++) {
    if (core_cmds[i].params[0].flags == 0)
      r += 1;
  }
  return (r);
}

const cmd_export_t *
pick_some_command(uint8_t datap)
{
  const int ncmds = count_noparam_cmds();
  int i, r, idx = datap % (ncmds + 1);

  if (idx == ncmds)
      return (0);
  for (i = r = 0; core_cmds[i].name != NULL; i++) {
    if (core_cmds[i].params[0].flags != 0)
      continue;
    if (r == idx)
      return &core_cmds[i];
    r += 1;
  }
  abort();
}

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
  str buf;
  const int ncmds = count_noparam_cmds();
  struct socket_info si = {};

  if (size <= ncmds + 1) {
    return 0;
  }

  struct sip_msg msg = {};
  msg.buf = (char *)data;
  msg.len = size - ncmds;

  if (parse_msg(msg.buf, msg.len, &msg) != 0)
    goto out;
  if (msg.via1 == NULL || msg.via1->error != PARSE_OK)
    goto out;
  msg.rcv.src_ip.af = AF_INET;
  msg.rcv.src_port = (unsigned short)66666;
  for (int i = 0; i < ncmds; i++) {
    const cmd_export_t *cmd = pick_some_command(data[size - ncmds + i]);
    if (cmd == NULL)
      continue;
    cmd->function(&msg, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  }
  for (int i = 0; i < nspecs; i++) {
    pv_value_t v = {};

    pv_specs[i].getf(&msg, &pv_specs[i].pvp, &v);
  }
  buf.s = build_req_buf_from_sip_req(&msg, (unsigned int*)&buf.len,
    &si, PROTO_UDP, NULL, 0 /*flags*/);
  if (buf.s)
    pkg_free(buf.s);
out:
  free_sip_msg(&msg);
  return 0;
}
