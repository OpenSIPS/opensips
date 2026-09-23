/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "../parser/sdp/sdp.h"

#include "../cachedb/test/test_cachedb.h"
#include "../lib/test/test_csv.h"
#include "../mem/test/test_malloc.h"
#include "../str.h"

#include "../context.h"
#include "../dprint.h"
#include "../globals.h"
#include "../lib/list.h"
#include "../sr_module.h"
#include "../sr_module_deps.h"

#include "../test/fuzz/fuzz_standalone.h"

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
  if (size <= 1) {
    return 0;
  }

  str sdp_body = { (char*)data, (int)size };
  sdp_info_t* sdp = new_sdp();
  if (sdp) {
    str cnt_disp = {NULL, 0};
    parse_sdp_session(&sdp_body, 0, &cnt_disp, sdp);
    free_sdp(sdp);
  }
  
  return 0;
}
