/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "../parser/msg_parser.h"
#include "../parser/sdp/sdp.h"

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
  sdp_info_t *sdp;
  sdp_session_cell_t *session;
  int session_num, stream_num;

  if (size <= 1) {
    return 0;
  }

  struct sip_msg msg = {};
  msg.buf = (char *)data;
  msg.len = size;

  if (parse_msg(msg.buf, msg.len, &msg) == 0) {
    sdp = parse_sdp(&msg);
    if (sdp != NULL) {
      for (session_num = 0;
           (session = get_sdp_session(sdp, session_num)) != NULL;
           session_num++) {
        for (stream_num = 0;
             get_sdp_stream(sdp, session_num, stream_num) != NULL;
             stream_num++) {
        }
      }
    }
  }

  free_sip_msg(&msg);
  return 0;
}
