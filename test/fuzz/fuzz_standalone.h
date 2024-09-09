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

#pragma once

#include <assert.h>
#if defined(FUZZ_STANDALONE)
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#endif /* FUZZ_STANDALONE */

#include "../../context.h"
#include "../../core_stats.h"
#include "../../dset.h"

/* Dummy */
const struct scm_version core_scm_ver;

#if defined(__linux__)
static int optreset; /* Not present in linux */
#endif

static struct opt_save {
    char *optarg;
    int optind;
    int optopt;
    int opterr;
    int optreset;
} opt_save;

#define OPT_SAVE() (opt_save = (struct opt_save){optarg, optind, optopt, opterr, optreset})
#define OPT_RESTORE() ({ \
    optarg = opt_save.optarg; \
    optind = opt_save.optind; \
    optopt = opt_save.optopt; \
    opterr = opt_save.opterr; \
    optreset = opt_save.optreset; \
})

__attribute__((constructor (101))) void
opensips_fuzz_init()
{
  static stat_val bad_URIs_c;
  static stat_val bad_msg_hdr_c;
  static stat_var _bad_URIs = {.u.val = &bad_URIs_c};
  static stat_var _bad_msg_hdr = {.u.val = &bad_msg_hdr_c};

  bad_URIs = &_bad_URIs;
  bad_msg_hdr = &_bad_msg_hdr;

  assert(init_dset() == 0);
  assert(ensure_global_context() == 0);
  *log_level = L_CRIT;
}

#if defined(FUZZ_STANDALONE)
int LLVMFuzzerTestOneInput(const char *data, size_t size);

int
main(int argc, char *argv[])
{
    int fflag, ch, fd;
    char buf[1024], *cp;
    size_t size;

    fflag = 0;
    OPT_SAVE();
    while ((ch = getopt(argc, argv, "f")) != -1) {
        switch (ch) {
        case 'f':
            fflag = 1;
            break;
        default:
            return (-1);
        }
    }
    argc -= optind;
    argv += optind;
    OPT_RESTORE();

    assert(argc == 1);
    if (fflag) {
        fd = open(argv[0], O_RDONLY, 0);
        assert(fd >= 0);
        size = read(fd, buf, sizeof(buf));
        assert(size > 0);
        close(fd);
        cp = buf;
    } else {
        cp = argv[0];
        size = strlen(cp);
    }
    LLVMFuzzerTestOneInput(cp, size);
    return (0);
}
#endif /* FUZZ_STANDALONE */
