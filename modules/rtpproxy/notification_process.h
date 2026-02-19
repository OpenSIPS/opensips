#pragma once

enum inp_op {NPROC_CHECK = 0, NPROC_SET};

int rtpproxy_is_nproc(enum inp_op);

typedef int (*rtpproxy_is_nproc_t)(enum inp_op);
