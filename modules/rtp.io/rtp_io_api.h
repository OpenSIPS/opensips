#pragma once

struct rtpp_notify_cfg;

typedef int (*rtp_io_getchildsock_t)(int);
typedef int (*rtp_io_getrnsock_t)(struct rtpp_notify_cfg *);
