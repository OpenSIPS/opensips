#pragma once

struct rtpp_cfg;

struct rtpp_env {
    union {
        const char *cp;
        char *_cp;
    };
    enum {env_static=0, env_heap=1} atype;
    struct rtpp_env *next;
};

struct rtpp_env_hd {
    int len;
    const struct rtpp_env *first;
    union {
        const struct rtpp_env *last;
        struct rtpp_env *_last;
    };
};

struct rtp_io_socks {
    int n;
    int holder[];
};

struct rtp_io_desc {
    struct rtpp_cfg *rtpp_cfsp;
    struct rtpp_env_hd env;
    struct rtp_io_socks *socks;
};

extern struct rtp_io_desc *rpi_descp;
