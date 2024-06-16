#pragma once

struct rtpp_env;
struct rtpp_env_hd;

struct rtpp_env *rtp_io_env_asprintf(const char *, ...);
struct rtpp_env *rtp_io_env_strref(const char *);

void rtp_io_env_append(struct rtpp_env_hd *, struct rtpp_env *);
const char *const * rtp_io_env_gen_argv(struct rtpp_env_hd *, int *);

int rtp_io_close_serv_socks(void);
int rtp_io_close_cnlt_socks(void);
