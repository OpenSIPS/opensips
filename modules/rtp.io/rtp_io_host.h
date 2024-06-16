#pragma once

extern int *rtpp_host_process_no;

int init_rtpp_host(void);
void rtpproxy_host_process(int);
void ipc_shutdown_rtpp_host(int, void *);
