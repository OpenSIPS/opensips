#ifndef HTTP2_SERVER
#define HTTP2_SERVER

#include "../../str.h"

extern unsigned int h2_port;
extern char *h2_ip;
extern str h2_tls_cert;
extern str h2_tls_key;

void http2_server(int rank);

#endif /* HTTP2_SERVER */
