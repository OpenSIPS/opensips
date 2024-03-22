#ifndef HTTP2_SERVER
#define HTTP2_SERVER

#include <pthread.h>
#include <nghttp2/nghttp2.h>
#include "../../str.h"

struct h2_response {
	pthread_mutex_t mutex;
	pthread_cond_t cond;

	int code;
	nghttp2_nv *hdrs;
	int hdrs_len;
	str body;
};

extern int h2_response_timeout;

extern struct h2_response **h2_response, *ng_h2_response;

extern unsigned int h2_port;
extern char *h2_ip;
extern str h2_tls_cert;
extern str h2_tls_key;

void http2_server(int rank);
void h2_response_clean(void);

#endif /* HTTP2_SERVER */
