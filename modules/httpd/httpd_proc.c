/*
 * Copyright (C) 2011-2012 VoIP Embedded Inc.
 *
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * History:
 * ---------
 *  2011-09-20  first version (osas)
 */


#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <grp.h>
#include <stdlib.h>

#ifdef LIBMICROHTTPD
#include <stdint.h>
#include <stdarg.h>
#include <microhttpd.h>
#endif

#include "../../pt.h"
#include "../../sr_module.h"
#include "../../str.h"
#include "../../ut.h"
#include "../../lib/sliblist.h"
#include "../../reactor_proc.h"
#include "httpd_load.h"
#include "httpd_proc.h"


extern int port;
extern str ip;
extern str buffer;
extern unsigned int hd_conn_timeout_s;
extern int post_buf_size;
extern str tls_cert_file;
extern str tls_key_file;
extern str tls_ciphers;
extern struct httpd_cb *httpd_cb_list;
static union sockaddr_union httpd_server_info;


extern int receive_buf_size;
extern char *httpd_receive_buff;
extern int httpd_receive_buff_pos;

static const str MI_HTTP_U_URL = str_init("<html><body>"
"Unable to parse URL!</body></html>");
static const str MI_HTTP_U_METHOD = str_init("<html><body>"
"Unsupported HTTP request!</body></html>");

static char * load_file(char * );

/**
 * Data structure to store inside elents of slinkedl_list list.
 */
typedef struct str_str {
	str key;
	str val;
} str_str_t;


#ifdef LIBMICROHTTPD
struct MHD_Daemon *dmn;

struct post_request {
	struct MHD_PostProcessor *pp;
	int status;
	enum HTTPD_CONTENT_TYPE content_type;
	enum HTTPD_CONTENT_TYPE accept_type;
	int content_len;
	slinkedl_list_t *p_list;
};
#endif


/**
 * Allocator for the slinkedl_list list.
 */
void *httpd_alloc(size_t size) { return pkg_malloc(size); }

/**
 * De-allocator for the slinkedl_list list.
 *
 * @param ptr The pointer to memory that we want to free up.
 */
void httpd_free(void *ptr) { pkg_free(ptr); return; }

/**
 * Function to extract data from an element of a slinkedl_list list.
 *
 * @param e_data Pointer to the data stored by the current
 *               element being processed (a str_str_t type).
 * @param data   Pointer to the key idetifier.
 * @param r_data Pointer where the value that we are looking for
 */
int httpd_get_val(void *e_data, void *data, void *r_data)
{
	str_str_t *kv = (str_str_t*)e_data;
	str *val = (str*)r_data;
	if (kv==NULL) {
		LM_ERR("null data\n");
	} else {
		if (strncmp(kv->key.s, data, kv->key.len)==0) {
			val->s = kv->val.s;
			val->len = kv->val.len;
			LM_DBG("DATA=[%p] [%p][%p] [%.*s]->[%.*s]\n",
				kv, kv->key.s, kv->val.s,
				kv->key.len, kv->key.s,
				kv->val.len, kv->val.s);
			return 1;
		}
	}
	return 0;
}

int httpd_merge_data(void *e_data, void *data, void *r_data)
{
	str_str_t *kv = (str_str_t*)e_data;
	if (kv==NULL) {
		LM_ERR("null data\n");
	} else {
		LM_DBG("data=[%p] [%p][%p] [%.*s]->[%.*s]\n",
			kv, kv->key.s, kv->val.s,
			kv->key.len, kv->key.s,
			kv->val.len, kv->val.s);
		if (httpd_receive_buff_pos + kv->val.len > receive_buf_size) {
			LM_ERR("Received too big HTTP request ( %d bytes ), increase receive_buf_size param value\n", httpd_receive_buff_pos + kv->val.len);
		} else {
			memcpy(httpd_receive_buff+httpd_receive_buff_pos,kv->val.s,kv->val.len);
			httpd_receive_buff_pos+=kv->val.len;
		}
	}
	return 0;
}

/**
 * Function to print data stored in  slinkedl_list list elemnts.
 * For debugging purposes only.
 */
/*
int httpd_print_data(void *e_data, void *data, void *r_data)
{
	str_str_t *kv = (str_str_t*)e_data;
	if (kv==NULL) {
		LM_ERR("null data\n");
	} else {
		LM_DBG("data=[%p] [%p][%p] [%.*s]->[%.*s]\n",
			kv, kv->key.s, kv->val.s,
			kv->key.len, kv->key.s,
			kv->val.len, kv->val.s);
	}
	return 0;
}
*/


/**
 * Function that retrieves the callback function that should
 * handle the current request.
 *
 * @param url Pointer to the root part of the HTTP URL.
 * @return    The callback function to handle the HTTP request.
 */
struct httpd_cb *get_httpd_cb(const char *url)
{
	int url_len;
	int index;
	struct httpd_cb *cb;
	str *http_root;

	if (!url) {
		LM_ERR("NULL URL\n"); return NULL;
	}
	url_len = strlen(url);
	if (url_len<=0) {
		LM_ERR("Invalid url length [%d]\n", url_len); return NULL;
	}
	if (url[0] != '/') {
		LM_ERR("URL starting with [%c] instead of'/'\n", *url);
		return NULL;
	}
	cb = httpd_cb_list;
	while(cb) {
		index = 1;
		http_root = cb->http_root;
		if (url_len - index < http_root->len) goto skip;
		if (strncmp(http_root->s, &url[index], http_root->len) != 0) goto skip;
		index += http_root->len;
		if (url_len - index == 0) return cb;
		if (url[index] == '/') return cb;
skip:
		cb = cb->next;
	}

	return NULL;
}

#ifdef LIBMICROHTTPD
/**
 * Handle regular POST data.
 *
 */
static MHD_RET post_iterator (void *cls,
		enum MHD_ValueKind kind,
		const char *key,
		const char *filename,
		const char *content_type,
		const char *transfer_encoding,
		const char *value, uint64_t off, size_t size)
{
	int key_len;
	struct post_request *pr;
	str_str_t *kv;
	char *p;

	LM_DBG("post_iterator: cls=%p, kind=%d key=[%p]->'%s'"
			" filename='%s' content_type='%s' transfer_encoding='%s'"
			" value=[%p]->'%s' off=%llu size=%zu\n",
			cls, kind, key, key,
			filename, content_type, transfer_encoding,
			value, value, (long long unsigned int)off, size);


	pr = (struct post_request*)cls;
	if (pr==NULL) {
		LM_CRIT("corrupted data: null cls\n");
		return MHD_NO;
	}

	if (off!=0) {
		if (size==0) {
			/* This is the last call post_iterator call
			 * before destroying the post_processor. */
			return MHD_YES;
		} else {
			LM_ERR("Trunkated data: post_iterator buffer to small!"
					" Increase post_buf_size value\n");
			pr->status = -1; return MHD_NO;
		}
	}

	if (key) {
		key_len = strlen(key);
		if (key_len==0) {
			LM_ERR("empty key\n");
			pr->status = -1; return MHD_NO;
		}
	} else {
		LM_ERR("NULL key\n");
		pr->status = -1; return MHD_NO;
	}

	if (filename) {
		LM_ERR("we don't support file uploading\n");
		pr->status = -1; return MHD_NO;
	}
	if (content_type) {
		LM_ERR("we don't support content_type\n");
		pr->status = -1; return MHD_NO;
	}
	if (transfer_encoding) {
		LM_ERR("we don't support transfer_encoding\n");
		pr->status = -1; return MHD_NO;
	}

	LM_DBG("[%.*s]->[%.*s]\n", key_len, key, (int)size, value);

	kv = (str_str_t*)slinkedl_append(pr->p_list,
						sizeof(str_str_t) + key_len + size);
	p = (char*)(kv + 1);
	kv->key.len = key_len; kv->key.s = p;
	memcpy(p, key, key_len);
	p += key_len;
	kv->val.len = size; kv->val.s = p;
	memcpy(p, value, size);
	LM_DBG("inserting element pr=[%p] pp=[%p] p_list=[%p]\n",
				pr, pr->pp, pr->p_list);

	return MHD_YES;
}

/**
 * Lookup for HTTP headers.
 *
 * @param cls   Pointer to store return data.
 * @param kind  Specifies the source of the key-value pairs that
 *              we are looking for in the HTTP protocol.
 * @param key   The key.
 * @param value The value.
 *
 * @return MHD_YES to continue iterating,
 *         MHD_NO to abort the iteration.
 */
MHD_RET getConnectionHeader(void *cls, enum MHD_ValueKind kind,
					const char *key, const char *value)
{
	struct post_request *pr = (struct post_request*)cls;
	str content_length;
	unsigned int len;
	char *p, bk;

	if (cls == NULL) {
		LM_ERR("Unable to store return data\n");
		return MHD_NO;
	}
	if (kind != MHD_HEADER_KIND) {
		LM_ERR("Got kind != MHD_HEADER_KIND\n");
		return MHD_NO;
	}

	if (strcasecmp("Accept", key) == 0) {
		LM_DBG("Accept=%s\n", value);
		if (strcasecmp("text/xml", value) == 0)
			pr->accept_type = HTTPD_TEXT_XML_CNT_TYPE;
		else if (strcasecmp("application/json", value) == 0)
			pr->accept_type = HTTPD_APPLICATION_JSON_CNT_TYPE;
		else
			pr->accept_type = HTTPD_UNKNOWN_CNT_TYPE;
		return MHD_YES;
	}
	if (strcasecmp("Content-Type", key) == 0) {
		LM_DBG("Content-Type=%s\n", value);
		/* extract only the mime */
		if ( (p=strchr(value, ';'))!=NULL ) {
			while( p>value && (*(p-1)==' ' || *(p-1)=='\t') ) p--;
			bk = *p;
			*p = 0;
		}
		if (strcasecmp("text/xml", value) == 0)
			pr->content_type = HTTPD_TEXT_XML_CNT_TYPE;
		else if (strncasecmp("application/json", value, 16) == 0)
			pr->content_type = HTTPD_APPLICATION_JSON_CNT_TYPE;
		else if (strncasecmp("text/html", value, 9) == 0)
			pr->content_type = HTTPD_TEXT_HTML_TYPE;
		else if (strncasecmp("text/plain", value, 10) == 0)
			pr->content_type = HTTPD_TEXT_PLAIN_TYPE;
		else {
			pr->content_type = HTTPD_UNKNOWN_CNT_TYPE;
			LM_ERR("Unexpected Content-Type=[%s]\n", value);
		}
		if (p) *p = bk;
		goto done;
	}
	if (strcasecmp("Content-Length", key) == 0) {
		LM_DBG("Content-Length=%s\n", value);
		content_length.s = (char*)value;
		content_length.len = strlen(value);
		if (str2int(&content_length, &len)<0) {
			LM_ERR("got bogus Content-Length=%s\n", value);
			pr->content_len = HTTPD_UNKNOWN_CONTENT_LEN;
		} else
			pr->content_len = len;
		goto done;
	}

	LM_DBG("key=[%s] value=[%s]\n", key, value);
	return MHD_YES;

done:
	if (pr->content_type && pr->content_len)
		return MHD_NO;
	else
		return MHD_YES;
}


/**
 * Performs lookup values for given keys.
 * For GET requests, we will use the libmicrohttpd's
 * internal API: MHD_lookup_connection_value().
 * For POST requests, we will retrieve the value from
 * the slinkedl_list that was created and populated by
 * the post_iterator().
 *
 * @param connection Pointer to the MHD_Connection
 * @param key        The key for which we need to retrieve
 *                   the value.
 * @param con_cls    This is a pointer to the slinkedl_list
 *                   that was passed back and forth via
 *                   several callback between the application
 *                   and the libmicrohttpd library.
 * @param val        Pointer to the value that we are looking
 *                   for.
 */
void httpd_lookup_arg(void *connection, const char *key,
		void *con_cls, str *val)
{
	slinkedl_list_t *list = (slinkedl_list_t*)con_cls;

	if (val) {
		if (list==NULL) {
			val->s = (char *)MHD_lookup_connection_value(
					(struct MHD_Connection *)connection,
						MHD_GET_ARGUMENT_KIND, key);
			if (val->s) val->len = strlen(val->s);
			else val->len = 0;
		} else {
			slinkedl_traverse(list, &httpd_get_val, (void *)key, val);
		}
	} else {
		LM_ERR("NULL holder for requested val\n");
	}

	return;
}

union sockaddr_union* httpd_get_server_info(void)
{
	return &httpd_server_info;
}

/* 0x00097001 changed the returned result */
MHD_RET answer_to_connection (void *cls, struct MHD_Connection *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls)
{
	str page = {NULL, 0};
	struct MHD_Response *response;
	int ret;
	void *async_data = NULL;
	struct httpd_cb *cb = NULL;
	const char *normalised_url;
	struct post_request *pr;
	str_str_t *kv;
	char *p;
	int ret_code = MHD_HTTP_OK;
	str saved_body = STR_NULL;

#if ( MHD_VERSION >= 0x000092800 )
	int sv_sockfd;
	socklen_t addrlen=sizeof(httpd_server_info);
#endif
	union sockaddr_union* cl_socket;

	LM_DBG("START *** cls=%p, connection=%p, url=%s, method=%s, "
			"versio=%s, upload_data[%zu]=%p, *con_cls=%p\n",
			cls, connection, url, method, version,
			*upload_data_size, upload_data, *con_cls);

	pr = *con_cls;
	if(pr == NULL){
		pr = pkg_malloc(sizeof(struct post_request));
		if(pr==NULL) {
			LM_ERR("oom while allocating post_request structure\n");
			return MHD_NO;
		}
		memset(pr, 0, sizeof(struct post_request));
		*con_cls = pr;
		pr = NULL;
	}

	/* we're safe here since this returns a struct sockaddr* and
	 * sockaddr_union contains sockaddr* inside */
	cl_socket = (union sockaddr_union *)MHD_get_connection_info(connection,
			MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;

	if (!MHD_set_connection_option(connection, MHD_CONNECTION_OPTION_TIMEOUT, hd_conn_timeout_s))
		LM_ERR("failed to set connection timeout\n");

#if ( MHD_VERSION >= 0x000092800 )
	sv_sockfd = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CONNECTION_FD)->connect_fd;
	if (getsockname( sv_sockfd, &httpd_server_info.s, &addrlen) < 0) {
		LM_ERR("cannot resolve server's IP: %s:%d\n", strerror(errno), errno);
		return MHD_NO;
	}

	/* we could do
	 * httpd_server_info.sin.sin_port = ntohs(httpd_server_info.sin.sin_port);
	 * but it has no sense since we already know the port since we initialised
	 * httpd server
	 */
	httpd_server_info.sin.sin_port = port;
#endif

	if(strncmp(method, "POST", 4)==0) {
		if(pr == NULL){
			pr = *con_cls;
			pr->p_list = slinkedl_init(&httpd_alloc, &httpd_free);
			if (pr->p_list==NULL) {
				LM_ERR("oom while allocating list\n");
				return MHD_NO;
			}
			LM_DBG("running MHD_create_post_processor\n");
			pr->pp = MHD_create_post_processor(connection,
											post_buf_size,
											&post_iterator,
											pr);
			LM_DBG("pr=[%p] pp=[%p] p_list=[%p]\n",
					pr, pr->pp, pr->p_list);

			/* We need to wait for the actual data in the POST request */
			return MHD_YES;
		} else {
			if (pr->pp==NULL) {
				if (*upload_data_size == 0) {
					*con_cls = pr->p_list;
					cb = get_httpd_cb(url);
					if (cb) {
						normalised_url = &url[cb->http_root->len+1];
						LM_DBG("normalised_url=[%s]\n", normalised_url);
						httpd_receive_buff_pos=0;
						slinkedl_traverse(pr->p_list,&httpd_merge_data, NULL, NULL);
						if (httpd_receive_buff_pos>0) {
							saved_body.len = httpd_receive_buff_pos;
							saved_body.s = httpd_receive_buff;
						}
						ret_code = cb->callback(cls, (void*)connection,
								normalised_url,
								method, version,
								saved_body.s, saved_body.len,
								con_cls, &buffer, &page, cl_socket);
					} else {
						page = MI_HTTP_U_URL;
						ret_code = MHD_HTTP_BAD_REQUEST;
					}
					/* slinkedl_traverse(pr->p_list,
							&httpd_print_data, NULL, NULL); */
					slinkedl_list_destroy(*con_cls);
					pkg_free(pr); *con_cls = pr = NULL;
					goto send_response;
				}
				LM_DBG("NOT a regular POST :o)\n");
				if (pr->content_type==0 && pr->content_len==0)
					MHD_get_connection_values(connection, MHD_HEADER_KIND,
											&getConnectionHeader, pr);
				if (pr->content_type==0) {
					LM_ERR("missing Content-Type header\n");
					return MHD_NO;
				}
				if (pr->content_type<0) {
					/* Unexpected Content-Type header:
					err log printed in getConnectionHeader() */
					return MHD_NO;
				}
				LM_DBG("got ContentType [%d] with len [%d]: %.*s\n",
					pr->content_type, pr->content_len,
					(int)*upload_data_size, upload_data);
				/* Here we save data. */
				switch (pr->content_type) {
				case HTTPD_TEXT_XML_CNT_TYPE:
				case HTTPD_APPLICATION_JSON_CNT_TYPE:
					/* Save the entire body as the '1' key */
					kv = (str_str_t*)slinkedl_append(pr->p_list,
							sizeof(str_str_t) + 1 +
							*upload_data_size);
					p = (char*)(kv + 1);
					kv->key.len = 1; kv->key.s = p;
					memcpy(p, "1", 1);
					p += 1;
					kv->val.len = *upload_data_size;
					kv->val.s = p;
					memcpy(p, upload_data, *upload_data_size);
					break;
				default:
					LM_ERR("Unhandled data for ContentType [%d]\n",
							pr->content_type);
					return MHD_NO;
				}
				/* Mark the fact that we consumed all data */
				*upload_data_size = 0;
				return MHD_YES;
			}
			LM_DBG("running MHD_post_process: "
					"pp=%p status=%d upload_data_size=%zu\n",
					pr->pp, pr->status, *upload_data_size);
			if (pr->status<0) {
				slinkedl_list_destroy(pr->p_list);
				pr->p_list = NULL;
				/* FIXME:
				 * It might be better to reply with an error
				 * instead of resetting the connection via MHD_NO */
				return MHD_NO;
			}
			ret =MHD_post_process(pr->pp, upload_data, *upload_data_size);
			LM_DBG("ret=%d upload_data_size=%zu\n", ret, *upload_data_size);
			if(*upload_data_size != 0) {
				*upload_data_size = 0;
				return MHD_YES;
			}

			LM_DBG("running MHD_destroy_post_processor: "
					"pr=[%p] pp=[%p] p_list=[%p]\n",
					pr, pr->pp, pr->p_list);
			MHD_destroy_post_processor(pr->pp);
			LM_DBG("done MHD_destroy_post_processor\n");
			/* slinkedl_traverse(pr->p_list, &httpd_print_data, NULL, NULL); */
			*con_cls = pr->p_list;

			cb = get_httpd_cb(url);
			if (cb) {
				normalised_url = &url[cb->http_root->len+1];
				LM_DBG("normalised_url=[%s]\n", normalised_url);
				ret_code = cb->callback(cls, (void*)connection,
						normalised_url,
						method, version,
						upload_data, *upload_data_size, con_cls,
						&buffer, &page, cl_socket);
			} else {
				page = MI_HTTP_U_URL;
				ret_code = MHD_HTTP_BAD_REQUEST;
			}
			/* slinkedl_traverse(pr->p_list, &httpd_print_data, NULL, NULL); */
			slinkedl_list_destroy(*con_cls);
			pkg_free(pr); *con_cls = pr = NULL;
		}
	}else if(strncmp(method, "GET", 3)==0) {
		pr = *con_cls;
		MHD_get_connection_values(connection, MHD_HEADER_KIND,
								&getConnectionHeader, pr);
		pkg_free(pr); *con_cls = pr = NULL;
		cb = get_httpd_cb(url);
		if (cb) {
			normalised_url = &url[cb->http_root->len+1];
			LM_DBG("normalised_url=[%s]\n", normalised_url);
			ret_code = cb->callback(cls, (void*)connection,
					normalised_url,
					method, version,
					upload_data, *upload_data_size, con_cls,
					&buffer, &page, cl_socket);
		} else {
			page = MI_HTTP_U_URL;
			ret_code = MHD_HTTP_BAD_REQUEST;
		}
	}else{
		page = MI_HTTP_U_METHOD;
#ifdef MHD_HTTP_NOT_ACCEPTABLE
		ret_code = MHD_HTTP_NOT_ACCEPTABLE;
#else
		ret_code = MHD_HTTP_METHOD_NOT_ACCEPTABLE;
#endif
	}

send_response:
	if (page.s) {
#if defined MHD_VERSION && MHD_VERSION >= 0x00090000
		response = MHD_create_response_from_buffer(page.len,
							(void*)page.s,
							MHD_RESPMEM_MUST_COPY);
#else
		/* use old constructor */
		response = MHD_create_response_from_data(page.len,
							(void*)page.s,
							0, 1);
#endif
		LM_DBG("MHD_create_response_from_data [%p:%d]\n",
			page.s, page.len);
	} else if (cb) {
		LM_DBG("MHD_create_response_from_callback\n");
		response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN,
							buffer.len,
							(MHD_ContentReaderCallback)cb->flush_data_callback,
							(void*)async_data,
							NULL);
	} else {
		return MHD_NO;
	}

	if (cb && cb->type>0) {
		if (cb->type==HTTPD_TEXT_XML_CNT_TYPE)
			MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
				"text/xml; charset=utf-8");
		else if (cb->type==HTTPD_APPLICATION_JSON_CNT_TYPE)
			MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
				"application/json");
		else if (cb->type==HTTPD_TEXT_HTML_TYPE)
			MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
				"text/html");
		else if (cb->type==HTTPD_TEXT_PLAIN_TYPE)
			MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
				"text/plain");
		else if (cb->type==HTTPD_TEXT_PLAIN_PROMETHEUS_TYPE)
			MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
				"text/plain; version=0.0.4");
		else
			LM_BUG("unhandled content type %d\n",cb->type);
	} else {
		/* 'page' for sure contains some HTML error we pushed */
		MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE,
				"text/html");
	}
	ret = MHD_queue_response (connection, ret_code, response);
	MHD_destroy_response (response);

	return ret;
}
#endif


#ifdef LIBMICROHTTPD
static fd_set mhd_rs;
static fd_set mhd_ws;
static fd_set mhd_es;

int httpd_callback(int fd, void *dmn, int was_timeout)
{
	int status;
	status = MHD_run_from_select((struct MHD_Daemon *)dmn,
		&mhd_rs, &mhd_ws, &mhd_es);
	if (status == MHD_NO) {
		LM_ERR("failed to run http daemon\n");
		return -1;
	}
	return 0;
}
#endif


void httpd_proc(int rank)
{
	struct httpd_cb *cb = httpd_cb_list;

	/*child's initial settings*/
	if (init_mi_child()!=0) {
		LM_ERR("failed to init the mi child process\n");
		return;
	}

	/* Allocating http response buffer */
	buffer.s = (char*)malloc(sizeof(char)*buffer.len);
	if (buffer.s==NULL) {
		LM_ERR("oom\n");
		return;
	}

	while(cb) {
		if (cb->init_proc_callback)
			cb->init_proc_callback();
		cb = cb->next;
	}

#ifdef LIBMICROHTTPD
	unsigned int mhd_flags = MHD_USE_DEBUG;
	unsigned int mhdi_flags;
	int mhd_opt_n = 0;
	char *key_pem, *cert_pem, *ip_repr, ip6buf[1+IP_ADDR_MAX_STR_SIZE+1];
	void *saddr;
	struct sockaddr_in saddr4;
	struct MHD_OptionItem mhd_opts[4];
	const union MHD_DaemonInfo *dmni;
	int fd;

	if (tls_key_file.s && tls_cert_file.s) {

		key_pem = load_file(tls_key_file.s);
		if (NULL == key_pem) {
			LM_ERR("unable to load tls key\n");
			return;
		}

  		cert_pem = load_file(tls_cert_file.s);
		if (NULL == cert_pem) {
			free(key_pem);	
			LM_ERR("unable to load tls certificate\n");
			return;
		}

		mhd_flags = mhd_flags | MHD_USE_SSL;

		mhd_opts[mhd_opt_n].option = MHD_OPTION_HTTPS_MEM_KEY;
		mhd_opts[mhd_opt_n].value = 0;
		mhd_opts[mhd_opt_n].ptr_value = key_pem;
		mhd_opt_n++;
		mhd_opts[mhd_opt_n].option = MHD_OPTION_HTTPS_MEM_CERT;
		mhd_opts[mhd_opt_n].value = 0;
		mhd_opts[mhd_opt_n].ptr_value = cert_pem;
		mhd_opt_n++;
		mhd_opts[mhd_opt_n].option = MHD_OPTION_HTTPS_PRIORITIES;
		mhd_opts[mhd_opt_n].ptr_value = tls_ciphers.s;
		mhd_opts[mhd_opt_n].value = 0;
		mhd_opt_n++;

	} else
		mhd_flags = mhd_flags | MHD_NO_FLAG;

	mhd_opts[mhd_opt_n].option = MHD_OPTION_END;
	mhd_opts[mhd_opt_n].value = 0;
	mhd_opts[mhd_opt_n].ptr_value = NULL;

	#if (MHD_VERSION <= 0x00095000)
	mhd_flags = mhd_flags | MHD_USE_EPOLL_LINUX_ONLY;
	#else
	mhd_flags = mhd_flags | MHD_USE_EPOLL;
	#endif

#if ( MHD_VERSION >= 0x000092800 )
	struct sockaddr_in6 saddr6;
	if (ip.s && strcmp(ip.s, "*")) {
		if (q_memchr(ip.s, ':', ip.len)) {
			LM_DBG("preparing to listen on IPv6 interface '%s'\n", ip.s);
			memset(&saddr6, 0, sizeof saddr6);

			if (inet_pton(AF_INET6, ip.s, &saddr6.sin6_addr) <= 0) {
				LM_ERR("failed to parse 'ip' modparam: %s\n", ip.s);
				return;
			}

			saddr6.sin6_family = AF_INET6;
			saddr6.sin6_port = htons(port);
			saddr = &saddr6;
			sprintf(ip6buf, "[%s]", !strcmp(ip.s, "::0") ? "::" : ip.s);
			ip_repr = ip6buf;
			mhd_flags |= MHD_USE_IPv6;
		} else {
			LM_DBG("preparing to listen on IPv4 interface '%s'\n", ip.s);
			memset(&saddr4, 0, sizeof saddr4);

			if (inet_pton(AF_INET, ip.s, &saddr4.sin_addr) <= 0) {
				LM_ERR("failed to parse 'ip' modparam: %s\n", ip.s);
				return;
			}

			saddr4.sin_family = AF_INET;
			saddr4.sin_port = htons(port);
			saddr = &saddr4;
			ip_repr = ip.s;
		}
	} else {
		LM_DBG("preparing to listen on all IPv6 + IPv4 interfaces\n");
		memset(&saddr6, 0, sizeof saddr6);

		saddr6.sin6_addr = in6addr_any;
		saddr6.sin6_family = AF_INET6;
		saddr6.sin6_port = htons(port);
		saddr = &saddr6;
		ip_repr = "*";

		mhd_flags |= MHD_USE_DUAL_STACK;
	}
#else
	memset(&saddr4, 0, sizeof saddr4);
	saddr4.sin_family = AF_INET;
	saddr4.sin_port = htons(port);
	saddr = &saddr4;

	if (ip.s) {
		saddr4.sin_addr.s_addr = inet_addr(ip.s);
		ip_repr = ip.s;
	} else {
		saddr4.sin_addr.s_addr = INADDR_ANY;
		ip_repr = "0.0.0.0";
	}

	memcpy( &httpd_server_info, &saddr, sizeof(struct sockaddr_in) );
	httpd_server_info.sin.sin_port = port;
#endif

	LM_DBG("init_child [%d] - [%d] HTTP Server init [%s:%d]\n",
		rank, getpid(), ip_repr, port);
	set_proc_attrs("HTTPD %s:%d", ip_repr, port);
	dmn = MHD_start_daemon(mhd_flags, port, NULL, NULL,
			&(answer_to_connection), NULL,
			MHD_OPTION_SOCK_ADDR, saddr,
			MHD_OPTION_ARRAY, mhd_opts,
			MHD_OPTION_END);

	if (NULL == dmn) {
		LM_ERR("unable to start http daemon\n");
		return;
	}

	/* as we use the MHD_USE_EPOLL (so libmicrohttp is internally using
	 * epoll), the MHD_get_fdset() will return only the epoll controll fd.
	 * This fd never changes and is set only for reading.
	 * So, we "learn" that fd right now and bypass MHD_get_fdset() on
	 * further iterations.*/

	FD_ZERO (&mhd_rs);
	FD_ZERO (&mhd_ws);
	FD_ZERO (&mhd_es);
	MHD_get_fdset (dmn, &mhd_rs, &mhd_ws, &mhd_es, NULL);

#if (MHD_VERSION <= 0x00095100)
	mhdi_flags = MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY;
#else
	mhdi_flags = MHD_DAEMON_INFO_EPOLL_FD;
#endif

	dmni = MHD_get_daemon_info(dmn, mhdi_flags);
	if (!dmni) {
		LM_ERR("unable to get file descriptors\n");
		return;
	}
#if (MHD_VERSION <= 0x00095200)
	fd = dmni->listen_fd;
#else
	fd = dmni->epoll_fd;
#endif

	LM_DBG("found [%d] epoll ctl fd\n",fd);

	if (reactor_proc_init( "HTTPD" )<0) {
		LM_ERR("failed to init the HTTPD reactor\n");
		return;
	}

	if (reactor_proc_add_fd( fd, httpd_callback, (void*)dmn)<0) {
		LM_CRIT("failed to add Datagram listen socket to reactor\n");
		return;
	}

	reactor_proc_loop();

	/* we get here only if the "loop"-ing failed to start*/
#endif
	LM_DBG("HTTP Server stopped!\n");
}

void httpd_proc_destroy(void)
{
#ifdef LIBMICROHTTPD
	LM_DBG("destroying module ...\n");
	MHD_stop_daemon (dmn);
#endif
	return;
}

static char * load_file(char * filename)
{
	FILE *f = fopen(filename, "rb");
	if(!f)
		return NULL;

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);

	if(fsize <= 0) {
		fclose(f);
		return NULL;
	}

	fseek(f, 0, SEEK_SET);

	char *string = malloc(fsize + 1);
	size_t bread;

	bread = fread(string, 1, fsize, f);
	if (bread == 0 || ferror(f))
		LM_ERR("error while reading from %s (bytes read: %lu)\n",
				filename, (unsigned long)bread);
	fclose(f);

	string[fsize] = 0;

	return string;
}
