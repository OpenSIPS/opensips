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


#ifndef HTTPD_HTTPD_LOAD_H
#define HTTPD_HTTPD_LOAD_H


#define HTTPD_UNKNOWN_CONTENT_LEN	-1

enum HTTPD_CONTENT_TYPE {
	HTTPD_UNKNOWN_CNT_TYPE = -1,
	HTTPD_STD_CNT_TYPE = 0,
	HTTPD_TEXT_HTML_TYPE,
	HTTPD_TEXT_XML_CNT_TYPE,
	HTTPD_APPLICATION_JSON_CNT_TYPE
};

/**
 * A client has requested the given url using the given method ("GET",
 * "PUT", "DELETE", "POST", etc).  The callback must call httpd
 * callbacks to provide content to give back to the client and return
 * an HTTP status code (i.e. 200 for OK, 404, etc.).
 *
 * @param cls argument given together with the function
 *            pointer when the handler was registered
 *            with the httpd module
 * @param connection abstract connection handler
 * @param url the requested url after http_root was skipped
 * @param method the HTTP method used ("GET", "PUT", etc.)
 * @param version the HTTP version string (i.e. "HTTP/1.1")
 * @param upload_data the data being uploaded (for POST data in
 *                    key-value format, use lookup_arg() instead)
 * @param upload_data_size size of the data being uploaded
 * @param con_cls pointer that the callback can set to some
 *                address and that will be preserved by
 *                httpd for future calls for this request
 * @param  buffer preallocated buffer for building the page
 *                (the http response)
 * @param page the page to return.  If no page is returned,
 *             then the page will be built later on via a
 *             callback (see httpd_flush_data_cb)
 * @returns code the HTTP code to be returned to the client
 */
typedef int (httpd_acces_handler_cb) (void *cls, void *connection, const char *url,
				const char *method, const char *version,
				const char *upload_data, size_t upload_data_size,
				void **con_cls,
				str *buffer, str *page, union sockaddr_union* cl_socket);

/**
 * Callback used by httpd in order to obtain content.  The
 * callback is to copy at most "max" bytes of content into "buf".  The
 * total number of bytes that has been placed into "buf" should be
 * returned.<p>
 *
 * Note that returning zero will cause httpd to try again,
 * the next round. Returning 0 for a daemon that runs in internal
 * select mode is an error (since it would result in busy waiting) and
 * will cause the program to be aborted (abort()).
 *
 * @param cls extra argument to the callback
 * @param pos position in the datastream to access;
 *        note that if an MHD_Response object is re-used,
 *        it is possible for the same content reader to
 *        be queried multiple times for the same data;
 *        however, if an MHD_Response is not re-used,
 *        libmicrohttpd guarantees that "pos" will be
 *        the sum of all non-negative return values
 *        obtained from the content reader so far.
 * @return -1 for the end of transmission (or on error);
 *  if a content transfer size was pre-set and the callback
 *  has provided fewer than that amount of data,
 *  httpd will close the connection with the client;
 *  if no content size was specified and this is an
 *  http 1.1 connection using chunked encoding, httpd will
 *  interpret "-1" as the normal end of the transfer
 *  (possibly allowing the client to perform additional
 *  requests using the same TCP connection).
 */
typedef ssize_t (httpd_flush_data_cb) (void *cls, uint64_t pos, char *buf, size_t max);

/**
 * Callback to be run in order to initialize process specific data
 */
typedef void (httpd_init_proc_cb) (void);


struct httpd_cb {
	const char *module;
	str *http_root;
	httpd_acces_handler_cb *callback;
	httpd_flush_data_cb *flush_data_callback;
	httpd_init_proc_cb *init_proc_callback;
	enum HTTPD_CONTENT_TYPE type;
	struct httpd_cb *next;
};



void lookup_arg(void *connection, const char *key,
			void *con_cls, str *val);
typedef void (*lookup_arg_f)(void *connection, const char *key,
			void *con_cls, str *val);

int register_httpdcb(const char *mod, str *root_path,
			httpd_acces_handler_cb f1,
			httpd_flush_data_cb f2,
			httpd_init_proc_cb f3);
typedef int (*register_httpdcb_f)(const char *mod, str *root_path,
			httpd_acces_handler_cb f1,
			httpd_flush_data_cb f2,
			enum HTTPD_CONTENT_TYPE type,
			httpd_init_proc_cb f3);

union sockaddr_union* httpd_get_server_info(void);
typedef union sockaddr_union*(*get_server_info_f)(void);

typedef struct httpd_api {
	lookup_arg_f		lookup_arg;
	register_httpdcb_f	register_httpdcb;
	get_server_info_f	get_server_info;
}httpd_api_t;


void httpd_lookup_arg(void *connection, const char *key,
			void *con_cls, str *val);

typedef int(*load_httpd_f)(httpd_api_t *api);
int httpd_bind(httpd_api_t *api);

static inline int load_httpd_api(httpd_api_t *api)
{
	load_httpd_f load_httpd;

	/* import the httpd auto-loading functions */
	if ( !(load_httpd=(load_httpd_f)find_export("httpd_bind", 0)))
		return -1;

	/* let the auto-loading function load all httpd suuff */
	if (load_httpd(api)==-1)
		return -1;

	return 0;
}

#endif

