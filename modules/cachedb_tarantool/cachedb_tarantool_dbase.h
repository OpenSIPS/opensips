/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * modules/cachedb_tarantool/cachedb_tarantool_dbase.h
 * High-performance Tarantool 3.x CacheDB driver and IProto client
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CACHEDB_TARANTOOL_DBASE_H
#define CACHEDB_TARANTOOL_DBASE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define TNT_MUST_CHECK __attribute__((warn_unused_result))
#else
#define TNT_MUST_CHECK
#endif

#if __has_include("../../str.h") && __has_include("../../cachedb/cachedb.h")
#define TNT_REAL_OPENSIPS 1
#include "../../str.h"
#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_id.h"
#include "../../cachedb/cachedb_pool.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#else
#ifndef STR_H_DEFINED
#define STR_H_DEFINED
typedef struct str_t {
	char *s;
	int len;
} str;
#define str_init(str_val) { (str_val), (int)sizeof(str_val) - 1 }
#endif

#ifndef CACHEDB_H_DEFINED
#define CACHEDB_H_DEFINED
typedef void cachedb_con;
typedef enum { CDB_STR, CDB_INT } cdb_val_type_t;

typedef struct cdb_raw_entry {
	union {
		str s;
		int n;
	} val;
	cdb_val_type_t type;
} cdb_raw_entry;

typedef struct cachedb_url {
	str url;
	struct cachedb_url *next;
} cachedb_url;

typedef struct cachedb_funcs {
	cachedb_con *(*init)(const str *);
	void (*destroy)(cachedb_con *);
	int (*get)(cachedb_con *, const str *, str *);
	int (*set)(cachedb_con *, const str *, const str *, int);
	int (*remove)(cachedb_con *, const str *);
	int (*raw_query)(cachedb_con *, const str *, cdb_raw_entry ***, int, int *);
	int (*get_buf)(cachedb_con *, const str *, char *, unsigned int, unsigned int *, unsigned int *);
	int capability;
} cachedb_funcs_t;

typedef struct cachedb_engine {
	str name;
	cachedb_funcs_t cdb_func;
} cachedb_engine;

#define register_cachedb(engine) (0)
#define cachedb_store_url(head, url) (0)
#define cachedb_put_connection(name, con) (0)
#define cachedb_get_connection(name, cluster) (NULL)
#define cachedb_free_url(urls) ((void)0)
#define cachedb_end_connections(name) ((void)0)
#endif

#ifndef LM_ERR
#define LM_ERR(...) do { printf("[OpenSIPS ERR] " __VA_ARGS__); } while (0)
#define LM_WARN(...) do { printf("[OpenSIPS WARN] " __VA_ARGS__); } while (0)
#define LM_INFO(...) do { printf("[OpenSIPS INFO] " __VA_ARGS__); } while (0)
#define LM_NOTICE(...) do { printf("[OpenSIPS NOTICE] " __VA_ARGS__); } while (0)
#endif

#ifndef pkg_malloc
#define pkg_malloc malloc
#define pkg_free free
#define pkg_strdup strdup
#endif

typedef struct cachedb_pool_con_t {
	void *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;
} cachedb_pool_con;

#endif /* TNT_REAL_OPENSIPS */

/* IProto Protocol Constants */
#define IPROTO_REQUEST_TYPE   0x00
#define IPROTO_SYNC           0x01
#define IPROTO_SPACE_ID       0x10
#define IPROTO_INDEX_ID       0x11
#define IPROTO_LIMIT          0x12
#define IPROTO_OFFSET         0x13
#define IPROTO_ITERATOR       0x14
#define IPROTO_KEY            0x20
#define IPROTO_TUPLE          0x21
#define IPROTO_FUNCTION_NAME  0x22
#define IPROTO_USER_NAME      0x23
#define IPROTO_EXPR           0x27
#define IPROTO_OPS            0x28
#define IPROTO_DATA           0x30
#define IPROTO_ERROR_24       0x31
#define IPROTO_ERROR          0x52

#define IPROTO_OK             0x00
#define IPROTO_SELECT         0x01
#define IPROTO_INSERT         0x02
#define IPROTO_REPLACE        0x03
#define IPROTO_UPDATE         0x04
#define IPROTO_DELETE         0x05
#define IPROTO_CALL           0x06
#define IPROTO_AUTH           0x07
#define IPROTO_EVAL           0x08
#define IPROTO_UPSERT         0x09

#define DEFAULT_CONNECT_TIMEOUT_MS 1000
#define DEFAULT_QUERY_TIMEOUT_MS   500
#define DEFAULT_DISABLE_TIME_SEC   10
#define DEFAULT_ALLOWED_ERRORS     3
#define DEFAULT_POOL_SIZE          8

#define TNT_GREETING_SIZE          128
#define TNT_SHA1_DIGEST_SIZE       20

/**
 * enum tnt_conn_state - Socket connection state
 */
typedef enum {
	TNT_STATE_DISCONNECTED = 0,
	TNT_STATE_CONNECTING,
	TNT_STATE_CONNECTED,
	TNT_STATE_AUTHENTICATED,
	TNT_STATE_ERROR,
	TNT_STATE_DISABLED
} tnt_conn_state_t;

/**
 * struct tnt_single_conn - Individual socket connection to Tarantool
 */
typedef struct tnt_single_conn {
	int sock_fd;
	tnt_conn_state_t state;
	uint64_t sync_counter;
	time_t last_activity;
	time_t disabled_until;
	int consecutive_errors;
} tnt_single_conn_t;

/**
 * struct tnt_cluster_con - Cluster connection pool handle
 */
typedef struct tnt_cluster_con {
	cachedb_pool_con cache_con;

	str name;
	str host;
	int port;
	str user;
	str pass;
	str space;
	uint32_t space_id;

	int pool_size;
	int current_idx;
	tnt_single_conn_t *conns;
	pthread_mutex_t lock;
	pid_t owner_pid;

	int connect_timeout_ms;
	int query_timeout_ms;
	int disable_time_sec;
	int allowed_errors;
	int lazy_connect;
	int init_without_tarantool;
	int tcp_keepalive;
} tnt_cluster_con_t;

/* Global module configuration parameters */
extern int tarantool_connect_tout;
extern int tarantool_query_tout;
extern int tarantool_lazy_connect;
extern int tarantool_disable_time;
extern int tarantool_allowed_errors;
extern int tarantool_init_without_tnt;
extern int tarantool_pool_size;
extern int tarantool_tcp_keepalive;

/* OpenSIPS CacheDB Interface Functions */
cachedb_con *tarantool_init(const str *url);
void tarantool_destroy(cachedb_con *con);
int tarantool_get(cachedb_con *con, const str *attr, str *val) TNT_MUST_CHECK;
int tarantool_get_buf(cachedb_con *con, const str *attr, char *buf, unsigned int buflen, unsigned int *vlen, unsigned int *needed) TNT_MUST_CHECK;
int tarantool_set(cachedb_con *con, const str *attr, const str *val, int expires) TNT_MUST_CHECK;
int tarantool_remove(cachedb_con *con, const str *attr) TNT_MUST_CHECK;
int tarantool_raw_query(cachedb_con *con, const str *query, cdb_raw_entry ***reply, int num_cols, int *num_rows) TNT_MUST_CHECK;

/* Stored procedure and eval execution */
int tarantool_call_proc(tnt_cluster_con_t *tcon, const str *proc, const str *args, str *res) TNT_MUST_CHECK;
int tarantool_eval_expr(tnt_cluster_con_t *tcon, const str *expr, const str *args, str *res) TNT_MUST_CHECK;

#endif /* CACHEDB_TARANTOOL_DBASE_H */
