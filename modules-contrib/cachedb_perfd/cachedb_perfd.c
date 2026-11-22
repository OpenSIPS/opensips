/*
 * Copyright (C) 2026 Yury Kirsanov
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/* cachedb_perfd - CacheDB backend for the perfcached daemon (perfd://).
 * libperfd does the URL, seeds, routing, failover and async pool. */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <poll.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_id.h"
#include "../../async.h"
#include "../../pvar.h"

#include <perfd.h>

static str cache_mod_name = str_init("perfd");

/* applied to every perfd:// connection; 0 keeps the libperfd default */
static int connect_timeout_ms;
static int query_timeout_ms;
static int fleet_refresh_ms;
static int keepalive_s;
static int idle_ping_ms;
static int async_conns = 8;
static struct cachedb_url *perfd_script_urls;

#define PERFD_KEY_MAX 512             /* key buffer, NUL included */
#define PERFD_RAW_MAXARGS 258

static int set_connection(unsigned int type, void *val)
{
	return cachedb_store_url(&perfd_script_urls, (char *)val);
}

typedef struct {
	struct cachedb_id *id;         /* the cachedb_pool_con contract: */
	unsigned int ref;              /* these three fields first, always */
	struct cachedb_pool_con_t *next;

	perfd_url *url;
	perfd_t *pd;                   /* per process, dialled at first use */
	pid_t pid;
	perfd_apool *pool;             /* perfd_fetch(), per process */
	pid_t pool_pid;
	unsigned long long fleet_seen;
} perfd_con;

#define CON(c) ((perfd_con *)((c)->data))

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

static int timeout_ms(void)
{
	return query_timeout_ms > 0 ? query_timeout_ms : 5000;
}

static void con_opts(perfd_con *con, perfd_opts *o)
{
	perfd_opts_init(o);
	o->connect_timeout_ms = connect_timeout_ms;
	o->io_timeout_ms = query_timeout_ms;
	o->refresh_ms = fleet_refresh_ms;
	o->keepalive_s = keepalive_s;
	o->idle_ping_ms = idle_ping_ms;
	o->name = "opensips";
	perfd_url_apply(con->url, o);
}

static void con_report(perfd_con *con, const char *what)
{
	char line[256];

	perfd_describe(con->pd, line, sizeof line);
	LM_NOTICE("perfd col=%s %s: %s\n", perfd_url_collection(con->url),
		what, line);
	con->fleet_seen = perfd_fleet_changes(con->pd);
}

/* 0 = con->pd is usable in this process; -1 logged (or backing off) */
static int con_ready(perfd_con *con)
{
	perfd_opts o;

	if (con->pd && con->pid == getpid()) {
		if (perfd_state(con->pd) != PERFD_ST_FAILED) {
			if (perfd_fleet_changes(con->pd) != con->fleet_seen)
				con_report(con, "fleet changed");
			return 0;
		}
		if (perfd_redial(con->pd) == 0) {
			con_report(con, "re-dialled");
			return 0;
		}
	}
	if (con->pd)                   /* inherited across fork, or dead */
		perfd_free(con->pd);
	con_opts(con, &o);
	con->pd = perfd_url_connect(con->url, &o);
	if (!con->pd)
		return -1;
	con->pid = getpid();
	con_report(con, "dialled");
	return 0;
}

/* @s for a log line: control bytes (a forged line) become '?'; one use per call */
static const char *log_safe(const char *s, int len)
{
	static char buf[256];
	int i, n = len < (int)sizeof buf - 1 ? len : (int)sizeof buf - 1;

	for (i = 0; i < n; i++)
		buf[i] = ((unsigned char)s[i] < 0x20 || s[i] == 0x7f) ? '?' : s[i];
	buf[i] = 0;
	return buf;
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

/* @k as a C string: libperfd keys cannot hold a NUL */
static int perfd_key(const str *k, char *buf)
{
	if (k->len <= 0 || k->len >= PERFD_KEY_MAX ||
	    memchr(k->s, 0, (size_t)k->len)) {
		LM_ERR("bad key of %d bytes (1 to %d, no NUL)\n", k->len,
			PERFD_KEY_MAX - 1);
		return -1;
	}
	memcpy(buf, k->s, (size_t)k->len);
	buf[k->len] = 0;
	return 0;
}

/* ---- connections ------------------------------------------------------ */

/* the core has no public group -> connection lookup for our async cmd */
#define PERFD_MAX_CONS 16
static perfd_con *perfd_cons[PERFD_MAX_CONS];
static int n_perfd_cons;

static perfd_con *perfd_con_by_group(const str *group)
{
	int i;

	for (i = 0; i < n_perfd_cons; i++) {
		const char *g = perfd_cons[i]->id->group_name;

		if (!g ? !group->len : ((int)strlen(g) == group->len &&
		        !memcmp(g, group->s, (size_t)group->len)))
			return perfd_cons[i];
	}
	return NULL;
}

static void *perfd_new_connection(struct cachedb_id *id)
{
	perfd_con *con;
	char err[160];

	con = pkg_malloc(sizeof *con);
	if (!con)
		return NULL;
	memset(con, 0, sizeof *con);
	con->id = id;
	con->ref = 1;
	/* not the core's host field: it mangles IPv6 seeds in a list */
	con->url = perfd_url_parse(id->initial_url, err, sizeof err);
	if (!con->url) {
		LM_ERR("bad perfd URL: %s\n", err);
		pkg_free(con);
		return NULL;
	}
	if (n_perfd_cons < PERFD_MAX_CONS)
		perfd_cons[n_perfd_cons++] = con;
	else
		LM_WARN("more than %d perfd URLs - '%s' is not reachable from "
			"perfd_fetch()\n", PERFD_MAX_CONS,
			id->group_name ? id->group_name : "");
	return con;                    /* dialled at first use, never pre-fork */
}

static cachedb_con *perfd_cdb_init(str *url)
{
	return cachedb_do_init(url, (void *)perfd_new_connection);
}

static void perfd_free_connection(cachedb_pool_con *cpc)
{
	perfd_con *con = (perfd_con *)cpc;
	int i;

	/* a con freed before fork (b2b_logic's restore) must not be found later */
	for (i = 0; i < n_perfd_cons; i++)
		if (perfd_cons[i] == con) {
			memmove(&perfd_cons[i], &perfd_cons[i + 1],
				(size_t)(n_perfd_cons - i - 1) * sizeof *perfd_cons);
			n_perfd_cons--;
			break;
		}
	if (con->pool && con->pool_pid == getpid())
		perfd_apool_free(con->pool);
	if (con->pd && con->pid == getpid())
		perfd_free(con->pd);
	perfd_url_free(con->url);
	pkg_free(con);
}

static void perfd_cdb_destroy(cachedb_con *con)
{
	cachedb_do_close(con, perfd_free_connection);
}

/* ---- key-value ops ---------------------------------------------------- */

static int perfd_cdb_get_con(perfd_con *con, str *attr, str *val)
{
	char key[PERFD_KEY_MAX];
	void *v = NULL;
	size_t vlen = 0;
	long long ttl;
	int rc;

	if (perfd_key(attr, key) < 0 || con_ready(con) < 0)
		return -1;
	rc = perfd_get(con->pd, perfd_url_collection(con->url), key, &v, &vlen,
		&ttl);
	if (rc < 0) {
		LM_ERR("get %s: %s\n", log_safe(key, attr->len),
			perfd_error(con->pd));
		return -1;
	}
	if (rc == 0)
		return -2;
	if (vlen > INT_MAX) {
		LM_ERR("get %s: a value of %zu bytes\n", log_safe(key, attr->len),
			vlen);
		perfd_free_value(v);
		return -1;
	}
	val->s = pkg_malloc(vlen + 1);
	if (!val->s) {
		perfd_free_value(v);
		return -1;
	}
	memcpy(val->s, v, vlen);
	val->s[vlen] = 0;
	val->len = (int)vlen;
	perfd_free_value(v);
	return 0;
}

static int perfd_cdb_get(cachedb_con *c, str *attr, str *val)
{
	return perfd_cdb_get_con(CON(c), attr, val);
}

/* 0 or less = no expiry, as cachedb_redis (a negative ttl keeps the old one) */
static int perfd_cdb_set(cachedb_con *c, str *attr, str *val, int expires)
{
	perfd_con *con = CON(c);
	char key[PERFD_KEY_MAX];

	if (perfd_key(attr, key) < 0 || con_ready(con) < 0)
		return -1;
	if (perfd_set(con->pd, perfd_url_collection(con->url), key, val->s,
	        (size_t)val->len, expires > 0 ? expires : 0) != 0) {
		LM_ERR("set %s: %s\n", log_safe(key, attr->len),
			perfd_error(con->pd));
		return -1;
	}
	return 0;
}

static int perfd_cdb_remove(cachedb_con *c, str *attr)
{
	perfd_con *con = CON(c);
	char key[PERFD_KEY_MAX];

	if (perfd_key(attr, key) < 0 || con_ready(con) < 0)
		return -1;
	if (perfd_del(con->pd, perfd_url_collection(con->url), key) < 0) {
		LM_ERR("remove %s: %s\n", log_safe(key, attr->len),
			perfd_error(con->pd));
		return -1;
	}
	return 0;
}

/* @expires 0 or less keeps the counter's expiry, as Redis INCRBY */
static int perfd_cdb_addsub(cachedb_con *c, str *attr, long long by,
		int expires, int *new_val)
{
	perfd_con *con = CON(c);
	char key[PERFD_KEY_MAX];
	long long nv = 0;

	if (perfd_key(attr, key) < 0 || con_ready(con) < 0)
		return -1;
	if (perfd_add(con->pd, perfd_url_collection(con->url), key, by,
	        expires > 0 ? expires : -1, &nv) != 0) {
		LM_ERR("add %s: %s\n", log_safe(key, attr->len),
			perfd_error(con->pd));
		return -1;
	}
	if (nv < INT_MIN || nv > INT_MAX) {
		LM_ERR("counter %s is now %lld, beyond an int\n",
			log_safe(key, attr->len), nv);
		return -1;
	}
	if (new_val)
		*new_val = (int)nv;
	return 0;
}

static int perfd_cdb_add(cachedb_con *c, str *attr, int val, int expires,
		int *new_val)
{
	return perfd_cdb_addsub(c, attr, val, expires, new_val);
}

static int perfd_cdb_sub(cachedb_con *c, str *attr, int val, int expires,
		int *new_val)
{
	return perfd_cdb_addsub(c, attr, -(long long)val, expires, new_val);
}

static int perfd_cdb_get_counter(cachedb_con *c, str *attr, int *val)
{
	str sval;
	char num[24], *end;
	long long v = 0;
	int rc;

	rc = perfd_cdb_get(c, attr, &sval);
	if (rc != 0)
		return rc;
	rc = -1;
	if (sval.len > 0 && sval.len < (int)sizeof num) {
		memcpy(num, sval.s, sval.len);
		num[sval.len] = 0;
		errno = 0;
		v = strtoll(num, &end, 10);
		rc = (!errno && !*end && v >= INT_MIN && v <= INT_MAX) ? 0 : -1;
	}
	pkg_free(sval.s);
	if (rc < 0) {
		LM_ERR("counter %s does not hold an int\n",
			log_safe(attr->s, attr->len));
		return -1;
	}
	if (val)
		*val = (int)v;
	return 0;
}

/* ---- raw queries: any daemon command, as cachedb_redis ---------------- */

/* split on spaces; quotes keep spaces; a quote glued to a word is refused */
static int raw_tokenize(char *buf, char **argv, int maxargs)
{
	int argc = 0, q = 0;
	char *p, *arg = NULL;

	for (p = buf; *p; p++) {
		if (q) {
			if (*p == q) {
				if (p[1] && p[1] != ' ' && p[1] != '\t')
					return -1;
				*p = 0;
				q = 0;
			}
			continue;
		}
		if (*p == '\'' || *p == '"') {
			if (arg || argc >= maxargs)
				return -1;
			q = *p;
			argv[argc++] = p + 1;
		} else if (*p == ' ' || *p == '\t') {
			*p = 0;
			arg = NULL;
		} else if (!arg) {
			if (argc >= maxargs)
				return -1;
			arg = argv[argc++] = p;
		}
	}
	return q ? -1 : argc;
}

/* one scalar into a cell; 0 ok, -1 out of memory, -2 not a scalar or too long */
static int raw_cell(const perfd_reply *r, cdb_raw_entry *cell)
{
	switch (r->type) {
	case PERFD_REPLY_NIL:
		cell->type = CDB_NULL;
		return 0;
	case PERFD_REPLY_INTEGER:
		if (r->integer >= INT_MIN && r->integer <= INT_MAX) {
			cell->type = CDB_INT32;
			cell->val.n = (int)r->integer;
			return 0;
		}
		/* a wide integer goes in as its digits */
		/* fall through */
	case PERFD_REPLY_STRING:
	case PERFD_REPLY_STATUS: {
		char num[24];
		const char *s = r->str;
		size_t n = r->len;

		if (r->type == PERFD_REPLY_INTEGER) {
			n = (size_t)snprintf(num, sizeof num, "%lld", r->integer);
			s = num;
		}
		if (n > INT_MAX)
			return -2;
		cell->val.s.s = pkg_malloc(n ? n : 1);
		if (!cell->val.s.s)
			return -1;
		memcpy(cell->val.s.s, s, n);
		cell->val.s.len = (int)n;
		cell->type = CDB_STR;
		return 0;
	}
	default:
		return -2;
	}
}

static void raw_free_rows(cdb_raw_entry **rows, int n, int ncols)
{
	int i, j;

	for (i = 0; i < n; i++) {
		for (j = 0; j < ncols; j++)
			if (rows[i][j].type == CDB_STR)
				pkg_free(rows[i][j].val.s.s);
		pkg_free(rows[i]);
	}
	pkg_free(rows);
}

/* a scalar is one row; an array one row per element (an element that is an
 * array fills the row's columns), each row as wide as the script asked */
static int raw_rows(const perfd_reply *r, int ncols, cdb_raw_entry ***out,
		int *nout)
{
	const perfd_reply *const *el = &r;
	cdb_raw_entry **rows;
	size_t n = 1, i, j;
	int rc = 0;

	if (ncols < 1)
		ncols = 1;
	if (r->type == PERFD_REPLY_ARRAY) {
		el = (const perfd_reply *const *)r->element;
		n = r->elements;
	}
	rows = pkg_malloc((n ? n : 1) * sizeof *rows);
	if (!rows)
		return -1;
	for (i = 0; i < n; i++) {
		const perfd_reply *e = el[i];
		size_t m = e->type == PERFD_REPLY_ARRAY ? e->elements : 1;

		rows[i] = pkg_malloc((size_t)ncols * sizeof **rows);
		if (!rows[i])
			goto oom;
		memset(rows[i], 0, (size_t)ncols * sizeof **rows);
		for (j = 0; j < (size_t)ncols; j++)
			rows[i][j].type = CDB_NULL;
		for (j = 0; j < m && j < (size_t)ncols; j++) {
			rc = raw_cell(e->type == PERFD_REPLY_ARRAY ? e->element[j] : e,
				&rows[i][j]);
			if (rc < 0) {
				i++;
				goto oom;
			}
		}
	}
	*out = rows;
	*nout = (int)n;
	return 0;
oom:
	if (rc == -2)
		LM_ERR("raw reply does not fit rows and columns of strings\n");
	else
		LM_ERR("no pkg memory for a raw reply of %zu row(s)\n", n);
	raw_free_rows(rows, (int)i, ncols);
	return -1;
}

static int perfd_cdb_raw_query(cachedb_con *c, str *query,
		cdb_raw_entry ***reply, int expected_kv_no, int *reply_no)
{
	perfd_con *con = CON(c);
	char buf[4096], *argv[PERFD_RAW_MAXARGS];
	size_t argvlen[PERFD_RAW_MAXARGS];
	perfd_reply *r;
	int argc, i, rc = -1;

	if (!query || query->len <= 0 || query->len >= (int)sizeof buf ||
	    memchr(query->s, 0, (size_t)query->len)) {
		LM_ERR("raw query missing, over %zu bytes or holding a NUL\n",
			sizeof buf - 1);
		return -1;
	}
	memcpy(buf, query->s, query->len);
	buf[query->len] = 0;
	argc = raw_tokenize(buf, argv, PERFD_RAW_MAXARGS);
	if (argc < 1) {
		LM_ERR("raw query '%s': empty, bad quoting or too many "
			"arguments\n", log_safe(query->s, query->len));
		return -1;
	}
	for (i = 0; i < argc; i++)
		argvlen[i] = strlen(argv[i]);
	if (con_ready(con) < 0)
		return -1;
	r = perfd_exec(con->pd, perfd_url_collection(con->url), argc,
		(const char *const *)argv, argvlen);
	if (!r) {
		LM_ERR("raw query '%s': %s\n", log_safe(query->s, query->len),
			perfd_error(con->pd));
		return -1;
	}
	if (r->type == PERFD_REPLY_ERROR)
		LM_ERR("raw query '%s': %.200s\n", log_safe(query->s, query->len),
			r->str);
	else if (!reply)
		rc = 0;
	else
		rc = raw_rows(r, expected_kv_no, reply, reply_no);
	perfd_reply_free(r);
	return rc;
}

/* ---- perfd_fetch(): the async twin of cache_fetch() -------------------- */

typedef struct {
	perfd_apool *pool;
	pv_spec_t *dest;
	char *result;                  /* libperfd's, freed with perfd_free_value */
	size_t len;
	long long deadline;            /* now_ms() clock */
	int done, failed;
} perfd_areq;

static void perfd_fetch_cb(char *result, size_t len, const char *errmsg,
		void *ctx)
{
	perfd_areq *rq = ctx;

	rq->done = 1;
	if (!result) {
		rq->failed = 1;
		LM_ERR("async fetch failed: %s\n", errmsg ? errmsg : "?");
		return;
	}
	rq->result = result;
	rq->len = len;
}

/* the reply into the script variable; 1 found, -2 miss, -1 error */
static int perfd_fetch_finish(perfd_areq *rq, struct sip_msg *msg)
{
	pv_value_t val;
	int rc = -1;

	/* [u8 found][u32 ttl][value]; a miss is one zero byte */
	if (!rq->failed && rq->result && rq->len >= 1) {
		if (rq->result[0] != 1) {
			rc = -2;
		} else if (rq->len >= 5 && rq->len - 5 <= INT_MAX) {
			memset(&val, 0, sizeof val);
			val.flags = PV_VAL_STR;
			val.rs.s = rq->result + 5;
			val.rs.len = (int)(rq->len - 5);
			if (pv_set_value(msg, rq->dest, 0, &val) != 0)
				LM_ERR("failed to set the fetch output variable\n");
			rc = 1;
		}
	}
	if (rq->result)
		perfd_free_value(rq->result);
	pkg_free(rq);
	return rc;
}

/* reactor, or tm's synchronous loop: a reply still on its way waits 2 ms a turn,
 * so neither a long block nor a spin, up to the request's deadline */
static int perfd_fetch_resume(int fd, struct sip_msg *msg, void *param)
{
	perfd_areq *rq = param;
	struct pollfd pf = { fd, POLLIN, 0 };
	int r = perfd_apool_ready(rq->pool, fd);

	if (r == 0 && now_ms() < rq->deadline) {
		poll(&pf, 1, 2);
		async_status = ASYNC_CONTINUE;
		return 1;
	}
	if (r <= 0) {
		if (r == 0)
			perfd_apool_cancel(rq->pool, fd);
		LM_ERR("async fetch: no reply within %d ms\n", timeout_ms());
		pkg_free(rq);              /* the callback never runs */
		return -1;
	}
	return perfd_fetch_finish(rq, msg);
}

static int perfd_fetch_timeout(int fd, struct sip_msg *msg, void *param)
{
	perfd_areq *rq = param;

	LM_ERR("async fetch: no reply within %d ms\n", timeout_ms());
	perfd_apool_cancel(rq->pool, fd);
	pkg_free(rq);
	return -1;
}

static perfd_apool *con_pool(perfd_con *con)
{
	perfd_opts o;

	if (con->pool && con->pool_pid == getpid())
		return con->pool;
	con_opts(con, &o);             /* an inherited pool resets itself */
	con->pool = perfd_apool_new(con->url, &o, async_conns);
	con->pool_pid = getpid();
	return con->pool;
}

static int w_perfd_fetch(struct sip_msg *msg, async_ctx *ctx, str *group,
		str *key, pv_spec_t *dest)
{
	perfd_con *con = perfd_con_by_group(group);
	char kbuf[PERFD_KEY_MAX];
	perfd_apool *pool;
	perfd_areq *rq;
	int fd;

	if (!con) {
		LM_ERR("no perfd cachedb_url with group '%s'\n",
			log_safe(group->s, group->len));
		return -1;
	}
	if (perfd_key(key, kbuf) < 0)
		return -1;
	rq = pkg_malloc(sizeof *rq);
	if (!rq)
		return -1;
	memset(rq, 0, sizeof *rq);
	rq->pool = pool = con_pool(con);
	rq->dest = dest;
	fd = pool ? perfd_apool_get(pool, kbuf, perfd_fetch_cb, rq) : -1;
	if (fd == -1) {
		static time_t logged;      /* one line a minute per process */
		int full = pool && perfd_error_kind(NULL) == PERFD_E_STATE;
		str v;
		int rc;

		pkg_free(rq);
		async_status = ASYNC_NO_IO;
		if (time(NULL) - logged >= 60) {
			logged = time(NULL);
			if (full)
				LM_WARN("all %d async connections busy, fetching "
					"blocking - raise async_conns\n", async_conns);
			else
				LM_ERR("async fetch: %s\n", perfd_error(NULL));
		}
		/* blocking only for a full pool: an unreachable node fails now */
		if (!full)
			return -1;
		rc = perfd_cdb_get_con(con, key, &v);
		if (rc == 0) {
			pv_value_t val;

			memset(&val, 0, sizeof val);
			val.flags = PV_VAL_STR;
			val.rs = v;
			if (pv_set_value(msg, dest, 0, &val) != 0)
				LM_ERR("failed to set the fetch output variable\n");
			pkg_free(v.s);
			return 1;
		}
		return rc;
	}
	if (fd == PERFD_APOOL_DONE) {
		async_status = ASYNC_NO_IO;
		return perfd_fetch_finish(rq, msg);
	}
	rq->deadline = now_ms() + timeout_ms();
	ASYNC_SET_RESUME_F(ctx, perfd_fetch_resume);
	ctx->resume_param = rq;
	ctx->timeout_f = perfd_fetch_timeout;
	ctx->timeout_s = (unsigned int)((timeout_ms() + 999) / 1000);
	async_status = fd;
	return 1;
}

static const acmd_export_t acmds[] = {
	{"perfd_fetch", (acmd_function)w_perfd_fetch, {
		{CMD_PARAM_STR, 0, 0},         /* cachedb_url group */
		{CMD_PARAM_STR, 0, 0},         /* key */
		{CMD_PARAM_VAR, 0, 0},         /* output variable */
		{0, 0, 0}}},
	{0, 0, {{0, 0, 0}}}
};

static const param_export_t params[] = {
	{"cachedb_url", STR_PARAM|USE_FUNC_PARAM, (void *)&set_connection},
	{"connect_timeout", INT_PARAM, &connect_timeout_ms},
	{"query_timeout", INT_PARAM, &query_timeout_ms},
	{"fleet_refresh", INT_PARAM, &fleet_refresh_ms},
	{"keepalive", INT_PARAM, &keepalive_s},
	{"idle_ping", INT_PARAM, &idle_ping_ms},
	{"async_conns", INT_PARAM, &async_conns},
	{0, 0, 0}
};

struct module_exports exports = {
	"cachedb_perfd",            /* module name */
	MOD_TYPE_CACHEDB,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load function */
	0,                          /* OpenSIPS module dependencies */
	0,                          /* exported functions */
	acmds,                      /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	0,                          /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* exported transformations */
	0,                          /* extra processes */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	(response_function)0,       /* response handling function */
	(destroy_function)mod_destroy, /* destroy function */
	child_init,                 /* per-child init function */
	0                           /* reload confirm function */
};

/* derive every script URL's Noise key in the parent, so workers inherit it */
static void perfd_prepare_keys(void)
{
	struct cachedb_url *it;
	perfd_url **urls;
	const char **secrets;
	int n = 0, max = 0, i;
	char err[160];

	for (it = perfd_script_urls; it; it = it->next)
		max++;
	if (!max)
		return;
	urls = pkg_malloc((size_t)max * sizeof *urls);
	secrets = pkg_malloc((size_t)(max + 1) * sizeof *secrets);
	if (urls && secrets) {
		for (it = perfd_script_urls; it; it = it->next) {
			char u[1024];          /* the stored URL has no NUL */

			if (it->url.len >= (int)sizeof u)
				continue;
			memcpy(u, it->url.s, it->url.len);
			u[it->url.len] = 0;
			urls[n] = perfd_url_parse(u, err, sizeof err);
			if (urls[n] && perfd_url_secret(urls[n]))
				secrets[n] = perfd_url_secret(urls[n]), n++;
			else if (urls[n])
				perfd_url_free(urls[n]);
		}
		secrets[n] = NULL;
		if (n && perfd_psk_prepare(secrets) == 0)
			LM_NOTICE("derived %d secret key(s) before forking\n", n);
		for (i = 0; i < n; i++)
			perfd_url_free(urls[i]);
	}
	pkg_free(urls);
	pkg_free(secrets);
}

static void perfd_log_to_opensips(int level, const char *msg, void *ctx)
{
	if (level <= 2)
		LM_ERR("libperfd: %s", msg);
	else if (level == 3)
		LM_WARN("libperfd: %s", msg);
	else
		LM_DBG("libperfd: %s", msg);
}

static int mod_init(void)
{
	cachedb_engine cde;

	LM_NOTICE("initializing module cachedb_perfd (libperfd %s)\n",
		perfd_version());
	if (async_conns < 1 || async_conns > 1024 || connect_timeout_ms < 0 ||
	    query_timeout_ms < 0) {
		LM_ERR("async_conns must be 1 to 1024, and the timeouts not "
			"negative\n");
		return -1;
	}
	perfd_set_log(perfd_log_to_opensips, NULL);
	memset(&cde, 0, sizeof cde);
	cde.name = cache_mod_name;
	cde.cdb_func.init = perfd_cdb_init;
	cde.cdb_func.destroy = perfd_cdb_destroy;
	cde.cdb_func.get = perfd_cdb_get;
	cde.cdb_func.get_counter = perfd_cdb_get_counter;
	cde.cdb_func.set = perfd_cdb_set;
	cde.cdb_func.remove = perfd_cdb_remove;
	cde.cdb_func.add = perfd_cdb_add;
	cde.cdb_func.sub = perfd_cdb_sub;
	cde.cdb_func.raw_query = perfd_cdb_raw_query;
	cde.cdb_func.capability = CACHEDB_CAP_GET | CACHEDB_CAP_SET |
		CACHEDB_CAP_REMOVE | CACHEDB_CAP_ADD | CACHEDB_CAP_SUB |
		CACHEDB_CAP_BINARY_VALUE | CACHEDB_CAP_RAW;
	if (register_cachedb(&cde) < 0) {
		LM_ERR("cannot register cachedb functions\n");
		return -1;
	}
	perfd_prepare_keys();
	return 0;
}

/* bookkeeping only: the first cache op in the process dials */
static int child_init(int rank)
{
	struct cachedb_url *it;
	cachedb_con *con;

	for (it = perfd_script_urls; it; it = it->next) {
		con = perfd_cdb_init(&it->url);
		if (!con || cachedb_put_connection(&cache_mod_name, con) < 0) {
			LM_ERR("failed to open perfd connection\n");
			return -1;
		}
	}
	cachedb_free_url(perfd_script_urls);
	return 0;
}

static void mod_destroy(void)
{
	cachedb_end_connections(&cache_mod_name);
}
