/*
 * Flatstore module interface
 *
 * Copyright (C) 2004 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2003-03-11  updated to the new module exports interface (andrei)
 *  2003-03-16  flags export parameter added (janakj)
 */

#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "flat_pool.h"
#include "flat_con.h"
#include "flatstore_mod.h"
#include "flatstore.h"


static int parse_flat_url(const str* url, str* path)
{
	struct stat st_buf;

	if (!url || !url->s || !path) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}
	path->s = strchr(url->s, ':') + 1;
	path->len = strlen(path->s);

	/* check if the directory exists */
	if (stat(path->s, &st_buf) < 0) {
		LM_DBG("cannot stat %s (%d, %s)\n", path->s, errno, strerror(errno));

		if (mkdir(path->s, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH) < 0) {
			LM_ERR("failed to create %s directory (%d, %s)\n", path->s,
			       errno, strerror(errno));
			return -1;
		}

		return 0;
	}

	if (!S_ISDIR(st_buf.st_mode)) {
		LM_ERR("not a directory: %s\n", path->s);
		return -1;
	}

	if (access(path->s, R_OK) < 0) {
		LM_ERR("no read permission on %s (%d, %s)\n", path->s,
		       errno, strerror(errno));
		return -1;
	}

	if (access(path->s, W_OK|X_OK) < 0) {
		LM_ERR("no write/search permission on %s (%d, %s)\n", path->s,
		       errno, strerror(errno));
		return -1;
	}

	return 0;
}



/*
 * Initialize database module
 * No function should be called before this
 */
db_con_t* flat_db_init(const str* url)
{
	db_con_t* res;
	str* path;

	if (!url || !url->s) {
		LM_ERR("invalid parameter value\n");
		return 0;
	}

	/* We do not know the name of the table (and the name of the corresponding
	 * file) at this point, we will simply store the path taken from the url
	 * parameter in the table variable, flat_use_table will then pick that
	 * value and open the file
	 */
	/* as the table (path) is a substring of the received str, we need to
	 * allocate a separate str struct for it -bogdan
	 */
	res = pkg_malloc(sizeof(db_con_t)+sizeof(struct flat_con*)+sizeof(str));
	if (!res) {
		LM_ERR("no pkg memory left\n");
		return 0;
	}
	memset(res, 0, sizeof(db_con_t) + sizeof(struct flat_con*) + sizeof(str));
	path = (str*)(((char*)res) + sizeof(db_con_t) + sizeof(struct flat_con*));

	if (parse_flat_url(url, path) < 0) {
		pkg_free(res);
		return 0;
	}
	res->table = path;

	return res;
}


/*
 * Store name of table that will be used by
 * subsequent database functions
 */
int flat_use_table(db_con_t* h, const str* t)
{
	struct flat_con* con;

	if (!h || !t || !t->s) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	if (!CON_TAIL(h) || !(CON_FILENAME(h).len == t->len &&
			!memcmp(CON_FILENAME(h).s, t->s, t->len))) {
		if (CON_TAIL(h)) {
			/* Decrement the reference count
			 * of the connection but do not remove
			 * it from the connection pool
			 */
			con = (struct flat_con*)CON_TAIL(h);
			con->ref--;
		}

		CON_TAIL(h) = (unsigned long)
			flat_get_connection(CON_TABLE(h), t);
		if (!CON_TAIL(h)) {
			return -1;
		}
	}

	return 0;
}


void flat_db_close(db_con_t* h)
{
	struct flat_con* con;

	if (!h) {
		LM_ERR("invalid parameter value\n");
		return;
	}

	con = (struct flat_con*)CON_TAIL(h);

	if (con) {
		flat_release_connection(con);
	}
	pkg_free(h);
}

#ifdef FLAT_USE_FILE_LOCK
/* used for file locking */
static struct flock flat_file_lock = { 0, SEEK_SET, 0, 0, 0 };

	static inline void FLAT_LOCK(int f)
	{
		if (flat_single_file)
			return;

		flat_file_lock.l_type = F_WRLCK;
		if (fcntl(f, F_SETLKW, &flat_file_lock) < 0)
			LM_CRIT("cannot lock file (%s:%d)\n", strerror(errno), errno);
	}

	static inline void FLAT_UNLOCK(int f)
	{
		if (flat_single_file)
			return;

		flat_file_lock.l_type = F_UNLCK;
		if (fcntl(f, F_SETLK, &flat_file_lock) < 0)
			LM_CRIT("cannot unlock file (%s:%d)\n", strerror(errno), errno);
	}
#else
	#define FLAT_LOCK(f)
	#define FLAT_UNLOCK(f)
#endif /* FLAT_USE_FILE_LOCK */


static struct iovec *flat_iov = 0;
static int flat_iov_len = 0;

static str flat_iov_buf = { 0, 0 };
static int flat_iov_buf_len = 0;

static int flat_prepare_iovec(const int n)
{
	int i;

	LM_DBG("Needing %d fields, got %d\n", 2 * n, flat_iov_len);
	flat_iov_buf.len = 0;

	/* resize the buffer */
	flat_iov = pkg_realloc(flat_iov, 2 * n * sizeof(struct iovec));
	if (!flat_iov) {
		LM_ERR("not enough pkg mem for iov\n");
		flat_iov_len = 0;
		return -1;
	}
	for (i = !flat_iov_len ? flat_iov_len + 1: flat_iov_len - 1;
			i < 2 * n - 1; i += 2) {
		flat_iov[i].iov_base = flat_delimiter;
		flat_iov[i].iov_len = 1;
	}

	flat_iov_len = 2*n;
	flat_iov[flat_iov_len - 1].iov_base = "\n";
	flat_iov[flat_iov_len - 1].iov_len = 1;
	LM_DBG("Successfully allocated %d fields", flat_iov_len);

	return 0;
}

/* buffer operations */
#define FLAT_BUF (flat_iov_buf.s + flat_iov_buf.len)
#define FLAT_LEN (flat_iov_buf_len - flat_iov_buf.len)
#define FLAT_INC(_l) (flat_iov_buf.len += (_l))
#define FLAT_RESET() (flat_iov_buf.len = 0)
#define FLAT_ALLOC(_l) \
	do { \
		if (!flat_iov_buf_len) { \
			flat_iov_buf_len = (_l); \
			flat_iov_buf.s = pkg_malloc((_l)); \
		} else if (flat_iov_buf.len + (_l) > flat_iov_buf_len) { \
			do { \
				flat_iov_buf_len *= 2; \
			} while (flat_iov_buf_len < (_l)); \
			flat_iov_buf.s = pkg_realloc(flat_iov_buf.s, flat_iov_buf_len); \
			LM_DBG("reallocated to %d, needed %d\n", flat_iov_buf_len, (_l)); \
		} \
	} while (0)

/*
#define FLAT_ALLOC(_l) \
		flat_iov_buf.s = pkg_realloc(flat_iov_buf.s, (_l) + flat_iov_buf.len); \
		flat_iov_buf_len = (_l) + flat_iov_buf.len;
*/
#define FLAT_SET_STR(_i, _s) flat_iov[2 * (_i)].iov_base = (_s)
#define FLAT_SET_LEN(_i, _l) flat_iov[2 * (_i)].iov_len = (_l)
#define FLAT_GET_LEN(_i) (flat_iov[2 * (_i)].iov_len)

/* prints into buffer */
#define FLAT_PRINTF(_f, _v, _i) \
	do { \
		aux.len = snprintf(FLAT_BUF, FLAT_LEN, _f, _v); \
		if (aux.len < 0) { \
			LM_ERR("cannot print " #_v "\n"); \
			aux.len = 0; \
		} else if (aux.len >= FLAT_LEN) { \
			LM_ERR("not enough space to print " #_v " ... truncating\n"); \
			aux.len = FLAT_LEN - 1 /* '\0' at the end */; \
		}\
		FLAT_SET_LEN((_i), aux.len); \
		FLAT_INC(aux.len); \
	} while(0)

#define FLAT_COPY(_i, _s, _l) \
	do { \
		str aux; \
		int len = 0; \
		int l = _l; \
		const char *s = _s; \
		const char *p = _s; \
		while (l--) { \
			if ( !(isprint((int)*s) && *s != '\\' && *s != flat_delimiter[0])) { \
				aux.len = snprintf(FLAT_BUF, FLAT_LEN,"%.*s\\x%02X", \
						(int)(s-p),p,(*s & 0xff)); \
				p = s+1; \
				if (aux.len < 0) { \
					LM_ERR("error while writing blob %d\n", i); \
					aux.len = 0; \
				} \
				len += aux.len; \
				FLAT_INC(aux.len); \
			} \
			++s; \
		} \
		if (p!=s) { \
			aux.len = snprintf(FLAT_BUF, FLAT_LEN,"%.*s", (int)(s-p), p); \
			if (aux.len < 0) { \
				LM_ERR("error while writing blob %d\n", i); \
				aux.len = 0; \
			} \
			len += aux.len; \
			FLAT_INC(aux.len); \
		} \
		FLAT_SET_LEN(i, len); \
	} while (0)




/*
 * Insert a row into specified table
 * h: structure representing database connection
 * k: key names
 * v: values of the keys
 * n: number of key=value pairs
 */
int flat_db_insert(const db_con_t* h, const db_key_t* k, const db_val_t* v,
		const int n)
{
	FILE* f;
	int i;
	int auxl;
	str aux;
	char * begin = flat_iov_buf.s;

	if (local_timestamp < *flat_rotate) {
		flat_rotate_logs();
		local_timestamp = *flat_rotate;
	}

	if ( !h || !CON_TAIL(h) || (f=CON_FILE(h))==NULL ) {
		LM_ERR("uninitialized connection\n");
		return -1;
	}

	if (flat_prepare_iovec(n) < 0) {
		LM_ERR("cannot insert row\n");
		return -1;
	}

	FLAT_LOCK(f);

	for(i = 0; i < n; i++) {
		if (VAL_NULL(v + i)) {
			FLAT_SET_STR(i, "");
			FLAT_SET_LEN(i, 0);
			continue;
		}
		FLAT_SET_STR(i, FLAT_BUF);
		switch(VAL_TYPE(v + i)) {
		case DB_INT:
			/* guess this is 20 */
			FLAT_ALLOC(20);
			FLAT_PRINTF("%d", VAL_INT(v+i), i);
			break;

		case DB_DOUBLE:
			/* guess there are max 20 digits */
			FLAT_ALLOC(40);
			FLAT_PRINTF("%f", VAL_DOUBLE(v+i), i);
			break;

		case DB_BIGINT:
			/* guess there are max 20 digits */
			FLAT_ALLOC(40);
			FLAT_PRINTF("%llu", VAL_BIGINT(v+i), i);
			break;

		case DB_STRING:
			auxl = strlen(VAL_STRING(v + i));
			FLAT_ALLOC(auxl * 4);
			FLAT_COPY(i, VAL_STRING(v + i), auxl);
			break;

		case DB_STR:
			FLAT_ALLOC(VAL_STR(v + i).len * 4);
			FLAT_COPY(i, VAL_STR(v + i).s, VAL_STR(v + i).len);
			break;

		case DB_DATETIME:
			/* guess this is 20 */
			FLAT_ALLOC(20);
			FLAT_PRINTF("%lu", VAL_TIME(v+i), i);
			break;

		case DB_BLOB:
			auxl = VAL_BLOB(v+i).len;
			/* the maximum size is 4l - if all chars were not printable */
			FLAT_ALLOC(4 * auxl);
			FLAT_COPY(i, VAL_BLOB(v+i).s, auxl);
			break;

		case DB_BITMAP:
			/* guess this is 20 */
			FLAT_ALLOC(20);
			FLAT_PRINTF("%u", VAL_BITMAP(v+i), i);
			break;
		}
	}
	/* reorder pointers in case they were altered by (re)allocation */
	if (flat_iov_buf.s != begin && flat_iov_buf.len) {
		FLAT_RESET();
		for (i = 0; i < n; i++) {
			if (!VAL_NULL(v + i)) {
				FLAT_SET_STR(i, FLAT_BUF);
				FLAT_INC(FLAT_GET_LEN(i));
			}
		}
	}

	do {
		auxl = writev(fileno(f), flat_iov, 2 * n);
	} while (auxl < 0 && errno == EINTR);

	if (auxl < 0) {
		LM_ERR("unable to write to file: %s - %d\n", strerror(errno), errno);
		return -1;
	}

	/* XXX does this make sense any more? */
	if (flat_flush && fflush(f) < 0) {
		LM_ERR("cannot flush buffer: %s - %d\n", strerror(errno), errno);
	}
	FLAT_UNLOCK(f);


	return 0;
}
