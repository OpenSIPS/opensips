/*
 * Transactional route configuration orchestration for OpenSIPS
 *
 * Copyright (C) 2026 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../cfg_reload.h"
#include "../../daemonize.h"
#include "../../globals.h"
#include "../../locking.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../statistics.h"

struct cfg_snapshot {
	char *data;
	int len;
	uint64_t hash;
	unsigned long version;
};

struct cfg_tx_state {
	gen_lock_t lock;
	int busy;
	struct cfg_snapshot staged;
	struct cfg_snapshot rollback;
	uint64_t base_hash;
	uint64_t active_hash;
	unsigned long active_version;
	unsigned long next_version;
};

static struct cfg_tx_state *tx;
static int max_config_size = 8 * 1024 * 1024;
static int fsync_changes = 1;
static int validate_on_stage = 1;
static int validate_on_commit = 1;
static char *validator_binary;
/* absolute path of the active cfg_file, resolved at startup */
static char *cfg_path;

static stat_var *stages;
static stat_var *commits;
static stat_var *rollbacks;
static stat_var *conflicts;
static stat_var *failures;
static stat_var *validations;
static stat_var *validation_failures;

static int mod_init(void);
static void mod_destroy(void);
static mi_response_t *mi_stage(const mi_params_t *params,
	struct mi_handler *async_hdl);
static mi_response_t *mi_status(const mi_params_t *params,
	struct mi_handler *async_hdl);
static mi_response_t *mi_commit(const mi_params_t *params,
	struct mi_handler *async_hdl);
static mi_response_t *mi_rollback(const mi_params_t *params,
	struct mi_handler *async_hdl);
static mi_response_t *mi_discard(const mi_params_t *params,
	struct mi_handler *async_hdl);
static mi_response_t *mi_validate(const mi_params_t *params,
	struct mi_handler *async_hdl);
static mi_response_t *mi_diff(const mi_params_t *params,
	struct mi_handler *async_hdl);

static const param_export_t params[] = {
	{"max_config_size", INT_PARAM, &max_config_size},
	{"fsync_changes", INT_PARAM, &fsync_changes},
	{"validate_on_stage", INT_PARAM, &validate_on_stage},
	{"validate_on_commit", INT_PARAM, &validate_on_commit},
	{"validator_binary", STR_PARAM, &validator_binary},
	{0, 0, 0}
};

static unsigned long stat_staged(void *unused)
{
	unsigned long value;

	(void)unused;
	if (!tx)
		return 0;
	lock_get(&tx->lock);
	value = tx->staged.data ? 1 : 0;
	lock_release(&tx->lock);
	return value;
}

static unsigned long stat_version(void *unused)
{
	unsigned long value;

	(void)unused;
	if (!tx)
		return 0;
	lock_get(&tx->lock);
	value = tx->active_version;
	lock_release(&tx->lock);
	return value;
}

static const stat_export_t mod_stats[] = {
	{"staged", STAT_IS_FUNC, (stat_var **)stat_staged},
	{"active_version", STAT_IS_FUNC, (stat_var **)stat_version},
	{"stages", STAT_NO_RESET, &stages},
	{"commits", STAT_NO_RESET, &commits},
	{"rollbacks", STAT_NO_RESET, &rollbacks},
	{"conflicts", STAT_NO_RESET, &conflicts},
	{"failures", STAT_NO_RESET, &failures},
	{"validations", STAT_NO_RESET, &validations},
	{"validation_failures", STAT_NO_RESET, &validation_failures},
	{0, 0, 0}
};

static const mi_export_t mi_cmds[] = {
	{"stage", 0, 0, 0, {
		{mi_stage, {"path", 0}}, {EMPTY_MI_RECIPE}}, {0}},
	{"status", 0, 0, 0, {
		{mi_status, {0}}, {EMPTY_MI_RECIPE}}, {0}},
	{"validate", 0, 0, 0, {
		{mi_validate, {0}}, {EMPTY_MI_RECIPE}}, {0}},
	{"diff", 0, 0, 0, {
		{mi_diff, {0}}, {EMPTY_MI_RECIPE}}, {0}},
	{"commit", 0, 0, 0, {
		{mi_commit, {0}}, {EMPTY_MI_RECIPE}}, {0}},
	{"rollback", 0, 0, 0, {
		{mi_rollback, {0}}, {EMPTY_MI_RECIPE}}, {0}},
	{"discard", 0, 0, 0, {
		{mi_discard, {0}}, {EMPTY_MI_RECIPE}}, {0}},
	{EMPTY_MI_EXPORT}
};

struct module_exports exports = {
	"config_tx",
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	NULL,
	NULL,
	NULL,
	NULL,
	params,
	mod_stats,
	mi_cmds,
	NULL,
	NULL,
	NULL,
	NULL,
	mod_init,
	0,
	mod_destroy,
	0,
	0
};

static uint64_t fnv1a64(const char *data, int len)
{
	uint64_t h = UINT64_C(14695981039346656037);
	int i;

	for (i = 0; i < len; i++) {
		h ^= (unsigned char)data[i];
		h *= UINT64_C(1099511628211);
	}
	return h;
}

static int snapshot_set(struct cfg_snapshot *dst, const char *data, int len,
	unsigned long version)
{
	char *p;

	p = shm_malloc(len + 1);
	if (!p)
		return -1;
	memcpy(p, data, len);
	p[len] = '\0';

	if (dst->data)
		shm_free(dst->data);
	dst->data = p;
	dst->len = len;
	dst->hash = fnv1a64(data, len);
	dst->version = version;
	return 0;
}

static void snapshot_clear(struct cfg_snapshot *s)
{
	if (s->data)
		shm_free(s->data);
	memset(s, 0, sizeof(*s));
}

static int read_file(const char *path, char **out, int *out_len,
	struct stat *st_out)
{
	int fd = -1, len = 0, n;
	struct stat st;
	char *buf = NULL;

	if (!path || !out || !out_len)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
		st.st_size < 0 || st.st_size > max_config_size) {
		close(fd);
		errno = EFBIG;
		return -1;
	}

	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);
		return -1;
	}
	while (len < st.st_size) {
		n = read(fd, buf + len, st.st_size - len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		len += n;
	}
	close(fd);
	if (len != st.st_size) {
		free(buf);
		errno = EIO;
		return -1;
	}
	buf[len] = '\0';
	*out = buf;
	*out_len = len;
	if (st_out)
		*st_out = st;
	return 0;
}

static int count_lines(const char *data, int len)
{
	int i, lines = 0;

	for (i = 0; i < len; i++)
		if (data[i] == '\n')
			lines++;
	/* a final line without a terminating newline still counts */
	if (len > 0 && data[len - 1] != '\n')
		lines++;
	return lines;
}

static int replaceable_regular_path(const char *path)
{
	struct stat st;

	if (!path || lstat(path, &st) < 0)
		return 0;
	/*
	 * rename(2) replaces the directory entry itself. Following a symlink for
	 * reads and then renaming over the symlink would silently destroy the
	 * symlink rather than update its target.
	 */
	return S_ISREG(st.st_mode);
}

/*
 * OpenSIPS changes its working directory (to "/" by default) when it
 * daemonizes, which happens before the modules are initialized.  Relative
 * paths given on the command line or over MI are therefore resolved against
 * the startup working directory, the same way reload_routing_script() does.
 * Returns a malloc'ed, NUL-terminated path.
 */
static char *absolute_path_dup(const char *path, int len)
{
	const char *base = NULL;
	char *cwd = NULL, *p;
	size_t base_len = 0;

	if (!path || len <= 0)
		return NULL;

	if (path[0] != '/') {
		if (startup_wdir) {
			base = startup_wdir;
		} else {
			cwd = getcwd(NULL, 0);
			if (!cwd)
				return NULL;
			base = cwd;
		}
		base_len = strlen(base);
	}

	p = malloc(base_len + 1 + (size_t)len + 1);
	if (!p) {
		free(cwd);
		return NULL;
	}
	if (base_len) {
		memcpy(p, base, base_len);
		if (p[base_len - 1] != '/')
			p[base_len++] = '/';
	}
	memcpy(p + base_len, path, len);
	p[base_len + len] = '\0';
	free(cwd);
	return p;
}

static void fsync_parent_dir(const char *path)
{
	char *dir;
	const char *slash;
	size_t len;
	int fd;

	if (!fsync_changes || !path || !*path)
		return;

	slash = strrchr(path, '/');
	if (!slash) {
		dir = strdup(".");
	} else if (slash == path) {
		dir = strdup("/");
	} else {
		len = (size_t)(slash - path);
		dir = malloc(len + 1);
		if (dir) {
			memcpy(dir, path, len);
			dir[len] = '\0';
		}
	}
	if (!dir) {
		LM_ERR("cannot allocate parent directory path for fsync\n");
		return;
	}

	fd = open(dir, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		LM_ERR("cannot open config parent directory '%s' for fsync: %s\n",
			dir, strerror(errno));
		free(dir);
		return;
	}
	if (fsync(fd) < 0)
		LM_ERR("cannot fsync config parent directory '%s': %s\n",
			dir, strerror(errno));
	close(fd);
	free(dir);
}

static int atomic_replace(const char *path, const char *data, int len,
	const struct stat *preserve)
{
	char tmp[4096];
	int fd = -1, off = 0, n, saved_errno;

	if (!replaceable_regular_path(path)) {
		LM_ERR("config path must be a regular non-symlink file for atomic replacement\n");
		errno = EINVAL;
		return -1;
	}

	n = snprintf(tmp, sizeof(tmp), "%s.config-tx.%ld.XXXXXX",
		path, (long)getpid());
	if (n <= 0 || n >= (int)sizeof(tmp)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	fd = mkstemp(tmp);
	if (fd < 0)
		return -1;
	(void)fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (preserve) {
		/*
		 * chown may clear set-ID mode bits, so restore ownership first and
		 * mode second.
		 */
		if (fchown(fd, preserve->st_uid, preserve->st_gid) < 0) {
			LM_ERR("cannot preserve config owner/group on temporary file: %s\n",
				strerror(errno));
			goto error;
		}
		if (fchmod(fd, preserve->st_mode & 07777) < 0) {
			LM_ERR("cannot preserve config mode on temporary file: %s\n",
				strerror(errno));
			goto error;
		}
	}

	while (off < len) {
		n = write(fd, data + off, len - off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			goto error;
		off += n;
	}
	if (fsync_changes && fsync(fd) < 0)
		goto error;
	if (close(fd) < 0) {
		fd = -1;
		goto error_unlink;
	}
	fd = -1;
	if (rename(tmp, path) < 0)
		goto error_unlink;
	/*
	 * fsync(file) persists file contents; fsync(parent) makes the rename
	 * durable across a crash. Failure here is logged but cannot be reported
	 * as an unperformed replacement because rename has already succeeded.
	 */
	fsync_parent_dir(path);
	return 0;

error:
	saved_errno = errno;
	if (fd >= 0)
		close(fd);
	errno = saved_errno;
error_unlink:
	saved_errno = errno;
	unlink(tmp);
	errno = saved_errno;
	return -1;
}

static int write_validation_file(const char *data, int len,
	char *path, size_t path_size)
{
	int fd, off = 0, n, saved_errno;

	n = snprintf(path, path_size, "%s.config-tx-validate.XXXXXX", cfg_path);
	if (n <= 0 || n >= (int)path_size) {
		errno = ENAMETOOLONG;
		return -1;
	}

	fd = mkstemp(path);
	if (fd < 0)
		return -1;
	(void)fcntl(fd, F_SETFD, FD_CLOEXEC);

	while (off < len) {
		n = write(fd, data + off, len - off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			goto error;
		off += n;
	}

	if (fsync_changes && fsync(fd) < 0)
		goto error;
	if (close(fd) < 0) {
		fd = -1;
		goto error_unlink;
	}
	return 0;

error:
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
error_unlink:
	saved_errno = errno;
	unlink(path);
	errno = saved_errno;
	return -1;
}

static int validate_config_data(const char *data, int len)
{
	char tmp[4096];
	const char *bin;
	pid_t pid, waited;
	sigset_t chld_set, old_set;
	int status = 0, rc = -1;

	if (!data || len < 0)
		return -1;

	if (write_validation_file(data, len, tmp, sizeof(tmp)) < 0) {
		LM_ERR("cannot create temporary config for validation: %s\n",
			strerror(errno));
		return -1;
	}

	bin = validator_binary && *validator_binary ? validator_binary :
		(my_argv && my_argv[0] && *my_argv[0] ? my_argv[0] : "opensips");

	update_stat(validations, 1);

	/*
	 * OpenSIPS worker processes install a SIGCHLD handler which reaps any
	 * child with waitpid(-1). Keep SIGCHLD blocked while the validator runs
	 * so that handler cannot steal our child's exit status (which would make
	 * the waitpid() below fail with ECHILD).
	 */
	sigemptyset(&chld_set);
	sigaddset(&chld_set, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &chld_set, &old_set) < 0) {
		LM_ERR("cannot block SIGCHLD: %s\n", strerror(errno));
		goto done;
	}

	pid = fork();
	if (pid < 0) {
		LM_ERR("cannot fork config validator: %s\n", strerror(errno));
		goto restore_mask;
	}

	if (pid == 0) {
		/*
		 * -C performs the normal OpenSIPS config validation plus route
		 * function-flag checks.  execvp() intentionally preserves the
		 * running process environment and PATH.
		 *
		 * Run from the startup working directory so that a relative
		 * argv[0], mpath or include_file resolves exactly as it did when
		 * OpenSIPS was started (and as reload_routing_script() does).
		 */
		sigprocmask(SIG_SETMASK, &old_set, NULL);
		if (startup_wdir && chdir(startup_wdir) < 0)
			_exit(126);
		execlp(bin, bin, "-C", "-f", tmp, (char *)NULL);
		_exit(127);
	}

	do {
		waited = waitpid(pid, &status, 0);
	} while (waited < 0 && errno == EINTR);

	if (waited < 0) {
		LM_ERR("waitpid() for config validator failed: %s\n",
			strerror(errno));
		goto restore_mask;
	}

	if (!WIFEXITED(status)) {
		LM_ERR("config validator did not exit normally\n");
		goto restore_mask;
	}

	if (WEXITSTATUS(status) == 0)
		rc = 0;
	else
		LM_ERR("config validation failed (validator exit=%d)\n",
			WEXITSTATUS(status));

restore_mask:
	sigprocmask(SIG_SETMASK, &old_set, NULL);
done:
	unlink(tmp);
	if (rc < 0)
		update_stat(validation_failures, 1);
	return rc;
}

static int copy_staged(char **data, int *len)
{
	char *p;

	if (!data || !len || !tx)
		return -1;
	*data = NULL;
	*len = 0;

	lock_get(&tx->lock);
	if (!tx->staged.data) {
		lock_release(&tx->lock);
		return 1;
	}
	p = malloc(tx->staged.len + 1);
	if (!p) {
		lock_release(&tx->lock);
		return -1;
	}
	memcpy(p, tx->staged.data, tx->staged.len);
	p[tx->staged.len] = '\0';
	*data = p;
	*len = tx->staged.len;
	lock_release(&tx->lock);
	return 0;
}

static int hash_current(uint64_t *hash, char **data, int *len,
	struct stat *st)
{
	char *buf;
	int n;

	if (!cfg_path || read_file(cfg_path, &buf, &n, st) < 0)
		return -1;
	*hash = fnv1a64(buf, n);
	if (data)
		*data = buf;
	else
		free(buf);
	if (len)
		*len = n;
	return 0;
}

static void hash_to_hex(uint64_t hash, char out[17])
{
	snprintf(out, 17, "%016llx", (unsigned long long)hash);
}

static mi_response_t *build_status(void)
{
	mi_response_t *resp;
	mi_item_t *obj;
	char staged_hash[17] = "";
	char base_hash[17] = "";
	char active_hash[17] = "";
	char rollback_hash[17] = "";

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;

	lock_get(&tx->lock);
	if (tx->staged.data) {
		hash_to_hex(tx->staged.hash, staged_hash);
		hash_to_hex(tx->base_hash, base_hash);
	}
	hash_to_hex(tx->active_hash, active_hash);
	if (tx->rollback.data)
		hash_to_hex(tx->rollback.hash, rollback_hash);

	if (add_mi_bool(obj, MI_SSTR("staged"), tx->staged.data != NULL) < 0 ||
		add_mi_number(obj, MI_SSTR("active_version"), tx->active_version) < 0 ||
		add_mi_string(obj, MI_SSTR("active_hash"), active_hash,
			strlen(active_hash)) < 0 ||
		add_mi_number(obj, MI_SSTR("staged_version"), tx->staged.version) < 0 ||
		add_mi_number(obj, MI_SSTR("staged_bytes"), tx->staged.len) < 0 ||
		add_mi_number(obj, MI_SSTR("staged_lines"),
			tx->staged.data ? count_lines(tx->staged.data, tx->staged.len) : 0) < 0 ||
		add_mi_string(obj, MI_SSTR("staged_hash"), staged_hash,
			strlen(staged_hash)) < 0 ||
		add_mi_string(obj, MI_SSTR("base_hash"), base_hash,
			strlen(base_hash)) < 0 ||
		add_mi_bool(obj, MI_SSTR("rollback_available"), tx->rollback.data != NULL) < 0 ||
		add_mi_string(obj, MI_SSTR("rollback_hash"), rollback_hash,
			strlen(rollback_hash)) < 0) {
		lock_release(&tx->lock);
		free_mi_response(resp);
		return NULL;
	}
	lock_release(&tx->lock);
	return resp;
}

static mi_response_t *mi_stage_impl(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	str path;
	char *path0 = NULL, *candidate = NULL, *current = NULL;
	int candidate_len, current_len;
	uint64_t current_hash;
	unsigned long version;

	(void)async_hdl;
	if (get_mi_string_param(params, "path", &path.s, &path.len) < 0)
		return init_mi_param_error();
	if (!path.s || path.len <= 0)
		return init_mi_error(400, MI_SSTR("empty candidate path"));
	path0 = absolute_path_dup(path.s, path.len);
	if (!path0)
		return init_mi_error(500, MI_SSTR("cannot resolve candidate path"));

	if (read_file(path0, &candidate, &candidate_len, NULL) < 0) {
		free(path0);
		update_stat(failures, 1);
		return init_mi_error(400, MI_SSTR("cannot read candidate config"));
	}
	free(path0);

	if (validate_on_stage && validate_config_data(candidate, candidate_len) < 0) {
		free(candidate);
		update_stat(failures, 1);
		return init_mi_error(400, MI_SSTR("candidate failed opensips -C validation"));
	}

	if (hash_current(&current_hash, &current, &current_len, NULL) < 0) {
		free(candidate);
		update_stat(failures, 1);
		return init_mi_error(500, MI_SSTR("cannot read active config"));
	}
	free(current);

	lock_get(&tx->lock);
	version = tx->next_version++;
	if (snapshot_set(&tx->staged, candidate, candidate_len, version) < 0) {
		lock_release(&tx->lock);
		free(candidate);
		return init_mi_error(500, MI_SSTR("cannot stage config"));
	}
	tx->base_hash = current_hash;
	lock_release(&tx->lock);
	free(candidate);
	update_stat(stages, 1);

	return build_status();
}

static mi_response_t *mi_status(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	(void)params;
	(void)async_hdl;
	return build_status();
}

static int first_changed_line(const char *a, int alen,
	const char *b, int blen)
{
	int i, limit, line = 1;

	if (!a || !b)
		return 0;
	limit = alen < blen ? alen : blen;
	for (i = 0; i < limit; i++) {
		if (a[i] != b[i])
			return line;
		if (a[i] == '\n')
			line++;
	}
	return alen == blen ? 0 : line;
}

static mi_response_t *mi_diff(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *obj;
	char *active = NULL, *staged = NULL;
	int active_len = 0, staged_len = 0;
	int rc, active_lines, staged_lines, first_line;
	uint64_t active_hash, staged_hash, base_hash;
	char active_hex[17], staged_hex[17], base_hex[17];
	long byte_delta, line_delta;

	(void)params;
	(void)async_hdl;

	rc = copy_staged(&staged, &staged_len);
	if (rc > 0)
		return init_mi_error(409, MI_SSTR("no staged config"));
	if (rc < 0)
		return init_mi_error(500, MI_SSTR("cannot copy staged config"));

	if (hash_current(&active_hash, &active, &active_len, NULL) < 0) {
		free(staged);
		return init_mi_error(500, MI_SSTR("cannot read active config"));
	}

	staged_hash = fnv1a64(staged, staged_len);
	lock_get(&tx->lock);
	base_hash = tx->base_hash;
	lock_release(&tx->lock);

	active_lines = count_lines(active, active_len);
	staged_lines = count_lines(staged, staged_len);
	first_line = first_changed_line(active, active_len, staged, staged_len);
	byte_delta = (long)staged_len - (long)active_len;
	line_delta = (long)staged_lines - (long)active_lines;
	hash_to_hex(active_hash, active_hex);
	hash_to_hex(staged_hash, staged_hex);
	hash_to_hex(base_hash, base_hex);

	resp = init_mi_result_object(&obj);
	if (!resp)
		goto error;
	if (add_mi_bool(obj, MI_SSTR("changed"), active_hash != staged_hash) < 0 ||
		add_mi_bool(obj, MI_SSTR("active_changed_since_stage"),
			active_hash != base_hash) < 0 ||
		add_mi_string(obj, MI_SSTR("active_hash"),
			active_hex, strlen(active_hex)) < 0 ||
		add_mi_string(obj, MI_SSTR("staged_hash"),
			staged_hex, strlen(staged_hex)) < 0 ||
		add_mi_string(obj, MI_SSTR("base_hash"),
			base_hex, strlen(base_hex)) < 0 ||
		add_mi_number(obj, MI_SSTR("active_bytes"), active_len) < 0 ||
		add_mi_number(obj, MI_SSTR("staged_bytes"), staged_len) < 0 ||
		add_mi_number(obj, MI_SSTR("byte_delta"), byte_delta) < 0 ||
		add_mi_number(obj, MI_SSTR("active_lines"), active_lines) < 0 ||
		add_mi_number(obj, MI_SSTR("staged_lines"), staged_lines) < 0 ||
		add_mi_number(obj, MI_SSTR("line_delta"), line_delta) < 0 ||
		add_mi_number(obj, MI_SSTR("first_changed_line"), first_line) < 0) {
		free_mi_response(resp);
		resp = NULL;
	}

	free(active);
	free(staged);
	return resp;

error:
	free(active);
	free(staged);
	return NULL;
}

static mi_response_t *mi_validate(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *obj;
	char *candidate = NULL;
	int candidate_len = 0;
	int rc;

	(void)params;
	(void)async_hdl;

	rc = copy_staged(&candidate, &candidate_len);
	if (rc > 0)
		return init_mi_error(409, MI_SSTR("no staged config"));
	if (rc < 0)
		return init_mi_error(500, MI_SSTR("cannot copy staged config"));

	rc = validate_config_data(candidate, candidate_len);
	free(candidate);

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;
	if (add_mi_bool(obj, MI_SSTR("valid"), rc == 0) < 0 ||
		add_mi_string(obj, MI_SSTR("validator"),
			validator_binary && *validator_binary ? validator_binary :
			(my_argv && my_argv[0] ? my_argv[0] : "opensips"),
			strlen(validator_binary && *validator_binary ? validator_binary :
			(my_argv && my_argv[0] ? my_argv[0] : "opensips"))) < 0) {
		free_mi_response(resp);
		return NULL;
	}
	return resp;
}

static mi_response_t *mi_discard_impl(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	(void)params;
	(void)async_hdl;
	lock_get(&tx->lock);
	snapshot_clear(&tx->staged);
	tx->base_hash = 0;
	lock_release(&tx->lock);
	return init_mi_result_ok();
}

static mi_response_t *mi_commit_impl(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	char *current = NULL, *candidate = NULL;
	int current_len = 0, candidate_len = 0;
	struct stat st;
	uint64_t current_hash, expected_hash;
	unsigned long candidate_version;
	int restored;

	(void)params;
	(void)async_hdl;
	lock_get(&tx->lock);
	if (!tx->staged.data) {
		lock_release(&tx->lock);
		return init_mi_error(409, MI_SSTR("no staged config"));
	}
	candidate = malloc(tx->staged.len + 1);
	if (!candidate) {
		lock_release(&tx->lock);
		return init_mi_error(500, MI_SSTR("out of memory"));
	}
	memcpy(candidate, tx->staged.data, tx->staged.len);
	candidate[tx->staged.len] = '\0';
	candidate_len = tx->staged.len;
	expected_hash = tx->base_hash;
	candidate_version = tx->staged.version;
	lock_release(&tx->lock);

	if (validate_on_commit &&
			validate_config_data(candidate, candidate_len) < 0) {
		free(candidate);
		update_stat(failures, 1);
		return init_mi_error(400, MI_SSTR("staged config failed opensips -C validation"));
	}

	if (hash_current(&current_hash, &current, &current_len, &st) < 0) {
		free(candidate);
		update_stat(failures, 1);
		return init_mi_error(500, MI_SSTR("cannot read active config"));
	}
	if (current_hash != expected_hash) {
		free(current);
		free(candidate);
		update_stat(conflicts, 1);
		return init_mi_error(409, MI_SSTR("active config changed since stage"));
	}

	if (atomic_replace(cfg_path, candidate, candidate_len, &st) < 0) {
		free(current);
		free(candidate);
		update_stat(failures, 1);
		return init_mi_error(500, MI_SSTR("cannot atomically install staged config"));
	}

	if (reload_routing_script() < 0) {
		/*
		 * reload_routing_script() validates in every process before sending
		 * the switch command, so the old in-memory routes are still active
		 * on failure. Restore the on-disk file to the same snapshot.
		 */
		restored = atomic_replace(cfg_path, current, current_len, &st) == 0;
		if (!restored)
			LM_CRIT("route reload failed and active config file restoration also failed\n");
		free(current);
		free(candidate);
		update_stat(failures, 1);
		if (!restored)
			return init_mi_error(500, MI_SSTR("reload failed and file restore failed; manual intervention required"));
		return init_mi_error(500, MI_SSTR("reload validation failed; config restored"));
	}

	lock_get(&tx->lock);
	if (snapshot_set(&tx->rollback, current, current_len, tx->active_version) < 0)
		LM_ERR("commit succeeded but rollback snapshot could not be retained\n");
	tx->active_version = candidate_version;
	tx->active_hash = fnv1a64(candidate, candidate_len);
	snapshot_clear(&tx->staged);
	tx->base_hash = 0;
	lock_release(&tx->lock);
	free(current);
	free(candidate);
	update_stat(commits, 1);
	return build_status();
}

static mi_response_t *mi_rollback_impl(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	char *rollback = NULL, *current = NULL;
	int rollback_len = 0, current_len = 0;
	struct stat st;
	uint64_t current_hash, expected_active_hash;
	unsigned long rollback_version;
	int restored;

	(void)params;
	(void)async_hdl;
	lock_get(&tx->lock);
	if (!tx->rollback.data) {
		lock_release(&tx->lock);
		return init_mi_error(409, MI_SSTR("no rollback snapshot"));
	}
	rollback = malloc(tx->rollback.len + 1);
	if (!rollback) {
		lock_release(&tx->lock);
		return init_mi_error(500, MI_SSTR("out of memory"));
	}
	memcpy(rollback, tx->rollback.data, tx->rollback.len);
	rollback[tx->rollback.len] = '\0';
	rollback_len = tx->rollback.len;
	rollback_version = tx->rollback.version;
	expected_active_hash = tx->active_hash;
	lock_release(&tx->lock);

	if (hash_current(&current_hash, &current, &current_len, &st) < 0) {
		free(rollback);
		return init_mi_error(500, MI_SSTR("cannot read active config"));
	}
	if (current_hash != expected_active_hash) {
		free(current);
		free(rollback);
		update_stat(conflicts, 1);
		return init_mi_error(409,
			MI_SSTR("active config changed outside config_tx; refusing rollback"));
	}
	if (atomic_replace(cfg_path, rollback, rollback_len, &st) < 0) {
		free(current);
		free(rollback);
		update_stat(failures, 1);
		return init_mi_error(500, MI_SSTR("cannot install rollback config"));
	}
	if (reload_routing_script() < 0) {
		restored = atomic_replace(cfg_path, current, current_len, &st) == 0;
		if (!restored)
			LM_CRIT("rollback validation failed and current config restoration also failed\n");
		free(current);
		free(rollback);
		update_stat(failures, 1);
		if (!restored)
			return init_mi_error(500, MI_SSTR("rollback reload failed and file restore failed; manual intervention required"));
		return init_mi_error(500, MI_SSTR("rollback reload failed; current config restored"));
	}

	lock_get(&tx->lock);
	if (snapshot_set(&tx->rollback, current, current_len, tx->active_version) < 0)
		LM_ERR("rollback succeeded but roll-forward snapshot could not be retained\n");
	tx->active_version = rollback_version;
	tx->active_hash = fnv1a64(rollback, rollback_len);
	snapshot_clear(&tx->staged);
	tx->base_hash = 0;
	lock_release(&tx->lock);
	free(current);
	free(rollback);
	update_stat(rollbacks, 1);
	return build_status();
}

/*
 * Mutating operations are serialized with a "busy" flag rather than by
 * holding a lock for their whole duration: they fork/wait for the external
 * validator and run reload_routing_script(), which waits (up to 20s) for
 * every script process to process an IPC job. A process spinning on a
 * gen_lock_t (e.g. a second MI worker, or a SIP worker running an MI
 * command from script) would never serve that IPC job, so the reload would
 * time out. A concurrent request is rejected instead.
 */
static mi_response_t *run_serialized(
	mi_response_t *(*impl)(const mi_params_t *, struct mi_handler *),
	const mi_params_t *params, struct mi_handler *async_hdl)
{
	mi_response_t *resp;

	lock_get(&tx->lock);
	if (tx->busy) {
		lock_release(&tx->lock);
		return init_mi_error(409,
			MI_SSTR("another config_tx operation is in progress"));
	}
	tx->busy = 1;
	lock_release(&tx->lock);

	resp = impl(params, async_hdl);

	lock_get(&tx->lock);
	tx->busy = 0;
	lock_release(&tx->lock);
	return resp;
}

static mi_response_t *mi_stage(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	return run_serialized(mi_stage_impl, params, async_hdl);
}

static mi_response_t *mi_discard(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	return run_serialized(mi_discard_impl, params, async_hdl);
}

static mi_response_t *mi_commit(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	return run_serialized(mi_commit_impl, params, async_hdl);
}

static mi_response_t *mi_rollback(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	return run_serialized(mi_rollback_impl, params, async_hdl);
}

#ifdef UNIT_TESTS
int config_tx_test_replaceable_path(const char *path)
{
	return replaceable_regular_path(path);
}

unsigned long long config_tx_test_hash(const char *text)
{
	if (!text)
		return 0;
	return (unsigned long long)fnv1a64(text, strlen(text));
}

int config_tx_test_count_lines(const char *text)
{
	if (!text)
		return 0;
	return count_lines(text, strlen(text));
}

int config_tx_test_first_changed_line(const char *left, const char *right)
{
	if (!left || !right)
		return -1;
	return first_changed_line(left, strlen(left), right, strlen(right));
}
#endif

static int mod_init(void)
{
	if (!cfg_file || !*cfg_file || !strcmp(cfg_file, "-")) {
		LM_ERR("config_tx requires a file-backed OpenSIPS configuration\n");
		return -1;
	}
	cfg_path = absolute_path_dup(cfg_file, strlen(cfg_file));
	if (!cfg_path) {
		LM_ERR("cannot resolve the absolute path of '%s'\n", cfg_file);
		return -1;
	}
	if (!replaceable_regular_path(cfg_path)) {
		LM_ERR("config_tx requires cfg_file to be a regular non-symlink path "
			"(%s)\n", cfg_path);
		goto error_path;
	}
	if (max_config_size < 1024)
		max_config_size = 1024;

	tx = shm_malloc(sizeof(*tx));
	if (!tx) {
		LM_ERR("no more shm memory\n");
		goto error_path;
	}
	memset(tx, 0, sizeof(*tx));
	if (!lock_init(&tx->lock)) {
		shm_free(tx);
		tx = NULL;
		goto error_path;
	}
	if (hash_current(&tx->active_hash, NULL, NULL, NULL) < 0) {
		LM_ERR("cannot hash active configuration during config_tx initialization\n");
		lock_destroy(&tx->lock);
		shm_free(tx);
		tx = NULL;
		goto error_path;
	}
	tx->active_version = 1;
	tx->next_version = 2;
	return 0;

error_path:
	free(cfg_path);
	cfg_path = NULL;
	return -1;
}

static void mod_destroy(void)
{
	if (!tx)
		return;
	snapshot_clear(&tx->staged);
	snapshot_clear(&tx->rollback);
	lock_destroy(&tx->lock);
	shm_free(tx);
	tx = NULL;
	free(cfg_path);
	cfg_path = NULL;
}
