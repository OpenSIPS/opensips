/* Regression tests included in sql_cacher.c to exercise its private helpers. */
#include <tap.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

static void test_cache_spec(const char *suffix, int valid, int scope, int expire)
{
	char spec[1024];
	cache_entry_t *entry, *saved = entry_list ? *entry_list : NULL;
	int rc;

	snprintf(spec, sizeof(spec), "id=test\ndb_url=sqlite:///tmp/sql_cacher.db\n"
		"cachedb_url=local://\ntable=test\nkey=id\n%s", suffix);
	rc = parse_cache_entry(0, spec);
	ok((rc == 0) == valid, "cache_table parses/rejects '%s'", suffix);
	if (rc == 0) {
		entry = *entry_list;
		ok(entry->cache_lock.scope == scope && entry->expire == expire,
			"lock scope and expiry decoded correctly");
		*entry_list = saved;
		free_c_entry(entry);
	} else {
		ok(*entry_list == saved, "invalid specification is not published");
	}
}

static void test_cache_versions(void)
{
	cache_entry_t entry;
	pv_name_fix_t pv;
	char data[2 * INT_B64_ENC_LEN];
	str value = {data, sizeof(data)}, str_res;
	int version, number = 123, result;

	memset(&entry, 0, sizeof(entry));
	memset(&pv, 0, sizeof(pv));
	pv.c_entry = &entry;
	pv.col_offset = INT_B64_ENC_LEN;
	entry.cache_lock.scope = CACHE_LOCK_ROW;
	base64encode((unsigned char *)data + INT_B64_ENC_LEN,
		(unsigned char *)&number, 4);

	for (version = 3; version <= 6; version++) {
		base64encode((unsigned char *)data, (unsigned char *)&version, 4);
		entry.cache_lock.is_writing = 0;
		ok((cdb_val_decode(&pv, &value, 5, &str_res, &result) == 0)
			== (version == 5), "idle cache accepts only current version (%d)", version);
		entry.cache_lock.is_writing = 1;
		ok((cdb_val_decode(&pv, &value, 5, &str_res, &result) == 0)
			== (version == 4 || version == 5),
			"active reload accepts only current/previous version (%d)", version);
	}
	version = 4;
	base64encode((unsigned char *)data, (unsigned char *)&version, 4);
	entry.on_demand = 1;
	ok(cdb_val_decode(&pv, &value, 5, &str_res, &result) == 3,
		"on-demand cache never accepts previous generation");
	entry.on_demand = 0;
	entry.cache_lock.scope = CACHE_LOCK_TABLE;
	ok(cdb_val_decode(&pv, &value, 5, &str_res, &result) == 3,
		"table mode never accepts previous generation");
	entry.cache_lock.scope = CACHE_LOCK_ROW;
	entry.cache_lock.is_writing = 0;
	ok(cdb_val_decode(&pv, &value, 5, &str_res, &result) == 3,
		"deleted row becomes invisible when reload completes");
}

static struct {
	cache_entry_t entry;
	db_res_t result;
	db_row_t row;
	db_val_t values[2];
	int version, increment, fail_counter, fail_insert, freed, inserted;
} reload_test;

static int reload_use_table(db_con_t *con, const str *table)
{
	return 0;
}

static int reload_query(const db_con_t *con, const db_key_t *keys,
	const db_op_t *ops, const db_val_t *values, const db_key_t *cols,
	const int nkeys, const int ncols, const db_key_t order, db_res_t **result)
{
	*result = &reload_test.result;
	return 0;
}

static int reload_free_result(db_con_t *con, db_res_t *result)
{
	reload_test.freed++;
	return 0;
}

static int reload_add(cachedb_con *con, str *key, int increment,
	int expires, int *version)
{
	if (reload_test.fail_counter)
		return -1;
	reload_test.version += increment;
	*version = reload_test.version;
	return 0;
}

static int reload_insert(cachedb_con *con, str *key, str *value, int expires)
{
	pv_name_fix_t pv;
	str str_res;
	int result;

	reload_test.inserted++;
	/* A synchronous read from the cache while the real loader is inserting
	 * a row must proceed, and see a fully published version/state pair. */
	acquire_read_lock(reload_test.entry.cache_lock);
	ok(reload_test.entry.cache_lock.is_writing == reload_test.increment,
		"loader publishes the right reload state before writing rows");
	memset(&pv, 0, sizeof(pv));
	pv.c_entry = &reload_test.entry;
	pv.col_offset = INT_B64_ENC_LEN;
	ok(cdb_val_decode(&pv, value, reload_test.version, &str_res, &result) == 0 &&
		result == 123, "row inserted by loader decodes during concurrent read");
	release_read_lock(reload_test.entry.cache_lock);
	return reload_test.fail_insert ? -1 : 0;
}

static void test_full_reload(int increment, int empty, int fail_counter,
	int fail_insert, int changed_layout)
{
	db_handlers_t dbh;
	str col = str_init("value"), *columns[] = {&col};
	int rc;

	memset(&reload_test, 0, sizeof(reload_test));
	memset(&dbh, 0, sizeof(dbh));
	reload_test.entry.id = *_str("reload-test");
	reload_test.entry.db_url = *_str("sqlite:///tmp/sql-cacher-test.db");
	reload_test.entry.table = *_str("test");
	reload_test.entry.nr_columns = 1;
	reload_test.entry.nr_ints = 1;
	reload_test.entry.columns = columns;
	reload_test.entry.cache_lock.scope = CACHE_LOCK_ROW;
	reload_test.entry.cache_lock.ref_lock = lock_init_rw();
	reload_test.version = 7;
	reload_test.increment = increment;
	reload_test.fail_counter = fail_counter;
	reload_test.fail_insert = fail_insert;
	RES_ROWS(&reload_test.result) = &reload_test.row;
	RES_ROW_N(&reload_test.result) = !empty;
	ROW_VALUES(&reload_test.row) = reload_test.values;
	ROW_N(&reload_test.row) = 2;
	VAL_TYPE(&reload_test.values[0]) = DB_INT;
	VAL_INT(&reload_test.values[0]) = 1;
	VAL_TYPE(&reload_test.values[1]) = changed_layout ? DB_STR : DB_INT;
	VAL_INT(&reload_test.values[1]) = 123;
	dbh.c_entry = &reload_test.entry;
	dbh.db_funcs.use_table = reload_use_table;
	dbh.db_funcs.query = reload_query;
	dbh.db_funcs.free_result = reload_free_result;
	dbh.cdbf.add = reload_add;
	dbh.cdbf.set = reload_insert;

	rc = load_entire_table(&reload_test.entry, &dbh, increment);
	ok((rc == 0) == !(fail_counter || fail_insert || changed_layout),
		"full reload: startup=%d empty=%d counter-error=%d insert-error=%d layout-change=%d",
		!increment, empty, fail_counter, fail_insert, changed_layout);
	ok(reload_test.version == 7 +
		((fail_counter || changed_layout) ? 0 : increment),
		"reload preserves/increments version correctly, including empty results");
	ok(!reload_test.entry.cache_lock.is_writing &&
		!reload_test.entry.cache_lock.ref_lock->r_count &&
		!reload_test.entry.cache_lock.ref_lock->w_flag &&
		!reload_test.entry.cache_lock.ref_lock->sw_flag,
		"loader clears reload state and releases locks on every exit");
	ok(reload_test.freed == 1, "loader releases SQL result on every exit");
	ok(reload_test.inserted == !(empty || fail_counter || changed_layout),
		"loader only inserts rows after successful setup");
	lock_destroy_rw(reload_test.entry.cache_lock.ref_lock);
}

/* Use separate processes and the real shared-memory lock, not lock stubs. */
static void test_cache_locking(int scope, int writer)
{
	cache_lock_t *cache_lock;
	int fds[2], old_w_flag = 0, status;
	pid_t child;
	struct pollfd ready;
	char byte = 'x';

	cache_lock = shm_malloc(sizeof(*cache_lock));
	memset(cache_lock, 0, sizeof(*cache_lock));
	cache_lock->scope = scope;
	cache_lock->ref_lock = lock_init_rw();
	lock_cache_writes(*cache_lock);
	lock_cache_state(*cache_lock, old_w_flag);
	cache_lock->is_writing = 1;
	unlock_cache_state(*cache_lock, old_w_flag);
	if (pipe(fds) < 0 || (child = fork()) < 0) {
		fail("create reader/writer process");
		finish_cache_reload(cache_lock);
		lock_destroy_rw(cache_lock->ref_lock);
		shm_free(cache_lock);
		return;
	}
	if (child == 0) {
		close(fds[0]);
		if (writer)
			lock_cache_writes(*cache_lock);
		else
			acquire_read_lock(*cache_lock);
		if (write(fds[1], &byte, 1) != 1)
			_exit(1);
		if (writer)
			unlock_cache_writes(*cache_lock);
		else
			release_read_lock(*cache_lock);
		_exit(0);
	}
	close(fds[1]);
	ready.fd = fds[0];
	ready.events = POLLIN;
	status = poll(&ready, 1, 200);
	ok((status > 0 && (ready.revents & POLLIN)) ==
		(scope == CACHE_LOCK_ROW && !writer),
		"scope=%d: %s %s during reload", scope,
		writer ? "second writer" : "reader",
		scope == CACHE_LOCK_ROW && !writer ? "continues" : "waits");
	finish_cache_reload(cache_lock);
	status = poll(&ready, 1, 2000);
	ok(status > 0 && (ready.revents & POLLIN),
		"reader/writer completes after reload releases lock");
	if (status <= 0)
		kill(child, SIGKILL);
	waitpid(child, &status, 0);
	ok(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		"reader/writer exits successfully");
	close(fds[0]);
	ok(!cache_lock->is_writing && !cache_lock->ref_lock->r_count &&
		!cache_lock->ref_lock->w_flag && !cache_lock->ref_lock->sw_flag,
		"reload leaves no writing state or held locks");
	lock_destroy_rw(cache_lock->ref_lock);
	shm_free(cache_lock);
}

static void test_reload_boundary(int finishing)
{
	cache_lock_t *cache_lock;
	int fds[2], status, old_w_flag = 0;
	pid_t child;
	struct pollfd ready;
	char byte = 'x';

	cache_lock = shm_malloc(sizeof(*cache_lock));
	memset(cache_lock, 0, sizeof(*cache_lock));
	cache_lock->scope = CACHE_LOCK_ROW;
	cache_lock->ref_lock = lock_init_rw();
	if (finishing) {
		lock_cache_writes(*cache_lock);
		cache_lock->is_writing = 1;
	}
	acquire_read_lock(*cache_lock);
	if (pipe(fds) < 0 || (child = fork()) < 0) {
		fail("create reload-boundary process");
		release_read_lock(*cache_lock);
		if (finishing)
			finish_cache_reload(cache_lock);
		lock_destroy_rw(cache_lock->ref_lock);
		shm_free(cache_lock);
		return;
	}
	if (child == 0) {
		close(fds[0]);
		if (!finishing) {
			lock_cache_writes(*cache_lock);
			lock_cache_state(*cache_lock, old_w_flag);
			cache_lock->is_writing = 1;
			unlock_cache_state(*cache_lock, old_w_flag);
		}
		finish_cache_reload(cache_lock);
		_exit(write(fds[1], &byte, 1) == 1 ? 0 : 1);
	}
	close(fds[1]);
	ready.fd = fds[0];
	ready.events = POLLIN;
	ok(poll(&ready, 1, 200) == 0 && cache_lock->is_writing == finishing,
		"reload %s waits for an in-flight reader without changing its state",
		finishing ? "completion" : "start");
	release_read_lock(*cache_lock);
	status = poll(&ready, 1, 2000);
	ok(status > 0 && (ready.revents & POLLIN),
		"reload boundary completes after in-flight reader releases lock");
	if (status <= 0)
		kill(child, SIGKILL);
	waitpid(child, &status, 0);
	ok(WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
		!cache_lock->is_writing, "reload boundary leaves idle state");
	close(fds[0]);
	lock_destroy_rw(cache_lock->ref_lock);
	shm_free(cache_lock);
}

void mod_tests(void)
{
	test_cache_spec("on_demand=0", 1, CACHE_LOCK_ROW, DEFAULT_ON_DEMAND_EXPIRE);
	test_cache_spec("full_caching_lock_scope=row", 1, CACHE_LOCK_ROW,
		DEFAULT_ON_DEMAND_EXPIRE);
	test_cache_spec("full_caching_lock_scope=table", 1, CACHE_LOCK_TABLE,
		DEFAULT_ON_DEMAND_EXPIRE);
	test_cache_spec("on_demand=0\nexpire=120\nfull_caching_lock_scope=table",
		1, CACHE_LOCK_TABLE, 120);
	test_cache_spec("on_demand=1\nexpire=300", 1, CACHE_LOCK_ROW, 300);
	test_cache_spec("full_caching_lock_scope=invalid", 0, 0, 0);
	test_cache_spec("full_caching_lock_scope=", 0, 0, 0);
	test_cache_spec("full_caching_lock_scope=row\nunknown=1", 0, 0, 0);
	test_cache_spec("x=1", 0, 0, 0);
	test_cache_spec("columns=a b\non_demand=0\nfull_caching_lock_scope=table",
		1, CACHE_LOCK_TABLE, DEFAULT_ON_DEMAND_EXPIRE);
	test_cache_versions();
	sr_register_identifier(sql_srg, CHAR_INT("reload-test"),
		SR_STATUS_NO_DATA, CHAR_INT("test"), 20);
	test_full_reload(0, 0, 0, 0, 0);
	test_full_reload(1, 0, 0, 0, 0);
	test_full_reload(1, 1, 0, 0, 0);
	test_full_reload(1, 0, 1, 0, 0);
	test_full_reload(1, 0, 0, 1, 0);
	test_full_reload(1, 0, 0, 0, 1);
	test_cache_locking(CACHE_LOCK_ROW, 0);
	test_cache_locking(CACHE_LOCK_ROW, 1);
	test_cache_locking(CACHE_LOCK_TABLE, 0);
	test_cache_locking(CACHE_LOCK_TABLE, 1);
	test_reload_boundary(0);
	test_reload_boundary(1);
}
