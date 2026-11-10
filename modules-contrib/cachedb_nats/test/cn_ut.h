/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * Unit test suite of the cachedb_nats module: one entry point per test file,
 * all run from mod_tests() (test.c) through cn_ut_all() (test_all.c).
 * The entry-point list is generated (tools/gen_suite.py).
 */

#ifndef CN_UT_H
#define CN_UT_H

void cn_ut_all(void);
void cn_ut_cached_config_len(void);
void cn_ut_cas_backoff(void);
void cn_ut_cdb_url_servers(void);
void cn_ut_counter_overflow(void);
void cn_ut_counter_parse_strict(void);
void cn_ut_counter_value_uaf(void);
void cn_ut_cseq_merge_ordering(void);
void cn_ut_disconnected_ops(void);
void cn_ut_doc_filter(void);
void cn_ut_emit_rows(void);
void cn_ut_fmt_table(void);
void cn_ut_fts_optional(void);
void cn_ut_index_stale_recovery(void);
void cn_ut_insecure_url_warn(void);
void cn_ut_json_escape(void);
void cn_ut_json_foreach(void);
void cn_ut_json_name_passthrough(void);
void cn_ut_json_parse_guard(void);
void cn_ut_kv_epoch_refresh(void);
void cn_ut_kv_history_bounds(void);
void cn_ut_kv_key_encode(void);
void cn_ut_kv_key_validate(void);
void cn_ut_kv_put_fastfail_leak(void);
void cn_ut_kv_ttl_legacy_bucket(void);
void cn_ut_kv_ttl_zero_guard(void);
void cn_ut_kvget_copy_pattern(void);
void cn_ut_kvobs_filter(void);
void cn_ut_last_mod_int64(void);
void cn_ut_map_compose(void);
void cn_ut_map_key_encode(void);
void cn_ut_map_ops(void);
void cn_ut_mod_exports(void);
void cn_ut_modparam_guards(void);
void cn_ut_native_key_validation(void);
void cn_ut_op_stats(void);
void cn_ut_oversize_row(void);
void cn_ut_pk_stack_key(void);
void cn_ut_poison_value(void);
void cn_ut_raw_query_cols(void);
void cn_ut_read_expiry_filter(void);
void cn_ut_reap_first_jitter(void);
void cn_ut_reap_gauges(void);
void cn_ut_reap_interval_zero_guard(void);
void cn_ut_reap_pass(void);
void cn_ut_reap_project(void);
void cn_ut_reap_select(void);
void cn_ut_reap_watch_enum(void);
void cn_ut_reaper_sched(void);
void cn_ut_reg_filter(void);
void cn_ut_reg_row_scan(void);
void cn_ut_reg_scan_enum(void);
void cn_ut_reg_sort_page(void);
void cn_ut_reject_nul_field(void);
void cn_ut_remove_stub(void);
void cn_ut_resync_timer(void);
void cn_ut_row_exp_compute(void);
void cn_ut_row_fold_equiv(void);
void cn_ut_row_write(void);
void cn_ut_schema_version_legacy(void);
void cn_ut_seed_shape_adversarial(void);
void cn_ut_sink_emit_int(void);
void cn_ut_sink_emit_string(void);
void cn_ut_str_to_buf_nul(void);
void cn_ut_strict_security(void);
void cn_ut_strip_private_keys(void);
void cn_ut_ttl_cas_predicate(void);
void cn_ut_ttl_delete_header(void);
void cn_ut_ttl_dl_bindings(void);
void cn_ut_ttl_errcode_classify(void);
void cn_ut_ttl_fetch_marker(void);
void cn_ut_ttl_key_subject(void);
void cn_ut_ttl_linger_slack(void);
void cn_ut_update_creates_doc(void);
void cn_ut_update_nested_dict(void);
void cn_ut_update_nul_poison(void);
void cn_ut_url_parse_nonul(void);
void cn_ut_watch_resume(void);
void cn_ut_watcher_loop(void);
void cn_ut_write_hygiene_scope(void);

/* -- extra -- */
/* a cdb_pair_t built without cdb_mk_pair(); see test.c */
struct cdb_pair *cn_ut_mk_pair(const char *key, int klen,
	const char *subkey, int sklen);
/* -- end extra -- */

#endif /* CN_UT_H */
