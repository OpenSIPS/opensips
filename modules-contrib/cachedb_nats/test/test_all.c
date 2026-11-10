/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * Runs every test file of the suite (generated: tools/gen_suite.py).
 */

#include <tap.h>

#include "cn_ut.h"

void cn_ut_all(void)
{
	cn_ut_cached_config_len();
	cn_ut_cas_backoff();
	cn_ut_cdb_url_servers();
	cn_ut_counter_overflow();
	cn_ut_counter_parse_strict();
	cn_ut_counter_value_uaf();
	cn_ut_cseq_merge_ordering();
	cn_ut_disconnected_ops();
	cn_ut_doc_filter();
	cn_ut_emit_rows();
	cn_ut_fmt_table();
	cn_ut_fts_optional();
	cn_ut_index_stale_recovery();
	cn_ut_insecure_url_warn();
	cn_ut_json_escape();
	cn_ut_json_foreach();
	cn_ut_json_name_passthrough();
	cn_ut_json_parse_guard();
	cn_ut_kv_epoch_refresh();
	cn_ut_kv_history_bounds();
	cn_ut_kv_key_encode();
	cn_ut_kv_key_validate();
	cn_ut_kv_put_fastfail_leak();
	cn_ut_kv_ttl_legacy_bucket();
	cn_ut_kv_ttl_zero_guard();
	cn_ut_kvget_copy_pattern();
	cn_ut_kvobs_filter();
	cn_ut_last_mod_int64();
	cn_ut_map_compose();
	cn_ut_map_key_encode();
	cn_ut_map_ops();
	cn_ut_mod_exports();
	cn_ut_modparam_guards();
	cn_ut_native_key_validation();
	cn_ut_op_stats();
	cn_ut_oversize_row();
	cn_ut_pk_stack_key();
	cn_ut_poison_value();
	cn_ut_raw_query_cols();
	cn_ut_read_expiry_filter();
	cn_ut_reap_first_jitter();
	cn_ut_reap_gauges();
	cn_ut_reap_interval_zero_guard();
	cn_ut_reap_pass();
	cn_ut_reap_project();
	cn_ut_reap_select();
	cn_ut_reap_watch_enum();
	cn_ut_reaper_sched();
	cn_ut_reg_filter();
	cn_ut_reg_row_scan();
	cn_ut_reg_scan_enum();
	cn_ut_reg_sort_page();
	cn_ut_reject_nul_field();
	cn_ut_remove_stub();
	cn_ut_resync_timer();
	cn_ut_row_exp_compute();
	cn_ut_row_fold_equiv();
	cn_ut_row_write();
	cn_ut_schema_version_legacy();
	cn_ut_seed_shape_adversarial();
	cn_ut_sink_emit_int();
	cn_ut_sink_emit_string();
	cn_ut_str_to_buf_nul();
	cn_ut_strict_security();
	cn_ut_strip_private_keys();
	cn_ut_ttl_cas_predicate();
	cn_ut_ttl_delete_header();
	cn_ut_ttl_dl_bindings();
	cn_ut_ttl_errcode_classify();
	cn_ut_ttl_fetch_marker();
	cn_ut_ttl_key_subject();
	cn_ut_ttl_linger_slack();
	cn_ut_update_creates_doc();
	cn_ut_update_nested_dict();
	cn_ut_update_nul_poison();
	cn_ut_url_parse_nonul();
	cn_ut_watch_resume();
	cn_ut_watcher_loop();
	cn_ut_write_hygiene_scope();
}
