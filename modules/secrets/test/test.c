/*
 * Unit tests for secrets provider validation and exact JSON lookup.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <tap.h>
#include <string.h>

int secrets_test_vault_scheme_allowed(const char *scheme, int allow_insecure);
int secrets_test_k8s_namespace_valid(const char *value);
int secrets_test_k8s_secret_name_valid(const char *value);
int secrets_test_k8s_key_valid(const char *value);
int secrets_test_json_path(const char *json, const char *path,
	const char *expected);
int secrets_test_base64_valid(const char *value);
int secrets_test_header_value_valid(const char *value);
int secrets_test_json_depth_ok(const char *json);

static void test_json_depth(void)
{
	char deep[256];

	memset(deep, '[', sizeof(deep) - 1);
	deep[sizeof(deep) - 1] = '\0';

	ok(secrets_test_json_depth_ok("{\"data\":{\"data\":{\"a\":[1]}}}"),
		"secrets-json-depth-normal");
	ok(secrets_test_json_depth_ok("{\"s\":\"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\"}"),
		"secrets-json-depth-ignore-strings");
	ok(!secrets_test_json_depth_ok(deep), "secrets-json-depth-reject-deep");
	ok(!secrets_test_json_path(deep, "a", "b"),
		"secrets-json-path-deep-not-parsed");
}

static void test_input_validation(void)
{
	ok(secrets_test_base64_valid("c2VjcmV0"), "secrets-base64-plain");
	ok(secrets_test_base64_valid("cw=="), "secrets-base64-padded");
	ok(!secrets_test_base64_valid("c2VjcmV"), "secrets-base64-reject-length");
	ok(!secrets_test_base64_valid("c2Vj\ncmV0"),
		"secrets-base64-reject-newline");
	ok(!secrets_test_base64_valid("cw=a"), "secrets-base64-reject-inner-pad");
	ok(!secrets_test_base64_valid("c==="), "secrets-base64-reject-long-pad");

	ok(secrets_test_header_value_valid("s.abcDEF123"),
		"secrets-header-token");
	ok(!secrets_test_header_value_valid("tok\r\nX-Evil: 1"),
		"secrets-header-reject-crlf");
}

static void test_vault_transport_policy(void)
{
	ok(secrets_test_vault_scheme_allowed("https", 0),
		"secrets-vault-https-default");
	ok(!secrets_test_vault_scheme_allowed("http", 0),
		"secrets-vault-http-requires-opt-in");
	ok(secrets_test_vault_scheme_allowed("http", 1),
		"secrets-vault-http-explicit-opt-in");
	ok(!secrets_test_vault_scheme_allowed("ftp", 1),
		"secrets-vault-reject-unsupported-scheme");
}

static void test_kubernetes_names(void)
{
	char long_label[65];

	memset(long_label, 'a', sizeof(long_label) - 1);
	long_label[sizeof(long_label) - 1] = '\0';

	ok(secrets_test_k8s_namespace_valid("default"),
		"secrets-k8s-namespace-default");
	ok(secrets_test_k8s_namespace_valid("team-1"),
		"secrets-k8s-namespace-hyphen");
	ok(!secrets_test_k8s_namespace_valid("Team"),
		"secrets-k8s-namespace-reject-uppercase");
	ok(!secrets_test_k8s_namespace_valid("team.dev"),
		"secrets-k8s-namespace-reject-dot");
	ok(!secrets_test_k8s_namespace_valid("-team"),
		"secrets-k8s-namespace-reject-leading-hyphen");
	ok(!secrets_test_k8s_namespace_valid(long_label),
		"secrets-k8s-namespace-reject-long-label");

	ok(secrets_test_k8s_secret_name_valid("db-secret"),
		"secrets-k8s-secret-name");
	ok(secrets_test_k8s_secret_name_valid("db.secret"),
		"secrets-k8s-secret-subdomain");
	ok(!secrets_test_k8s_secret_name_valid("DB-secret"),
		"secrets-k8s-secret-reject-uppercase");
	ok(!secrets_test_k8s_secret_name_valid("db_secret"),
		"secrets-k8s-secret-reject-underscore");
	ok(!secrets_test_k8s_secret_name_valid("db..secret"),
		"secrets-k8s-secret-reject-empty-label");
	ok(!secrets_test_k8s_secret_name_valid("db-.secret"),
		"secrets-k8s-secret-reject-label-ending-hyphen");
}

static void test_kubernetes_keys(void)
{
	ok(secrets_test_k8s_key_valid("tls.crt"),
		"secrets-k8s-key-dot");
	ok(secrets_test_k8s_key_valid("DB_PASSWORD"),
		"secrets-k8s-key-uppercase-underscore");
	ok(secrets_test_k8s_key_valid("token-1"),
		"secrets-k8s-key-hyphen");
	ok(!secrets_test_k8s_key_valid("path/key"),
		"secrets-k8s-key-reject-slash");
	ok(!secrets_test_k8s_key_valid("space key"),
		"secrets-k8s-key-reject-space");
}

static void test_json_path_case(void)
{
	const char *json =
		"{\"data\":{\"Password\":\"Upper\",\"password\":\"lower\"}}";

	ok(secrets_test_json_path(json, "data.Password", "Upper"),
		"secrets-json-path-exact-upper");
	ok(secrets_test_json_path(json, "data.password", "lower"),
		"secrets-json-path-exact-lower");
	ok(!secrets_test_json_path(json, "data.PASSWORD", "Upper"),
		"secrets-json-path-case-sensitive");
}

void mod_tests(void)
{
	test_vault_transport_policy();
	test_kubernetes_names();
	test_kubernetes_keys();
	test_json_path_case();
	test_input_validation();
	test_json_depth();
}
