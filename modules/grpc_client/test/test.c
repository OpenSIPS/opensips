/*
 * Unit tests for grpc_client input validation.
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

int grpc_client_test_metadata_key(const char *input, char *out, int out_size);
int grpc_client_test_metadata_value(const char *key, const char *value);
int grpc_client_test_method(const char *input);

static void test_metadata_keys(void)
{
	char out[128];

	ok(grpc_client_test_metadata_key("x-tenant", out, sizeof(out)) > 0 &&
		!strcmp(out, "x-tenant"), "grpc-metadata-valid");
	ok(grpc_client_test_metadata_key("Authorization", out, sizeof(out)) > 0 &&
		!strcmp(out, "authorization"), "grpc-metadata-normalize-case");
	ok(grpc_client_test_metadata_key("x_trace.id", out, sizeof(out)) > 0 &&
		!strcmp(out, "x_trace.id"), "grpc-metadata-valid-specials");
	ok(grpc_client_test_metadata_key("bad key", out, sizeof(out)) < 0,
		"grpc-metadata-reject-space");
	ok(grpc_client_test_metadata_key("bad:key", out, sizeof(out)) < 0,
		"grpc-metadata-reject-colon");
	ok(grpc_client_test_metadata_key("grpc-timeout", out, sizeof(out)) < 0,
		"grpc-metadata-reject-reserved-prefix");
	ok(grpc_client_test_metadata_value("authorization", "Bearer token"),
		"grpc-metadata-printable-text-value");
	ok(!grpc_client_test_metadata_value("authorization", "Bearer\ntoken"),
		"grpc-metadata-reject-control-in-text-value");
	ok(grpc_client_test_metadata_value("opaque-bin", "raw\nbytes"),
		"grpc-metadata-binary-value-allows-octets");
}

static void test_methods(void)
{
	ok(grpc_client_test_method("/rating.RatingService/Authorize"),
		"grpc-method-valid");
	ok(grpc_client_test_method("/pkg.Service/Method"),
		"grpc-method-package-valid");
	ok(!grpc_client_test_method("pkg.Service/Method"),
		"grpc-method-require-leading-slash");
	ok(!grpc_client_test_method("/OnlyService"),
		"grpc-method-require-method-component");
	ok(!grpc_client_test_method("//Method"),
		"grpc-method-reject-empty-service");
	ok(!grpc_client_test_method("/pkg.Service/Method/Extra"),
		"grpc-method-reject-extra-slash");
	ok(!grpc_client_test_method("/pkg.Service/"),
		"grpc-method-reject-empty-method");
	ok(!grpc_client_test_method("/pkg.Service/Bad Method"),
		"grpc-method-reject-whitespace");
	ok(!grpc_client_test_method("/pkg..Service/Method"),
		"grpc-method-reject-empty-service-component");
	ok(!grpc_client_test_method("/1pkg.Service/Method"),
		"grpc-method-reject-numeric-service-start");
	ok(!grpc_client_test_method("/pkg.Service/1Method"),
		"grpc-method-reject-numeric-method-start");
	ok(!grpc_client_test_method("/pkg.Service/Bad?Method"),
		"grpc-method-reject-non-protobuf-identifier");
	ok(grpc_client_test_method("/pkg_name.Service_2/Method_3"),
		"grpc-method-accept-protobuf-identifiers");
}

void mod_tests(void)
{
	test_metadata_keys();
	test_methods();
}
