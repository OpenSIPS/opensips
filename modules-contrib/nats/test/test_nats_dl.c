/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
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
 *
 * The libnats loader (nats_dl.c): the library is opened with dlopen() on
 * first use, found by its name, by an explicit path or by
 * $NATS_DL_LIBNATS_PATH, and every function of the table is resolved --
 * or nothing is.  A library whose major.minor is not the one of the
 * headers the module was compiled against is refused before any of its
 * functions is called: the structures passed by pointer differ.
 *
 * Against the libnats installed on the host, the one the module would
 * load.  Runs first in the suite: nothing has loaded the library yet,
 * and it leaves it unloaded.
 */

#include <tap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <nats/nats.h>

#include "../nats_dl.h"

#include "nats_ut.h"

/* no function of the table may be left behind by a failed or undone load */
static int table_is_empty(void)
{
	static const nats_dl_funcs_t empty;

	return memcmp(&nats_dl, &empty, sizeof empty) == 0;
}

static int table_is_full(void)
{
	void *slot[sizeof(nats_dl_funcs_t) / sizeof(void *)];
	unsigned i;

	memcpy(slot, &nats_dl, sizeof slot);
	for (i = 0; i < sizeof slot / sizeof slot[0]; i++)
		if (!slot[i])
			return 0;
	return 1;
}

void nats_ut_nats_dl(void)
{
	char found[256] = "";
	const char *env = getenv("NATS_DL_LIBNATS_PATH");
	char saved_env[256] = "";
	void *h;

	if (env)
		snprintf(saved_env, sizeof saved_env, "%s", env);
	unsetenv("NATS_DL_LIBNATS_PATH");

	/* before any load */
	ok(!nats_dl_is_loaded(), "not loaded before the first use");
	ok(nats_dl_path() == NULL, "no path before the first use");
	ok(table_is_empty(), "the table is empty before the first use");

	/* found by name */
	cmp_ok(nats_dl_load(NULL), "==", 0, "libnats is found by its name");
	ok(nats_dl_is_loaded(), "loaded");
	ok(nats_dl_path() != NULL, "the path that was opened is reported");
	if (nats_dl_path())
		snprintf(found, sizeof found, "%s", nats_dl_path());
	ok(table_is_full(), "every function of the table is resolved");
	if (nats_dl.natsStatus_GetText)
		is(nats_dl.natsStatus_GetText(NATS_OK), "OK",
			"a call through the table reaches libnats");
	else
		fail("a call through the table reaches libnats");
	/* a second load */
	cmp_ok(nats_dl_load(NULL), "==", 0, "loading again is a no-op");
	cmp_ok(nats_dl_load("/nonexistent/libnats.so.999"), "==", 0,
		"...also with a path: the loaded library stays");
	is(nats_dl_path(), found, "...and its path too");

	/* unload */
	nats_dl_unload();
	ok(!nats_dl_is_loaded(), "not loaded after the unload");
	ok(nats_dl_path() == NULL, "no path after the unload");
	ok(table_is_empty(), "the table is emptied by the unload");
	nats_dl_unload();
	ok(!nats_dl_is_loaded(), "a second unload does nothing");

	/* explicit path */
	cmp_ok(nats_dl_load(found), "==", 0, "an explicit path is loaded");
	ok(nats_dl_is_loaded() && table_is_full(), "...with the table filled");
	nats_dl_unload();
	cmp_ok(nats_dl_load("/nonexistent/libnats.so.999"), "==", -1,
		"an explicit path that cannot be opened fails");
	ok(!nats_dl_is_loaded() && nats_dl_path() == NULL && table_is_empty(),
		"...and nothing is loaded in its place");
	cmp_ok(nats_dl_load(""), "==", 0,
		"an empty path is no path: found by name");
	nats_dl_unload();

	/* $NATS_DL_LIBNATS_PATH */
	setenv("NATS_DL_LIBNATS_PATH", found, 1);
	cmp_ok(nats_dl_load(NULL), "==", 0, "$NATS_DL_LIBNATS_PATH is loaded");
	is(nats_dl_path(), found, "...and reported as the path");
	nats_dl_unload();
	setenv("NATS_DL_LIBNATS_PATH", "/nonexistent/libnats.so.bad", 1);
	cmp_ok(nats_dl_load(NULL), "==", 0,
		"a $NATS_DL_LIBNATS_PATH that cannot be opened: found by name");
	ok(nats_dl_is_loaded() && table_is_full(), "...with the table filled");
	nats_dl_unload();
	setenv("NATS_DL_LIBNATS_PATH", "", 1);
	cmp_ok(nats_dl_load(NULL), "==", 0,
		"an empty $NATS_DL_LIBNATS_PATH is ignored");
	nats_dl_unload();
	unsetenv("NATS_DL_LIBNATS_PATH");

	/* the header / library version guard */
	cmp_ok(nats_dl_version_compatible(0x030F00, 0x030F00), "==", 1,
		"same version is compatible");
	cmp_ok(nats_dl_version_compatible(0x030F00, 0x030F07), "==", 1,
		"another patch level is compatible");
	cmp_ok(nats_dl_version_compatible(0x030F07, 0x030F00), "==", 1,
		"...in both directions");
	cmp_ok(nats_dl_version_compatible(0x030E00, 0x030F00), "==", 0,
		"a newer minor at run time (3.14 headers, 3.15 library) is refused");
	cmp_ok(nats_dl_version_compatible(0x030F00, 0x030E00), "==", 0,
		"an older minor at run time is refused");
	cmp_ok(nats_dl_version_compatible(0x030F00, 0x040F00), "==", 0,
		"another major is refused");
	cmp_ok(nats_dl_version_compatible(0x030FFF, 0x031000), "==", 0,
		"the patch byte does not carry into the minor");

	h = dlopen(found, RTLD_NOW | RTLD_LOCAL);
	ok(h != NULL, "libnats opens for the version check");
	if (h) {
		cmp_ok(nats_dl_check_version(h, found), "==", 0,
			"a library of the headers' version passes");
		nats_dl_test_compiled_version(NATS_VERSION_NUMBER + 0x100);
		cmp_ok(nats_dl_check_version(h, found), "==", -1,
			"headers one minor ahead of the library: refused");
		nats_dl_test_compiled_version(NATS_VERSION_NUMBER - 0x100);
		cmp_ok(nats_dl_check_version(h, found), "==", -1,
			"headers one minor behind the library: refused");
		nats_dl_test_compiled_version(0);
		dlclose(h);
	}
	/* a library that is not libnats: no nats_GetVersionNumber */
	h = dlopen("libm.so.6", RTLD_NOW | RTLD_LOCAL);
	skip(h == NULL, 3, "libm.so.6 cannot be opened on this host");
	cmp_ok(nats_dl_check_version(h, "libm.so.6"), "==", -1,
		"a library without nats_GetVersionNumber is refused");
	dlclose(h);
	cmp_ok(nats_dl_load("libm.so.6"), "==", -1,
		"...and nats_dl_load() does not load it");
	ok(!nats_dl_is_loaded() && table_is_empty(),
		"...leaving nothing loaded");
	end_skip;

	/* the whole load refuses a library of another version */
	nats_dl_test_compiled_version(NATS_VERSION_NUMBER + 0x100);
	cmp_ok(nats_dl_load(NULL), "==", -1,
		"nats_dl_load() refuses a libnats of another minor version");
	ok(!nats_dl_is_loaded() && nats_dl_path() == NULL && table_is_empty(),
		"...and leaves nothing loaded: no function of it can be called");
	nats_dl_test_compiled_version(0);
	cmp_ok(nats_dl_load(NULL), "==", 0,
		"with the headers' own version it loads again");
	nats_dl_unload();

	if (saved_env[0])
		setenv("NATS_DL_LIBNATS_PATH", saved_env, 1);
}
