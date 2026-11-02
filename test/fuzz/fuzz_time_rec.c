/*
 * Copyright (c) 2026 OpenSIPS Project fuzzing effort
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fuzz_time_rec - exercise the RFC2445 time-recurrence engine (time_rec.c).
 *
 * Threat model:
 * - Untrusted input: time-recurrence strings parsed by opensips come from
 *   configuration and from database tables (drouting carrierroute rules,
 *   dialplan rules, cfgutils time checks).  Deployments that load routing
 *   data from external or partially operator-visible sources expose these
 *   parsers to non-core strings, and every deployment runs _check() against
 *   wall-clock time on every call.
 * - Trust boundary crossed: tmrec_parse()/tmrec_expr_parse() (property
 *   parsing: DTSTART/DTEND/DURATION/UNTIL/FREQ/INTERVAL/BYDAY/BYMDAY/
 *   BYYYDAY/BYMONTH/BYWEEKNO/WKST/TZID), the expr combinator parser
 *   (& / / / ! / parens), and the check side _tmrec_check()/
 *   _tmrec_expr_check() with varying timestamps.
 * - Attacker controls: the whole recurrence/expr string; the check time is
 *   derived from the input so different corpus entries evaluate different
 *   instants (date math edge cases are where the historical bugs live).
 * - Real bug here: out-of-bounds reads in byxxx handling, integer issues in
 *   date arithmetic, unbounded loops in recurrence iteration, assertions on
 *   malformed properties.
 *
 * Design notes:
 * - the SAME input is fed to tmrec_parse (single rule), tmrec_expr_parse
 *   (combinator tree) and the two *_check_str one-shot variants, matching
 *   all four production entry points;
 * - allocation uses PKG_ALLOC (the fuzz build does not initialise shm, the
 *   modules that use SHM_ALLOC run after init_shm_mallocs() in production);
 * - _tmrec_check_str() requires write-able memory (upstream FIXME), so the
 *   input is always copied;
 * - check timestamps are derived from the last input bytes and clamped to
 *   2010..2060 to keep the evaluation inside realistic date ranges;
 * - inputs are capped at 4 KiB; embedded NULs are rejected.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../time_rec.h"

#include "../dprint.h"
#include "../globals.h"
#include "../cmds.h"
#include "../lib/list.h"
#include "../sr_module.h"
#include "../sr_module_deps.h"
#include "../socket_info.h"
#include "../msg_translator.h"

#include "../test/fuzz/fuzz_standalone.h"

#define MAX_TR_LEN 4096

int LLVMFuzzerTestOneInput(const char *data, size_t size)
{
	static char wbuf[MAX_TR_LEN + 1];
	tmrec *tr;
	tmrec_expr *trx;
	time_t t;
	size_t i;
	unsigned long seed;

	if (size == 0 || size > MAX_TR_LEN)
		return 0;

	for (i = 0; i < size; i++)
		if (data[i] == 0)
			return 0;

	memcpy(wbuf, data, size);
	wbuf[size] = '\0';

	/* derive a check time from the input: base year 2010 + clamped
	 * seconds from the trailing bytes */
	seed = 0;
	for (i = size > 4 ? size - 4 : 0; i < size; i++)
		seed = (seed << 8) | (unsigned char)data[i];
	t = (time_t)(1262304000 /* 2010-01-01 UTC */ +
	    (time_t)(seed % 1586774400UL) /* +50 years */);

	/* single recurrence rule */
	tr = tmrec_parse(wbuf, PKG_ALLOC);
	if (tr != NULL) {
		_tmrec_check(tr, t);
		tmrec_free(tr);
	}

	/* combinator expression */
	trx = tmrec_expr_parse(wbuf, PKG_ALLOC);
	if (trx != NULL) {
		_tmrec_expr_check(trx, t);
		tmrec_expr_free(trx);
	}

	/* one-shot string variants (write-able copies as documented) */
	_tmrec_check_str(wbuf, t);
	_tmrec_expr_check_str(wbuf, t);

	return 0;
}
