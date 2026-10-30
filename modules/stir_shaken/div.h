/* Copyright (C) 2026 OpenSIPS Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef STIR_SHAKEN_DIV_H
#define STIR_SHAKEN_DIV_H

#include "passport.h"

/* AS structural selection only; incoming signatures are a VS responsibility. */
#define DIV_MAX_PASSPORTS 64
struct div_chain {
	struct parsed_identity tokens[DIV_MAX_PASSPORTS];
	int count;
	str orig;
	str previous;
	time_t iat;
};

int div_normalize(str *identity, int allow_uri);
int div_identity_equal(str a, str b);
int div_chain_add(struct div_chain *chain, str *body);
int div_chain_select(struct div_chain *chain, str *requested_div);
void div_chain_cleanup(struct div_chain *chain);
int div_get_claim(cJSON *payload, const char *name, int array, int index, str *out);
int div_has_destination(cJSON *payload, str *id);

#endif
