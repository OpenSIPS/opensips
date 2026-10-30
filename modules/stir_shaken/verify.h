/* Copyright (C) 2026 OpenSIPS Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef STIR_SHAKEN_VERIFY_H
#define STIR_SHAKEN_VERIFY_H

#include "passport.h"
#include "../../pvar.h"

extern int verify_date_div_freshness;
int verify_init(void);
int stir_shaken_verify_passport(struct sip_msg *, int *, str *, pv_spec_t *, pv_spec_t *);
int stir_shaken_verify_chain(struct sip_msg *, pv_spec_t *, pv_spec_t *, str *, str *, int *);
int pv_get_identity_all(struct sip_msg *, pv_param_t *, pv_value_t *);
int pv_parse_identity_all(pv_spec_p, const str *);

/* Existing module trust-store lifecycle and SIP canonicalization. */
int stir_shaken_verify_credential(str *, struct parsed_identity *, str *);
int stir_shaken_verify_caller(struct sip_msg *, str *);
int stir_shaken_verify_destination(struct sip_msg *, str *);
int stir_shaken_verify_result(struct sip_msg *, pv_spec_t *, pv_spec_t *, int, const char *);
int stir_shaken_outer_freshness(void);
int passport_certificate_authority(X509 *, str *);
int passport_authority_der(str *, str *);

#endif
