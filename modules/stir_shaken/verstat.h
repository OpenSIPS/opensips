/* Copyright (C) 2026 OpenSIPS Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef STIR_SHAKEN_VERSTAT_H
#define STIR_SHAKEN_VERSTAT_H

#include "../../parser/msg_parser.h"

int verstat_init(void);
int stir_shaken_set_verstat(struct sip_msg *msg, str *target, str *value);
int stir_shaken_remove_verstat(struct sip_msg *msg, str *target);

#endif
