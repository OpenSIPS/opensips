/*
 * Authentication QOP parsing functions
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */


#ifndef AUTH_QOP_H
#define AUTH_QOP_H

#include "../../lib/csv.h"

static inline int fixup_qop(void** param)
{
	str *s = (str*)*param;
	qop_type_t qop_type = QOP_UNSPEC_D;
	csv_record *q_csv, *q;

	q_csv = parse_csv_record(s);
	if (!q_csv) {
		LM_ERR("Failed to parse qop types\n");
		return -1;
	}
	for (q = q_csv; q; q = q->next) {
		if (!str_strcmp(&q->s, const_str(QOP_AUTH_STR)))  {
			if (qop_type == QOP_AUTHINT_D)
				qop_type = QOP_AUTHINT_AUTH_D;
			else
				qop_type = QOP_AUTH_D;
		} else if (!str_strcmp(&q->s, const_str(QOP_AUTHINT_STR))) {
			if (qop_type == QOP_AUTH_D)
				qop_type = QOP_AUTH_AUTHINT_D;
			else
				qop_type = QOP_AUTHINT_D;
		} else {
			LM_ERR("Bad qop type\n");
			free_csv_record(q_csv);
			return -1;
		}
	}
	free_csv_record(q_csv);

	*param=(void*)(long)qop_type;
	return 0;
}

#endif /* AUTH_QOP_H */
