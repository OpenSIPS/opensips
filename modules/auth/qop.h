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

#define QOP_AUTH	  ", qop=\"" QOP_AUTH_STR "\""
#define QOP_AUTH_INT	  ", qop=\"" QOP_AUTHINT_STR "\""
#define QOP_AUTH_BOTH_AAI	  ", qop=\"" QOP_AUTH_STR "," QOP_AUTHINT_STR "\""
#define QOP_AUTH_BOTH_AIA	  ", qop=\"" QOP_AUTHINT_STR "," QOP_AUTH_STR "\""

static inline str_const get_qop_param(qop_type_t qop)
{
	static str_const qop_param;
	switch (qop) {
	case QOP_UNSPEC_D:
		qop_param = STR_NULL_const;
		break;
	case QOP_AUTH_D:
		qop_param = str_const_init(QOP_AUTH);
		break;
	case QOP_AUTHINT_D:
		qop_param = str_const_init(QOP_AUTH_INT);
		break;
	case QOP_AUTHINT_AUTH_D:
		qop_param = str_const_init(QOP_AUTH_BOTH_AAI);
		break;
	case QOP_AUTH_AUTHINT_D:
		qop_param = str_const_init(QOP_AUTH_BOTH_AIA);
		break;
	default:
		LM_ERR("Wrong _qop value: %d\n", qop);
		abort();
	}
	return qop_param;
}

#undef QOP_AUTH
#undef QOP_AUTH_INT
#undef QOP_AUTH_BOTH_AAI
#undef QOP_AUTH_BOTH_AIA

#endif /* AUTH_QOP_H */
