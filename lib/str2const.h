/*
 * Copyright (C) 2020 Sippy Software, Inc.
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
 *
 */

#ifndef __LIB_STR2CONST_H__
#define __LIB_STR2CONST_H__

#if defined(HAVE_GENERICS)
#define str2const(_sp) ( \
    _Generic((_sp), str *: _s2c, const str *: _cs2cc)(_sp) \
)

#define escape_user(sin, sout) ( \
    _Generic(*(sin), str: _escape_userSS, str_const: _escape_user)(sin, sout) \
)

#define unescape_user(sin, sout) ( \
    _Generic(*(sin), str: _unescape_userSS, str_const: _unescape_user)(sin, sout) \
)

#define escape_param(sin, sout) ( \
    _Generic(*(sin), str: _escape_paramSS, str_const: _escape_param)(sin, sout) \
)

#define unescape_param(sin, sout) ( \
    _Generic(*(sin), str: _unescape_paramSS, str_const: _unescape_param)(sin, sout) \
)

/*
 * Params: ([const] str *_a), ([const] str *_b)
 * Return: 1 on a match, 0 otherwise
 */
#define str_match(_a, _b) _Generic(*(_a), \
	str: _Generic(*(_b), \
	    str: _str_matchSS, \
	    str_const: _str_matchSC), \
	str_const: _Generic(*(_b), \
	    str: _str_matchCS, \
	    str_const: _str_matchCC) \
    )(_a, _b)

/*
 * Params: ([const] str *_a), ([const] str *_b)
 * Return: 1 on a match, 0 otherwise
 */
#define str_casematch(_a, _b) _Generic(*(_a), \
	str: _Generic(*(_b), \
	    str: _str_casematchSS, \
	    str_const: _str_casematchSC), \
	str_const: _Generic(*(_b), \
	    str: _str_casematchCS, \
	    str_const: _str_casematchCC) \
    )(_a, _b)

/*
 * Params: ([const] str *_a), ([const] str *_b)
 * Return: 0 on a match, -1/1 otherwise
 */
#define str_strcmp(_a, _b) _Generic(*(_a), \
        str: _Generic(*(_b), \
            str: _str_strcmpSS, \
            str_const: _str_strcmpSC), \
        str_const: _Generic(*(_b), \
            str: _str_strcmpCS, \
            str_const: _str_strcmpCC) \
    )(_a, _b)
#else /* !HAVE_GENERICS */
#define str2const(_sp) ((str_const *)(void *)(_sp))
#define escape_user(sin, sout) _escape_user(str2const(sin), sout)
#define unescape_user(sin, sout) _unescape_user(str2const(sin), sout)
#define escape_param(sin, sout) _escape_param(str2const(sin), sout)
#define unescape_param(sin, sout) _unescape_param(str2const(sin), sout)
#define str_match(_a, _b) _str_matchCC(str2const(_a), str2const(_b))
#define str_casematch(_a, _b) _str_casematchCC(str2const(_a), str2const(_b))
#define str_strcmp(_a, _b) _str_strcmpCC(str2const(_a), str2const(_b))
#endif /* HAVE_GENERICS */

#endif /* __LIB_STR2CONST_H__ */
