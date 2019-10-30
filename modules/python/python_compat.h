/*
 * Copyright (C) 2019 OpenSIPS Project
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

#ifndef _PYTHON_COMPAT_H_
#define _PYTHON_COMPAT_H_

#if PY_VERSION_HEX < 0x03000000
#ifndef PyUnicode_FromString
#define PyUnicode_FromString PyString_FromString
#endif
#ifndef PyUnicode_FromStringAndSize
#define PyUnicode_FromStringAndSize PyString_FromStringAndSize
#endif
#ifndef PyEval_ReleaseThread
#define PyEval_ReleaseThread(tstate) \
	do { \
		PyThreadState_Swap(NULL); \
		PyEval_ReleaseLock(); \
	} while(0)
#endif

#ifndef PyEval_AcquireThread
#define PyEval_AcquireThread(tstate) \
	do { \
		PyEval_AcquireLock(); \
		PyThreadState_Swap(tstate); \
	} while(0)
#endif

#define PyUnicode_AsUTF8 PyString_AsString
#define PyLong_FromLong PyInt_FromLong
#define PyLong_AsLong PyInt_AsLong

void initOpenSIPS(void);
#define PyInit_OpenSIPS initOpenSIPS
#else /* python3.x */
PyMODINIT_FUNC PyInit_OpenSIPS(void);
#endif

#endif /* _PYTHON_COMPAT_H_ */
