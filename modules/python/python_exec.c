/*
 * Copyright (C) 2009 Sippy Software, Inc., http://www.sippysoft.com
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

#include <Python.h>

#include "../../mem/mem.h"
#include "../../data_lump.h"
#include "../../parser/parse_param.h"
#include "../../parser/msg_parser.h"
#include "../../dprint.h"
#include "../../action.h"
#include "../../config.h"
#include "../../parser/parse_uri.h"
#include "../../ut.h"

#include "python_exec.h"
#include "python_mod.h"
#include "python_msgobj.h"
#include "python_support.h"
#include "python_compat.h"

int
python_exec(struct sip_msg *_msg, str *_method_name_s, str *_mystr_s)
{
    PyObject *pFunc, *pArgs, *pValue, *pResult;
    PyObject *msg;
    int rval;
    str method_name;
    str mystr;

    if (pkg_nt_str_dup(&method_name, _method_name_s) < 0)
        return -1;
    if (_mystr_s && pkg_nt_str_dup(&mystr, _mystr_s) < 0)
        return -1;

    PyEval_AcquireThread(myThreadState);

    pFunc = PyObject_GetAttrString(handler_obj, method_name.s);
    if (pFunc == NULL || !PyCallable_Check(pFunc)) {
        LM_ERR("%s not found or is not callable\n", method_name.s);
        Py_XDECREF(pFunc);
        PyEval_ReleaseThread(myThreadState);
        goto error;
    }

    msg = newmsgobject(_msg);
    if (msg == NULL) {
        LM_ERR("can't create MSGtype instance\n");
        Py_DECREF(pFunc);
        PyEval_ReleaseThread(myThreadState);
        goto error;
    }

    pArgs = PyTuple_New(!_mystr_s ? 1 : 2);
    if (pArgs == NULL) {
        LM_ERR("PyTuple_New() has failed\n");
        msg_invalidate(msg);
        Py_DECREF(msg);
        Py_DECREF(pFunc);
        PyEval_ReleaseThread(myThreadState);
        goto error;
    }
    PyTuple_SetItem(pArgs, 0, msg);
    /* Tuple steals msg */

    if (_mystr_s != NULL) {
        pValue = PyUnicode_FromString(mystr.s);
        if (pValue == NULL) {
            LM_ERR("PyUnicode_FromString(%s) has failed\n", mystr.s);
            msg_invalidate(msg);
            Py_DECREF(pArgs);
            Py_DECREF(pFunc);
            PyEval_ReleaseThread(myThreadState);
            goto error;
        }
        PyTuple_SetItem(pArgs, 1, pValue);
        /* Tuple steals pValue */
    }

    pResult = PyObject_CallObject(pFunc, pArgs);
    msg_invalidate(msg);
    Py_DECREF(pArgs);
    Py_DECREF(pFunc);
    if (PyErr_Occurred()) {
        Py_XDECREF(pResult);
        python_handle_exception("python_exec", method_name.s);
        PyEval_ReleaseThread(myThreadState);
        goto error;
    }

    if (pResult == NULL) {
        LM_ERR("PyObject_CallObject() returned NULL\n");
        PyEval_ReleaseThread(myThreadState);
        goto error;
    }

    rval = PyLong_AsLong(pResult);
    Py_DECREF(pResult);
    PyEval_ReleaseThread(myThreadState);
    
    pkg_free(method_name.s);

    return rval;

error:
    pkg_free(method_name.s);
    if (_mystr_s)
        pkg_free(mystr.s);

    return -1;
}
