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
#include "python_compat.h"

#include "../../str.h"
#include "../../sr_module.h"

#include "python_exec.h"
#include "python_iface.h"
#include "python_msgobj.h"
#include "python_support.h"

#include <libgen.h>

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

static str script_name = str_init("/usr/local/etc/opensips/handler.py");
static str mod_init_fname = str_init("mod_init");
static str child_init_mname = str_init("child_init");
PyObject *handler_obj;
PyObject *format_exc_obj;

PyThreadState *myThreadState;

/** module parameters */
static param_export_t params[]={
    {"script_name",        STR_PARAM, &script_name.s },
    {"mod_init_function",  STR_PARAM, &mod_init_fname.s },
    {"child_init_method",  STR_PARAM, &child_init_mname.s },
    {0,0,0}
};

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
    {"python_exec", (cmd_function)python_exec, {
        {CMD_PARAM_STR,0,0},
        {CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
        REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE},
    {0,0,{{0,0,0}},0}
};

/** module exports */
struct module_exports exports = {
    "python",                       /* module name */
    MOD_TYPE_DEFAULT,/* class of this module */
    MODULE_VERSION,
    RTLD_NOW | RTLD_GLOBAL,         /* dlopen flags */
    0,                              /* load function */
    NULL,                           /* OpenSIPS module dependencies */
    cmds,                           /* exported functions */
    0,                              /* exported async functions */
    params,                         /* exported parameters */
    0,                              /* exported statistics */
    0,                              /* exported MI functions */
    0,                              /* exported pseudo-variables */
    0,                              /* exported transformations */
    0,                              /* extra processes */
    0,                              /* module pre-initialization function */
    mod_init,                       /* module initialization function */
    (response_function) NULL,       /* response handling function */
    (destroy_function) mod_destroy, /* destroy function */
    child_init,                     /* per-child init function */
    0                               /* reload confirm function */
};

static int
mod_init(void)
{
    char *dname, *bname;
    int i;
    PyObject *sys_path, *pDir, *pModule, *pFunc, *pArgs;
    PyThreadState *mainThreadState;

    script_name.len = strlen(script_name.s);
    mod_init_fname.len = strlen(mod_init_fname.s);
    child_init_mname.len = strlen(child_init_mname.s);

    bname = basename(script_name.s);
    i = strlen(bname);
    if (bname[i - 1] == 'c' || bname[i - 1] == 'o')
        i -= 1;
    if (bname[i - 3] == '.' && bname[i - 2] == 'p' && bname[i - 1] == 'y') {
        bname[i - 3] = '\0';
    } else {
        LM_ERR("%s: script_name doesn't look like a python script\n",
          script_name.s);
        return -1;
    }
    dname = dirname(script_name.s);
    if (strlen(dname) == 0)
        dname = ".";

    if (PyImport_AppendInittab("OpenSIPS", &PyInit_OpenSIPS) < 0) {
        LM_ERR("could not append init tab for OpenSIPS!\n");
        return -1;
    }

    Py_Initialize();
    PyEval_InitThreads();
    mainThreadState = PyThreadState_Get();

    if (python_msgobj_init() != 0) {
        LM_ERR("python_msgobj_init() has failed\n");
        PyEval_ReleaseThread(mainThreadState);
        return -1;
    }

    sys_path = PySys_GetObject("path");
    /* PySys_GetObject doesn't pass reference! No need to DEREF */
    if (sys_path == NULL) {
        PyErr_Print();
        LM_ERR("cannot import sys.path\n");
        PyEval_ReleaseThread(mainThreadState);
        return -1;
    }

    pDir = PyUnicode_FromString(dname);
    if (pDir == NULL) {
        PyErr_Print();
        LM_ERR("PyUnicode_FromString() has filed\n");
        PyEval_ReleaseThread(mainThreadState);
        return -1;
    }
    PyList_Insert(sys_path, 0, pDir);
    Py_DECREF(pDir);

    pModule = PyImport_ImportModule(bname);
    if (pModule == NULL) {
        PyErr_Print();
        LM_ERR("cannot import %s\n", bname);
        PyEval_ReleaseThread(mainThreadState);
        return -1;
    }

    pFunc = PyObject_GetAttrString(pModule, mod_init_fname.s);
    Py_DECREF(pModule);
    /* pFunc is a new reference */
    if (pFunc == NULL || !PyCallable_Check(pFunc)) {
        PyErr_Print();
        LM_ERR("cannot locate %s function in %s module\n",
          mod_init_fname.s, script_name.s);
        Py_XDECREF(pFunc);
        PyEval_ReleaseThread(mainThreadState);
        return -1;
    }

    pModule = PyImport_ImportModule("traceback");
    if (pModule == NULL) {
        PyErr_Print();
        LM_ERR("cannot import traceback module\n");
        Py_DECREF(pFunc);
        PyEval_ReleaseThread(mainThreadState);
        return -1;
    }

    format_exc_obj = PyObject_GetAttrString(pModule, "format_exception");
    Py_DECREF(pModule);
    if (format_exc_obj == NULL || !PyCallable_Check(format_exc_obj)) {
        PyErr_Print();
        LM_ERR("cannot locate format_exception function in" \
          " traceback module\n");
        Py_XDECREF(format_exc_obj);
        Py_DECREF(pFunc);
        PyEval_ReleaseThread(mainThreadState);
        return -1;
    }

    pArgs = PyTuple_New(0);
    if (pArgs == NULL) {
        PyErr_Print();
        LM_ERR("PyTuple_New() has failed\n");
        Py_DECREF(pFunc);
        Py_DECREF(format_exc_obj);
        PyEval_ReleaseThread(mainThreadState);
        return -1;
    }

    handler_obj = PyObject_CallObject(pFunc, pArgs);
    Py_DECREF(pFunc);
    Py_DECREF(pArgs);

    if (PyErr_Occurred()) {
        PyErr_Print();
        python_handle_exception("mod_init", NULL);
        Py_XDECREF(handler_obj);
        Py_DECREF(format_exc_obj);
        PyEval_ReleaseThread(mainThreadState);
        return -1;
    }

    if (handler_obj == NULL) {
        PyErr_Print();
        LM_ERR("%s function has not returned object\n",
          mod_init_fname.s);
        Py_DECREF(format_exc_obj);
        PyEval_ReleaseThread(mainThreadState);
        return -1;
    }

    myThreadState = PyThreadState_New(mainThreadState->interp);
    PyEval_ReleaseThread(mainThreadState);

    return 0;
}

static int
child_init(int rank)
{
    PyObject *pFunc, *pArgs, *pValue, *pResult;
    int rval;

    PyEval_AcquireThread(myThreadState);

    pFunc = PyObject_GetAttrString(handler_obj, child_init_mname.s);
    if (pFunc == NULL || !PyCallable_Check(pFunc)) {
        PyErr_Print();
        LM_ERR("cannot locate %s function\n", child_init_mname.s);
        if (pFunc != NULL) {
            Py_DECREF(pFunc);
        }
        PyEval_ReleaseThread(myThreadState);
        return -1;
    }

    pArgs = PyTuple_New(1);
    if (pArgs == NULL) {
        PyErr_Print();
        LM_ERR("PyTuple_New() has failed\n");
        Py_DECREF(pFunc);
        PyEval_ReleaseThread(myThreadState);
        return -1;
    }

    pValue = PyLong_FromLong(rank);
    if (pValue == NULL) {
        PyErr_Print();
        LM_ERR("PyLong_FromLong() has failed\n");
        Py_DECREF(pArgs);
        Py_DECREF(pFunc);
        PyEval_ReleaseThread(myThreadState);
        return -1;
    }
    PyTuple_SetItem(pArgs, 0, pValue);
    /* pValue has been stolen */

    pResult = PyObject_CallObject(pFunc, pArgs);
    Py_DECREF(pFunc);
    Py_DECREF(pArgs);

    if (PyErr_Occurred()) {
        char srank[16];
        snprintf(srank, sizeof(srank), "%d", rank);
        python_handle_exception("child_init", srank);
        Py_XDECREF(pResult);
        PyEval_ReleaseThread(myThreadState);
        return -1;
    }

    if (pResult == NULL) {
        PyErr_Print();
        LM_ERR("PyObject_CallObject() returned NULL but no exception!\n");
        PyEval_ReleaseThread(myThreadState);
        return -1;
    }

    rval = PyLong_AsLong(pResult);
    Py_DECREF(pResult);
    PyEval_ReleaseThread(myThreadState);
    return rval;
}

static void
mod_destroy(void)
{

    return;
}

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_OpenSIPS(void)
{
    PyObject *m;
    static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "OpenSIPS",          /* m_name */
        NULL,                /* m_doc */
        -1,                  /* m_size */
        OpenSIPSMethods,     /* m_methods */
        NULL,                /* m_reload */
        NULL,                /* m_traverse */
        NULL,                /* m_clear */
        NULL,                /* m_free */
    };
    m = PyModule_Create(&moduledef);
    if (!m) {
        LM_ERR("could not create OpenSIPS module!\n");
        return NULL;
    }
    return m;
}
#else
void initOpenSIPS(void)
{
    Py_InitModule("OpenSIPS", OpenSIPSMethods);
}
#endif
