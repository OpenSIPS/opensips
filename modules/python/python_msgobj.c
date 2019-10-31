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
#include <structmember.h>

#include "../../action.h"
#include "../../mem/mem.h"
#include "../../sr_module.h"
#include "../../mod_fix.h"
#include "../../parser/msg_parser.h"
#include "../../ut.h"

#ifndef Py_TYPE
#define Py_TYPE(ob)               (((PyObject*)(ob))->ob_type)
#endif

typedef struct {
    PyObject_HEAD
    struct sip_msg *msg;
} msgobject;

static PyTypeObject MSGtype;

#define is_msgobject(v)         ((v)->ob_type == &MSGtype)

void set_Py_Type(PyObject *obj, struct _typeobject *type)
{
	obj->ob_type = type;
}

msgobject *
newmsgobject(struct sip_msg *msg)
{
    msgobject *msgp;

    msgp = PyObject_New(msgobject, &MSGtype);
    if (msgp == NULL)
        return NULL;

    msgp->msg = msg;
    return msgp;
}

void
msg_invalidate(msgobject *self)
{

    self->msg = NULL;
}

static void
msg_dealloc(msgobject *msgp)
{

    PyObject_Del(msgp);
}

static PyObject *
msg_copy(msgobject *self)
{
    msgobject *msgp;

    if ((msgp = newmsgobject(self->msg)) == NULL)
        return NULL;

    return (PyObject *)msgp;
}

static PyObject *
msg_rewrite_ruri(msgobject *self, PyObject *args)
{
    str ruri;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        Py_INCREF(Py_None);
        return Py_None;
    }

    if ((self->msg->first_line).type != SIP_REQUEST) {
        PyErr_SetString(PyExc_RuntimeError, "Not a request message - "
          "rewrite is not possible.\n");
        Py_INCREF(Py_None);
        return Py_None;
    }

    if(!PyArg_ParseTuple(args, "s:rewrite_ruri", &ruri.s))
        return NULL;
    ruri.len = strlen(ruri.s);

    if (set_ruri(self->msg, &ruri) < 0) {
        LM_ERR("Error setting RURI\n");
        PyErr_SetString(PyExc_RuntimeError, "Error setting RURI\n");
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
msg_set_dst_uri(msgobject *self, PyObject *args)
{
    str ruri;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        Py_INCREF(Py_None);
        return Py_None;
    }

    if ((self->msg->first_line).type != SIP_REQUEST) {
        PyErr_SetString(PyExc_RuntimeError, "Not a request message - "
          "set destination is not possible.\n");
        Py_INCREF(Py_None);
        return Py_None;
    }

    if(!PyArg_ParseTuple(args, "s:set_dst_uri", &ruri.s))
        return NULL;

    ruri.len = strlen(ruri.s);

    if (set_dst_uri(self->msg, &ruri) < 0) {
        LM_ERR("Error in set_dst_uri\n");
        PyErr_SetString(PyExc_RuntimeError, "Error in set_dst_uri\n");
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
msg_getHeader(msgobject *self, PyObject *args)
{
    struct hdr_field *hf;
    str hname, *hbody;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        Py_INCREF(Py_None);
        return Py_None;
    }

    if(!PyArg_ParseTuple(args, "s:getHeader", &hname.s))
        return NULL;
    hname.len = strlen(hname.s);

    if (parse_headers(self->msg, ~0, 0) < 0) {
		LM_ERR("cannot parse message!\n");
		return NULL;
	}
    hbody = NULL;
    for (hf = self->msg->headers; hf != NULL; hf = hf->next) {
        if (hname.len == hf->name.len &&
          strncasecmp(hname.s, hf->name.s, hname.len) == 0) {
            hbody = &(hf->body);
            break;
        }
    }

    if (hbody == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    return PyUnicode_FromStringAndSize(hbody->s, hbody->len);
}

static int py_do_action(struct sip_msg* msg, struct action *act,
    cmd_export_t *cmd, int *retval)
{
    void* cmdp[MAX_CMD_PARAMS];
    pv_value_t tmp_vals[MAX_CMD_PARAMS];
    int i;
    struct cmd_param *param;
    gparam_p gp;

    if (fix_cmd(cmd->params, act->elem) < 0) {
        PyErr_SetString(PyExc_RuntimeError, "failed to fix command");
        return -1;
    }

    if (get_cmd_fixups(msg, cmd->params, act->elem, cmdp, tmp_vals) < 0) {
        PyErr_SetString(PyExc_RuntimeError, "failed to get fixups for command");
        return -1;
    }

    *retval = cmd->function(msg,
      cmdp[0],cmdp[1],cmdp[2],
      cmdp[3],cmdp[4],cmdp[5],
      cmdp[6],cmdp[7]);

    for (param=cmd->params, i=1; param->flags; param++, i++) {
        gp = (gparam_p)act->elem[i].u.data;
        if (!gp)
            continue;

        if (param->free_fixup && param->free_fixup(&cmdp[i-1]) < 0) {
            PyErr_SetString(PyExc_RuntimeError, "failed to free fixups");
            return -1;
        }

        if (param->flags & CMD_PARAM_REGEX && gp->type != GPARAM_TYPE_PVS) {
            regfree((regex_t*)cmdp[i-1]);
            pkg_free(cmdp[i-1]);
        }
    }

    return 0;
}

static PyObject *
msg_call_function(msgobject *self, PyObject *args)
{
    int i, rval;
    char *fname;
    char *pargs[MAX_CMD_PARAMS];
    cmd_export_t *fexport;
    struct action *act;
    action_elem_t elems[MAX_ACTION_ELEMS];
    struct cmd_param *param;
    int n = 0;
    str s;
    pv_spec_t *specs[MAX_CMD_PARAMS];

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        Py_INCREF(Py_None);
        return Py_None;
    }

    i = PySequence_Size(args);
    if (i < 1 || i > MAX_CMD_PARAMS+1) {
        PyErr_SetString(PyExc_RuntimeError, "call_function() should "
          "have from 1 to 9 arguments");
        Py_INCREF(Py_None);
        return Py_None;
    }

    for (i=0; i < MAX_CMD_PARAMS; i++)
        pargs[i] = (char*)-1; /* mark params as not given */

    if(!PyArg_ParseTuple(args, "s|zzzzzzzz:call_function", &fname,
        &pargs[0], &pargs[1], &pargs[2], &pargs[3],
        &pargs[4], &pargs[5], &pargs[6], &pargs[7])) {
        PyErr_SetString(PyExc_RuntimeError,
            "failed to parse arguments from python");
        Py_INCREF(Py_None);
        return Py_None;
    }

    fexport = find_cmd_export_t(fname, 0);
    if (fexport == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "no such function");
        Py_INCREF(Py_None);
        return Py_None;
    }

    for (i=0; i < MAX_CMD_PARAMS; i++) {
        if (pargs[i] != (char*)-1) {
            n++;
            if (pargs[i] == NULL)  /* given as 'None' in Python */
                elems[i+1].type = NULLV_ST;
            else
                elems[i+1].type = NOSUBTYPE;
        }
        specs[i] = NULL;
    }

    rval = check_cmd_call_params(fexport, elems, n);
    if (rval == -1 || rval == -2) {
        PyErr_SetString(PyExc_RuntimeError, "to few or too many parameters");
        Py_INCREF(Py_None);
        return Py_None;
    } else if (rval == -3) {
        PyErr_SetString(PyExc_RuntimeError, "mandatory parameter ommited");
        Py_INCREF(Py_None);
        return Py_None;
    }

    elems[0].type = CMD_ST;
    elems[0].u.data = fexport;

    for (param=fexport->params, i=1; param->flags; param++, i++) {
        if (!pargs[i-1])
            continue;

        if (param->flags & CMD_PARAM_INT) {
            elems[i].type = NUMBER_ST;
            s.s = pargs[i-1];
            s.len =  strlen(s.s);
            if (str2sint(&s, (int*)&elems[i].u.number) < 0) {
                PyErr_SetString(PyExc_RuntimeError,
                    "parameter should be an integer");
                Py_INCREF(Py_None);
                return Py_None;
            }
        } else if (param->flags & (CMD_PARAM_STR | CMD_PARAM_REGEX)) {
            elems[i].type = STR_ST;
            elems[i].u.data = pargs[i-1];
        } else if (param->flags & CMD_PARAM_VAR) {
            elems[i].type = SCRIPTVAR_ST;
            specs[i] = pkg_malloc(sizeof *specs[i]);
            if (!specs[i]) {
                LM_ERR("oom\n");
                PyErr_SetString(PyExc_RuntimeError, "no more pkg memory");
                Py_INCREF(Py_None);
                return Py_None;
            }
            s.s = pargs[i-1];
            s.len = strlen(s.s);
            if (pv_parse_spec(&s, specs[i]) == NULL) {
                PyErr_SetString(PyExc_RuntimeError, "unknown script variable");
                Py_INCREF(Py_None);
                return Py_None;
            }
            elems[i].u.data = specs[i];
        }
    }

    act = mk_action(CMD_T, n+1, elems, 0, "python");

    if (act == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
          "action structure could not be created");
        Py_INCREF(Py_None);
        return Py_None;
    }

    if (py_do_action(self->msg, act, fexport, &rval) < 0) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    for (i=0; i < MAX_CMD_PARAMS; i++)
        pv_spec_free(specs[i]);

    /* free the gparam_t structs allocated by fix_cmd() */
    for (i=1; i < MAX_ACTION_ELEMS; i++)
        if (act->elem[i].u.data)
            pkg_free(act->elem[i].u.data);

    pkg_free(act);

    return PyLong_FromLong(rval);
}

PyDoc_STRVAR(copy_doc,
"copy() -> msg object\n\
\n\
Return a copy (``clone'') of the msg object.");

static PyMethodDef msg_methods[] = {
    {"copy",          (PyCFunction)msg_copy,          METH_NOARGS,  copy_doc},
    {"rewrite_ruri",  (PyCFunction)msg_rewrite_ruri,  METH_VARARGS,
      "Rewrite Request-URI."},
    {"set_dst_uri",   (PyCFunction)msg_set_dst_uri,   METH_VARARGS,
      "Set destination URI."},
    {"getHeader",     (PyCFunction)msg_getHeader,     METH_VARARGS,
      "Get SIP header field by name."},
    {"call_function", (PyCFunction)msg_call_function, METH_VARARGS,
      "Invoke function exported by the other module."},
    {NULL, NULL, 0, NULL}                              /* sentinel */
};

static PyObject *
msg_getType(msgobject *self, PyObject *unused)
{
    const char *rval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        Py_INCREF(Py_None);
        return Py_None;
    }

    switch ((self->msg->first_line).type) {
    case SIP_REQUEST:
       rval = "SIP_REQUEST";
       break;

    case SIP_REPLY:
       rval = "SIP_REPLY";
       break;

    default:
       /* Shouldn't happen */
       abort();
    }
    return PyUnicode_FromString(rval);
}

static PyObject *
msg_getMethod(msgobject *self, PyObject *unused)
{
    str *rval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        Py_INCREF(Py_None);
        return Py_None;
    }

    if ((self->msg->first_line).type != SIP_REQUEST) {
        PyErr_SetString(PyExc_RuntimeError, "Not a request message - "
          "no method available.\n");
        Py_INCREF(Py_None);
        return Py_None;
    }
    rval = &((self->msg->first_line).u.request.method);
    return PyUnicode_FromStringAndSize(rval->s, rval->len);
}

static PyObject *
msg_getStatus(msgobject *self, PyObject *unused)
{
    str *rval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        Py_INCREF(Py_None);
        return Py_None;
    }

    if ((self->msg->first_line).type != SIP_REPLY) {
        PyErr_SetString(PyExc_RuntimeError, "Not a non-reply message - "
          "no status available.\n");
        Py_INCREF(Py_None);
        return Py_None;
    }

    rval = &((self->msg->first_line).u.reply.status);
    return PyUnicode_FromStringAndSize(rval->s, rval->len);
}

static PyObject *
msg_getRURI(msgobject *self, PyObject *unused)
{
    str *rval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        Py_INCREF(Py_None);
        return Py_None;
    }

    if ((self->msg->first_line).type != SIP_REQUEST) {
        PyErr_SetString(PyExc_RuntimeError, "Not a request message - "
          "RURI is not available.\n");
        Py_INCREF(Py_None);
        return Py_None;
    }

    rval = &((self->msg->first_line).u.request.uri);
    return PyUnicode_FromStringAndSize(rval->s, rval->len);
}

static PyObject *
msg_get_src_address(msgobject *self, PyObject *unused)
{
    PyObject *src_ip, *src_port, *pyRval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        Py_INCREF(Py_None);
        return Py_None;
    }

    src_ip = PyUnicode_FromString(ip_addr2a(&self->msg->rcv.src_ip));
    if (src_ip == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    src_port = PyLong_FromLong(self->msg->rcv.src_port);
    if (src_port == NULL) {
        Py_DECREF(src_ip);
        Py_INCREF(Py_None);
        return Py_None;
    }

    pyRval = PyTuple_Pack(2, src_ip, src_port);
    Py_DECREF(src_ip);
    Py_DECREF(src_port);
    if (pyRval == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    return pyRval;
}

static PyObject *
msg_get_dst_address(msgobject *self, PyObject *unused)
{
    PyObject *dst_ip, *dst_port, *pyRval;

    if (self->msg == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "self->msg is NULL");
        Py_INCREF(Py_None);
        return Py_None;
    }

    dst_ip = PyUnicode_FromString(ip_addr2a(&self->msg->rcv.dst_ip));
    if (dst_ip == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    dst_port = PyLong_FromLong(self->msg->rcv.dst_port);
    if (dst_port == NULL) {
        Py_DECREF(dst_ip);
        Py_INCREF(Py_None);
        return Py_None;
    }

    pyRval = PyTuple_Pack(2, dst_ip, dst_port);
    Py_DECREF(dst_ip);
    Py_DECREF(dst_port);
    if (pyRval == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    return pyRval;
}

static PyGetSetDef msg_getseters[] = {
    {"Type",
     (getter)msg_getType, NULL, NULL,
     "Get message type - \"SIP_REQUEST\" or \"SIP_REPLY\"."},
    {"Method",
     (getter)msg_getMethod, NULL, NULL,
     "Get SIP method name."},
    {"Status",
     (getter)msg_getStatus, NULL, NULL,
     "Get SIP status code string."},
    {"RURI",
     (getter)msg_getRURI, NULL, NULL,
     "Get SIP Request-URI."},
    {"src_address",
     (getter)msg_get_src_address, NULL, NULL,
     "Get (IP, port) tuple representing source address of the message."},
    {"dst_address",
     (getter)msg_get_dst_address, NULL, NULL,
     "Get (IP, port) tuple representing destination address of the message."},
    {NULL, NULL, NULL, NULL, NULL}  /* Sentinel */
};

int
python_msgobj_init(void)
{
	/* HEAD initialization */
#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 6
	PyVarObject obj = { PyVarObject_HEAD_INIT(NULL, 0) };

	memcpy(((PyVarObject *)&MSGtype), &obj, sizeof obj);
#elif PY_MAJOR_VERSION >= 3
	PyVarObject obj = { PyObject_HEAD_INIT(NULL) 0 };

	memcpy(((PyVarObject *)&MSGtype), &obj, sizeof obj);
#else
	PyObject obj = { PyObject_HEAD_INIT(NULL) };

	memcpy(((PyObject *)&MSGtype), &obj, sizeof obj);
#endif

	MSGtype.tp_name      = "OpenSIPS.msg";
	MSGtype.tp_basicsize = sizeof(msgobject);
	MSGtype.tp_dealloc   = (destructor)msg_dealloc;
	MSGtype.tp_flags     = Py_TPFLAGS_DEFAULT;
	MSGtype.tp_methods   = msg_methods;
	MSGtype.tp_getset   = msg_getseters;
	set_Py_Type((PyObject *)&MSGtype, &PyType_Type);

	if (PyType_Ready(&MSGtype) < 0)
	    return -1;

	return 0;
}
