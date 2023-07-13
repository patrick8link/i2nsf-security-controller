/*
 * Copyright 2013 Tail-F Systems AB
 */

// include first, order is significant to get defines correct
#include "confdpy_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <confd.h>
#include <confd_ha.h>

#include "confdpy_err.h"
#include "types.h"
#include "common.h"

EXT_API_FUN(_ha_connect, EXT_API_FUN_HA_CONNECT)
{
    static char *kwlist[] = {
        "sock",
        "token",
        "ip",
        "port",
        "pstr",
        NULL };

    PyObject *sock, *tmp;
    int s, family;
    char *ipstr;
    int port;
    char *pstr = NULL;
    char *token = NULL;

    struct in_addr in;
    struct sockaddr_in inaddr;
    struct sockaddr_in6 inaddr6;
    struct sockaddr_un unaddr;
    struct sockaddr *addr;
    socklen_t addrlen;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "Os|sis",
            kwlist, &sock, &token, &ipstr, &port, &pstr)) {
        return NULL;
    }

    /* Fish out information from socket object... */
    if ((tmp = PyObject_CallMethod(sock, "fileno", NULL)) == NULL) {
        /* CallMethod sets up the exception */
        return NULL;
    }
    s = (int)PyInt_AsLong(tmp);
    Py_DECREF(tmp);
    if ((tmp = PyObject_GetAttrString(sock, "family")) == NULL) {
        return NULL;
    }
    family = (int)PyInt_AsLong(tmp);
    Py_DECREF(tmp);
    /* should check that type = SOCK_STREAM */

    switch (family) {
    case AF_UNIX: {
        if (!pstr) {
            PyErr_SetString(PyExc_TypeError,
                    "path argument must be provided for an AF_UNIX socket");
            return NULL;
        }
        unaddr.sun_family = AF_UNIX;
        snprintf(unaddr.sun_path, sizeof(unaddr.sun_path), "%s", pstr);
        addr = (struct sockaddr *)&unaddr;
        addrlen = sizeof(unaddr);
    }
        break;
    case AF_INET: {
        if (!ipstr) {
            PyErr_SetString(PyExc_TypeError,
                    "ip argument must be provided for an AF_INET socket");
            return NULL;
        }
        if (port == -1) {
            PyErr_SetString(PyExc_TypeError,
                    "port argument must be provided for an AF_INET socket");
            return NULL;
        }
        if (inet_pton(AF_INET, ipstr, &in) != 1) {
            return PyErr_Format(PyExc_ValueError,
                    "invalid IP address: %s", ipstr);
        }
        inaddr.sin_family = AF_INET;
        inaddr.sin_addr.s_addr = in.s_addr;
        inaddr.sin_port = htons(port);
        addr = (struct sockaddr *)&inaddr;
        addrlen = sizeof(inaddr);
    }
        break;

    case AF_INET6 :
        if (!ipstr) {
            PyErr_SetString(PyExc_TypeError,
                    "ip argument must be provided for an AF_INET6 socket");
            return NULL;
        }
        if (port == -1) {
            PyErr_SetString(PyExc_TypeError,
                    "port argument must be provided for an AF_INET6 socket");
            return NULL;
        }
        if (inet_pton(AF_INET6, ipstr, &inaddr6.sin6_addr) != 1) {
            return
                PyErr_Format(PyExc_ValueError, "invalid IPv6 address: %s",
                                ipstr);
        }
        inaddr6.sin6_family = AF_INET6;

        inaddr6.sin6_port = htons(port);
        addr = (struct sockaddr *)&inaddr6;
        addrlen = sizeof(inaddr6);
        break;

    default:
        PyErr_Format(PyExc_TypeError, "unsupported socket family: %d", family);
        return NULL;
    }

    CHECK_CONFD_ERR(confd_ha_connect(s, addr, addrlen, token));

    Py_RETURN_NONE;
}

typedef struct {
    char *str;
    confd_value_t val;
    confd_value_t *val_ptr;
} py_nodeid_t;

static int _alloc_py_nodeid_t(PyObject *py_nodeid, py_nodeid_t *nodeid,
                              const char *name)
{
    nodeid->str = NULL;

    if (PyConfd_Value_CheckExact(py_nodeid)) {
        nodeid->val_ptr = PyConfd_Value_PTR((PyConfd_Value_Object *)py_nodeid);
    } else if (PyString_Check(py_nodeid)) {
        nodeid->str = confd_py_string_strdup(py_nodeid);
        CONFD_SET_BUF(&nodeid->val,
                      (unsigned char*)nodeid->str, strlen(nodeid->str));
        nodeid->val_ptr = &nodeid->val;
    } else {
        PyErr_Format(PyExc_TypeError, "%s argument must be a "
                     CONFD_PY_MODULE ".Value or a string", name);
        return 0;
    }
    return 1;
}

static void _free_py_nodeid_t(py_nodeid_t *nodeid)
{
    free(nodeid->str);
}

EXT_API_FUN(_ha_beprimary, EXT_API_FUN_HA_BEPRIMARY)
{
    static char *kwlist[] = {
        "sock",
        "mynodeid",
        NULL };

    int s;
    PyObject *nodeid;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O",
                                     kwlist, sock_arg, &s, &nodeid)) {
        return NULL;
    }

    py_nodeid_t nodeid_t;
    if (! _alloc_py_nodeid_t(nodeid, &nodeid_t, "mynodeid")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(confd_ha_beprimary(s, nodeid_t.val_ptr),
                         _free_py_nodeid_t(&nodeid_t));

    Py_RETURN_NONE;
}


EXT_API_FUN(_ha_besecondary, EXT_API_FUN_HA_BESECONDARY)
{
    static char *kwlist[] = {
        "sock",
        "mynodeid",
        "primary_id",
        "primary_ip",
        "waitreply",
        NULL };

    int s;
    PyObject *nodeid, *primary_id;
    char *ipstr = "127.0.0.1";
    int wr;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&OOsi",
            kwlist, sock_arg, &s, &nodeid, &primary_id, &ipstr, &wr)) {
        return NULL;
    }

    py_nodeid_t nodeid_t;
    if (! _alloc_py_nodeid_t(nodeid, &nodeid_t, "mynodeid")) {
        return NULL;
    }
    py_nodeid_t primary_nodeid_t;
    if (! _alloc_py_nodeid_t(primary_id, &primary_nodeid_t, "primary_id")) {
        _free_py_nodeid_t(&nodeid_t);
        return NULL;
    }

    struct confd_ha_node primary;
    primary.nodeid = *primary_nodeid_t.val_ptr;
    primary.af = AF_INET;
    if (inet_pton(AF_INET, ipstr, &(primary.addr.ip4)) != 1) {
        primary.af = AF_INET6;

        if (inet_pton(AF_INET6, ipstr, &(primary.addr.ip6)) != 1) {
            PyErr_Format(PyExc_ValueError, "Invalid primary_ip address.");
            _free_py_nodeid_t(&primary_nodeid_t);
            _free_py_nodeid_t(&nodeid_t);
            return NULL;
        }
    }
    CHECK_CONFD_ERR_EXEC(
        confd_ha_besecondary(s, nodeid_t.val_ptr, &primary, wr),
        {
            _free_py_nodeid_t(&primary_nodeid_t);
            _free_py_nodeid_t(&nodeid_t);
        });
    Py_RETURN_NONE;
}


EXT_API_FUN(_ha_benone, EXT_API_FUN_HA_BENONE)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&",
            kwlist, sock_arg, &s)) {
        return NULL;
    }
    CHECK_CONFD_ERR(confd_ha_benone(s));
    Py_RETURN_NONE;
}


EXT_API_FUN(_ha_berelay, EXT_API_FUN_HA_BERELAY)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&",
            kwlist, sock_arg, &s)) {
        return NULL;
    }
    CHECK_CONFD_ERR(confd_ha_berelay(s));
    Py_RETURN_NONE;
}


EXT_API_FUN(_ha_status, EXT_API_FUN_HA_STATUS)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&",
            kwlist, sock_arg, &s)) {
        return NULL;
    }

    struct confd_ha_status status;

    CHECK_CONFD_ERR(confd_ha_get_status(s, &status));

    PyObject *nodelist = PyList_New(status.num_nodes);
    int i;
    for (i=0; i<status.num_nodes; i++) {
        PyObject *item = PyDict_New();

        PYDICT_SET_ITEM(
            item,
            "nodeid",
            PyString_FromString(
                (const char *)CONFD_GET_BUFPTR(&status.nodes[i].nodeid)));

        char str[sizeof(status.nodes[i].addr)];
        if (inet_ntop(AF_INET, &status.nodes[i].addr,
                      str, sizeof(status.nodes[i].addr)) == NULL) {
            if (inet_ntop(AF_INET6, &status.nodes[i].addr,
                          str, sizeof(status.nodes[i].addr)) == NULL) {
                PyErr_Format(PyExc_ValueError, "Invalid address-family.");
                Py_DECREF(item);
                Py_DECREF(nodelist);
                return NULL;
            }
        }
        PYDICT_SET_ITEM(item, "address", PyString_FromString(str));
        PyList_SetItem(nodelist, i, item);
    }

    return Py_BuildValue("(iN)", status.state, nodelist);
}

EXT_API_FUN(_ha_secondary_dead, EXT_API_FUN_HA_SECONDARY_DEAD)
{
    static char *kwlist[] = {
        "sock",
        "nodeid",
        NULL };

    int s;
    PyObject *nodeid;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&O",
            kwlist, sock_arg, &s, &nodeid)) {
        return NULL;
    }

    py_nodeid_t nodeid_t;
    if (! _alloc_py_nodeid_t(nodeid, &nodeid_t, "nodeid")) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(confd_ha_secondary_dead(s, nodeid_t.val_ptr),
                         _free_py_nodeid_t(&nodeid_t));
    Py_RETURN_NONE;
}

#include "../doc/src/ha_doc.c"

#define PYMOD_ENTRY(NAME) {# NAME, (PyCFunction)_ha_ ## NAME, \
                           METH_VARARGS | METH_KEYWORDS, \
                           _ha_ ## NAME ## __doc__}

// BIASED FREE: Backwards compatibility - remove later
#define _ha_bemaster _ha_beprimary
#define _ha_beslave _ha_besecondary
#define _ha_slave_dead _ha_secondary_dead

static PyMethodDef ha_Methods[] = {
    PYMOD_ENTRY(connect),
    PYMOD_ENTRY(beprimary),
    PYMOD_ENTRY(besecondary),
    PYMOD_ENTRY(benone),
    PYMOD_ENTRY(status),
    PYMOD_ENTRY(berelay),
    PYMOD_ENTRY(secondary_dead),
    // BIASED FREE: Backwards compatibility - remove later
    PYMOD_ENTRY(bemaster),
    PYMOD_ENTRY(beslave),
    PYMOD_ENTRY(slave_dead),
    {NULL, NULL, 0, NULL}
};

#undef PYMOD_ENTRY


/* ************************************************************************ */
/* Module initialization                                                    */
/* ************************************************************************ */

#define MODULE CONFD_PY_MODULE ".ha"

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        MODULE,
        HA_MODULE_DOCSTR(CONFD_PY_PRODUCT),
        0,
        ha_Methods,
        NULL,
        NULL,
        NULL,
        NULL
};

PyObject* init__ha_module(void)
{
    PyObject *m = NULL;

    if ((m = PyModule_Create(&moduledef)) == NULL) {
        goto error;
    }

    /* Add constants */
#define ADD_CONST(C_NAME, PY_NAME) \
    (void)PyModule_AddIntConstant(m, PY_NAME, C_NAME);

#define ADD_CONST_STR(C_NAME, PY_NAME) \
    (void)PyModule_AddStringConstant(m, PY_NAME, C_NAME);

#include "gen_add_ha_const.c"

#undef ADD_CONST
#undef ADD_CONST_STR

error:
    if (PyErr_Occurred()) {
        PyErr_SetString(PyExc_ImportError, MODULE " : init failed");
        return NULL;
    } else {
        return m;
    }
}
