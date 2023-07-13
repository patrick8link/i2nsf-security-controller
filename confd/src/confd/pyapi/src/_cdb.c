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
#include <confd_cdb.h>

#include "confdpy_err.h"
#include "types.h"
#include "common.h"

/* Function to convert a python list of integers to a c array */
static int pylist2spoints(PyObject *list, int *arr[], int *len)
{
  int x;

  if (!PyList_Check(list)) {
    PyErr_SetString(PyExc_TypeError, "sub_points must be a list of integers");
    return 0;
  }

  *len = (int)PyList_Size(list);

  if (*len <= 0) {
    *len = 0;
    *arr = NULL;
    return 1;
  }

  *arr = (int*)malloc(*len * sizeof(int));

  for (x = 0; x < *len; x++) {
    PyObject *i = PyList_GetItem(list, x);
    if (!PyInt_Check(i)) {
      free(*arr);
      *arr = NULL;
      PyErr_Format(PyExc_TypeError, "sub_points[%d] must be an integer", x);
      return 0;
    }
    (*arr)[x] = (int)PyInt_AsLong(i);
  }
  return 1;
}


static void free_tag_values(confd_tag_value_t *tv, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        confd_free_value(CONFD_GET_TAG_VALUE(&tv[i]));
    }
}

/* ************************************************************************ */
/* confd_lib_cdb API functions                                              */
/* ************************************************************************ */

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_connect, EXT_API_FUN_CDB_CONNECT)
{
    static char *kwlist[] = {
        "sock",
        "type",
        "ip",
        "port",
        "path",
        NULL };

    PyObject *sock, *tmp;
    int s, family;
    enum cdb_sock_type type;
    char *ipstr = NULL;
    int port = -1;
    char *pstr = NULL;

    struct in_addr in;
    struct sockaddr_in inaddr;
    struct sockaddr_in6 inaddr6;
    struct sockaddr_un unaddr;
    struct sockaddr *addr;
    socklen_t addrlen;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "Oi|sis",
            kwlist, &sock, &type, &ipstr, &port, &pstr)) {
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
            return
                PyErr_Format(PyExc_ValueError, "invalid IP address: %s", ipstr);
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
    CHECK_CONFD_ERR(cdb_connect(s, type, addr, addrlen));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_connect_name, EXT_API_FUN_CDB_CONNECT_NAME)
{
    static char *kwlist[] = {
        "sock",
        "type",
        "name",
        "ip",
        "port",
        "path",
        NULL };

    PyObject *sock, *tmp;
    int s, family;
    enum cdb_sock_type type;
    char *ipstr = NULL;
    int port = -1;
    char *pstr = NULL;
    char *name = NULL;

    struct in_addr in;
    struct sockaddr_in inaddr;
    struct sockaddr_in6 inaddr6;
    struct sockaddr_un unaddr;
    struct sockaddr *addr;
    socklen_t addrlen;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "Ois|sis",
            kwlist, &sock, &type, &name, &ipstr, &port, &pstr)) {
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
                            "need to provide path for an AF_UNIX socket");
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
            return
                PyErr_Format(PyExc_ValueError, "invalid IP address: %s", ipstr);
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
    CHECK_CONFD_ERR(cdb_connect_name(s, type, addr, addrlen, name));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_mandatory_subscriber, EXT_API_FUN_CDB_MANDATORY_SUBSCRIBER)
{
    static char *kwlist[] = {
        "sock",
        "name",
        NULL };

    int s;
    char *name;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&s",
                                     kwlist, sock_arg, &s, &name)) {
        return NULL;
    }
    CHECK_CONFD_ERR(cdb_mandatory_subscriber(s, name));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_set_namespace, EXT_API_FUN_CDB_SET_NAMESPACE)
{
    static char *kwlist[] = {
        "sock",
        "hashed_ns",
        NULL };

    int s;
    int hashed_ns;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&i",
                                     kwlist, sock_arg, &s, &hashed_ns)) {
        return NULL;
    }
    CHECK_CONFD_ERR(cdb_set_namespace(s, hashed_ns));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_start_session, EXT_API_FUN_CDB_START_SESSION)
{
    static char *kwlist[] = {
        "sock",
        "db",
        NULL };

    int s;
    enum cdb_db_type db;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&i",
                                     kwlist, sock_arg, &s, &db)) {
        return NULL;
    }
    CHECK_CONFD_ERR(cdb_start_session(s, db));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_start_session2, EXT_API_FUN_CDB_START_SESSION2)
{
    static char *kwlist[] = {
        "sock",
        "db",
        "flags",
        NULL };

    int s;
    enum cdb_db_type db;
    int flags;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&ii",
                                     kwlist, sock_arg, &s, &db, &flags)) {
        return NULL;
    }
    CHECK_CONFD_ERR(cdb_start_session2(s, db, flags));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_end_session, EXT_API_FUN_CDB_END_SESSION)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) { return NULL; }
    CHECK_CONFD_ERR(cdb_end_session(s));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_close, EXT_API_FUN_CDB_CLOSE)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    PyObject *sock;
    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &sock)) {
        return NULL;
    }

    sock_arg(sock, &s);

    /* N.B. Don't call cdb_close() here. */

    if (PyObject_CallMethod(sock, "close", NULL) == NULL) {
        /* CallMethod sets up the exception */
        return NULL;
    }

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_wait_start, EXT_API_FUN_CDB_WAIT_START)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) { return NULL; }
    CHECK_CONFD_ERR(cdb_wait_start(s));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_txid, EXT_API_FUN_CDB_GET_TXID)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    struct cdb_txid txid;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) { return NULL; }
    CHECK_CONFD_ERR(cdb_get_txid(s, &txid));
    if (txid.primary[0] == '\0') {
        return Py_BuildValue("(IIIO)", txid.s1, txid.s2, txid.s3, Py_None);
    } else {
        return Py_BuildValue("(IIIs)", txid.s1, txid.s2, txid.s3, txid.primary);
    }
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_replay_txids, EXT_API_FUN_CDB_GET_REPLAY_TXIDS)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    int resultlen;
    struct cdb_txid *txids;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) { return NULL; }

    CHECK_CONFD_ERR(cdb_get_replay_txids(s, &txids, &resultlen));

    {
        PyObject *res = PyList_New(resultlen);
        int i;

        for (i=0; i<resultlen; i++) {
            PyObject *txid;
            if (*txids[i].primary == '\0') {
                txid = Py_BuildValue("(IIIO)",
                                     txids[i].s1,
                                     txids[i].s2,
                                     txids[i].s3,
                                     Py_None);
            } else {
                txid = Py_BuildValue("(IIIs)",
                                     txids[i].s1,
                                     txids[i].s2,
                                     txids[i].s3,
                                     txids[i].primary);
            }
            PyList_SetItem(res, i, txid);
        }
        free(txids);
        return res;
    }
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_initiate_journal_compaction,
            EXT_API_FUN_CDB_INITIATE_JOURNAL_COMPACTION)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) { return NULL; }
    CHECK_CONFD_ERR(cdb_initiate_journal_compaction(s));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_user_session, EXT_API_FUN_CDB_GET_USER_SESSION)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    int usid;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) {
      return NULL;
    }
    CHECK_CONFD_ERR(usid = cdb_get_user_session(s));
    return Py_BuildValue("i", usid);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_transaction_handle, EXT_API_FUN_CDB_GET_TRANSACTION_HANDLE)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    int th;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) {
      return NULL;
    }
    CHECK_CONFD_ERR(th = cdb_get_transaction_handle(s));
    return Py_BuildValue("i", th);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_set_timeout, EXT_API_FUN_CDB_SET_TIMEOUT)
{
    static char *kwlist[] = {
        "sock",
        "timeout_secs",
        NULL };

    int s;
    int timeout_secs;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&i",
                                     kwlist, sock_arg, &s, &timeout_secs)) {
      return NULL;
    }
    CHECK_CONFD_ERR(cdb_set_timeout(s, timeout_secs));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_phase, EXT_API_FUN_CDB_GET_PHASE)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    struct cdb_phase phase;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) { return NULL; }
    CHECK_CONFD_ERR(cdb_get_phase(s, &phase));
    return Py_BuildValue(
        "{sisisOsO}",
        "phase", phase.phase,
        "flags", phase.flags,
        "init", (phase.flags & CDB_FLAG_INIT) ? Py_True : Py_False,
        "upgrade", (phase.flags & CDB_FLAG_UPGRADE) ? Py_True : Py_False);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_exists, EXT_API_FUN_CDB_EXISTS)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL };

    int s, e;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&",
                                     kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(e = cdb_exists(s, path), free(path));
    if (e) { Py_RETURN_TRUE; } else { Py_RETURN_FALSE; }
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_num_instances, EXT_API_FUN_CDB_NUM_INSTANCES)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL };

    int s, r;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&",
                          kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(r = cdb_num_instances(s, path), free(path));
    return Py_BuildValue("i", r);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_next_index, EXT_API_FUN_CDB_NEXT_INDEX)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL };

    int s, r;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&",
                                     kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(r = cdb_next_index(s, path), free(path));
    return Py_BuildValue("i", r);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_index, EXT_API_FUN_CDB_INDEX)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL };

    int s, r;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&",
                                     kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(r = cdb_index(s, path), free(path));
    return Py_BuildValue("i", r);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_is_default, EXT_API_FUN_CDB_IS_DEFAULT)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL };

    int s, r;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&",
                                     kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(r = cdb_is_default(s, path), free(path));
    if (r) { Py_RETURN_TRUE; } else { Py_RETURN_FALSE; }
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_cd, EXT_API_FUN_CDB_CD)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL };

    int s;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&",
                                     kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(cdb_cd(s, path), free(path));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_pushd, EXT_API_FUN_CDB_PUSHD)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL };

    int s;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&",
                                     kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(cdb_pushd(s, path), free(path));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_popd, EXT_API_FUN_CDB_POPD)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) {
        return NULL;
    }
    CHECK_CONFD_ERR(cdb_popd(s));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_getcwd, EXT_API_FUN_CDB_GETCWD)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    char path[512];
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) {
        return NULL;
    }
    CHECK_CONFD_ERR(cdb_getcwd(s, sizeof(path), path));
    return Py_BuildValue("s", path);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_getcwd_kpath, EXT_API_FUN_CDB_GETCWD_KPATH)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) {
        return NULL;
    }

    confd_hkeypath_t *kp;
    CHECK_CONFD_ERR(cdb_getcwd_kpath(s, &kp));
    return newConfdHKeypathRefAutoFree(kp);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get, EXT_API_FUN_CDB_GET)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL };

    int s;
    char *path;
    PyConfd_Value_Object *v;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&",
                                     kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }
    if ((v = PyConfd_Value_New_NoInit()) == NULL) {
        return NULL;
    }
    CONFD_RET_CHECK_ERR(cdb_get(s, PyConfd_Value_PTR(v), path), v, free(path));
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_values, EXT_API_FUN_CDB_GET_VALUES)
{
    static char *kwlist[] = {
        "sock",
        "values",
        "path",
        NULL };

    int s;
    PyObject *values;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O!O&", kwlist,
                sock_arg, &s, &PyList_Type, &values, path_arg, &path)) {
        return NULL;
    }

    py_confd_tag_value_t_list_t tl = {0};
    if (!alloc_py_confd_tag_value_t_list(values, &tl, "values")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXECERR(
            cdb_get_values(s, tl.list, tl.size, path),
            {
              free_py_confd_tag_value_t_list(&tl);
              free(path);
            });

    int i;
    PyConfd_TagValue_Object *o;

    for (i = 0; i < tl.size; i++) {
        o = (PyConfd_TagValue_Object*)PyList_GetItem(values, i);
        o->tv.tag = tl.list[i].tag;
        confd_free_value(&o->tv.v);
        confd_value_dup_to(&tl.list[i].v, &o->tv.v);
    }

    free_py_confd_tag_value_t_list(&tl);
    free(path);

    Py_INCREF(values);
    return values;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_object, EXT_API_FUN_CDB_GET_OBJECT)
{
    static char *kwlist[] = {
        "sock",
        "n",
        "path",
        NULL };

    int s;
    int n;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&iO&", kwlist,
                sock_arg, &s, &n, path_arg, &path)) {
        return NULL;
    }

    confd_value_t values[n];

    CHECK_CONFD_ERR_EXEC(n = cdb_get_object(s, values, n, path),
        free(path));

    PyObject *l = PyList_New(n);
    PyConfd_Value_Object *o;

    int i;
    for (i = 0; i < n; i++) {
        o = PyConfd_Value_New_NoInit();
        memcpy(&o->ob_val, &values[i], sizeof(confd_value_t));
        PyList_SetItem(l, i, (PyObject*)o);
    }

    return l;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_objects, EXT_API_FUN_CDB_GET_OBJECTS)
{
    static char *kwlist[] = {
        "sock",
        "n",
        "ix",
        "nobj",
        "path",
        NULL };

    int s;
    int n;
    int ix;
    int nobj;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&iiiO&", kwlist,
                sock_arg, &s, &n, &ix, &nobj, path_arg, &path)) {
        return NULL;
    }

    confd_value_t values[n*nobj];
    memset(values, 0, sizeof(confd_value_t)*n*nobj);

    int nmax;
    CHECK_CONFD_ERR_EXEC(nmax = cdb_get_objects(s, values, n, ix, nobj, path),
        free(path));

    nmax = nmax > n ? n : nmax;

    PyObject *lobj = PyList_New(nobj);
    PyObject *lval;
    PyConfd_Value_Object *o;

    int i, j;
    for (i = 0; i < nobj; i++) {
        lval = PyList_New(nmax);

        for (j = 0; j < nmax; j++) {
            o = PyConfd_Value_New_NoInit();
            memcpy(&o->ob_val, &values[i*n+j], sizeof(confd_value_t));
            PyList_SetItem(lval, j, (PyObject*)o);
        }

        PyList_SetItem(lobj, i, lval);
    }

    return lobj;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_subscribe, EXT_API_FUN_CDB_SUBSCRIBE)
{
    static char *kwlist[] = {
        "sock",
        "prio",
        "nspace",
        "path",
        NULL };

    int s, prio, spoint;
    int ns;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&iiO&",
                                     kwlist, sock_arg, &s, &prio, &ns,
                                     path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(
        cdb_subscribe(s, prio, ns, &spoint, path),
        free(path));
    return Py_BuildValue("i", spoint);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_subscribe2, EXT_API_FUN_CDB_SUBSCRIBE2)
{
    static char *kwlist[] = {
        "sock",
        "type",
        "flags",
        "prio",
        "nspace",
        "path",
        NULL };

    int s, prio, spoint;
    enum cdb_sub_type type;
    int flags;
    int ns;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&iiiiO&",
                                     kwlist, sock_arg, &s,
                                     &type, &flags, &prio, &ns,
                                     path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(
        cdb_subscribe2(s, type, flags, prio, &spoint, ns, path),
        free(path));
    return Py_BuildValue("i", spoint);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_oper_subscribe, EXT_API_FUN_CDB_OPER_SUBSCRIBE)
{
    static char *kwlist[] = {
        "sock",
        "nspace",
        "path",
        NULL };

    int s, spoint;
    int ns;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&iO&",
                                     kwlist, sock_arg, &s, &ns,
                                     path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(
        cdb_oper_subscribe(s, ns, &spoint, path),
        free(path));
    return Py_BuildValue("i", spoint);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_subscribe_done, EXT_API_FUN_CDB_SUBSCRIBE_DONE)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&",
                                     kwlist, sock_arg, &s)) { return NULL; }
    CHECK_CONFD_ERR(cdb_subscribe_done(s));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_trigger_subscriptions, EXT_API_FUN_CDB_TRIGGER_SUBSCRIPTIONS)
{
    static char *kwlist[] = {
        "sock",
        "sub_points",
        NULL };

    int s, len = 0, *spoints = NULL;
    PyObject *list;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O",
                                     kwlist, sock_arg, &s, &list)) {
        return NULL;
    }

    if (!pylist2spoints(list, &spoints, &len)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
        cdb_trigger_subscriptions(s, spoints, len),
        free(spoints));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_trigger_oper_subscriptions,
            EXT_API_FUN_CDB_TRIGGER_OPER_SUBSCRIPTIONS)
{
    static char *kwlist[] = {
        "sock",
        "sub_points",
        "flags",
        NULL };

    int s, flags, len = 0, *spoints = NULL;
    PyObject *list;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&Oi",
                                     kwlist, sock_arg, &s, &list, &flags)) {
        return NULL;
    }

    if (!pylist2spoints(list, &spoints, &len)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
        cdb_trigger_oper_subscriptions(s, spoints, len, flags),
        free(spoints));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_replay_subscriptions, EXT_API_FUN_CDB_REPLAY_SUBSCRIPTIONS)
{
    static char *kwlist[] = {
        "sock",
        "txid",
        "sub_points",
        NULL };

    int s, len = 0, *spoints = NULL;
    PyObject *list = NULL;
    PyObject *primary = NULL;
    struct cdb_txid txid;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&(iiiO)O",
                                     kwlist, sock_arg, &s,
                                     &txid.s1, &txid.s2, &txid.s3,
                                     &primary, &list)) {
        return NULL;
    }

    if (PyString_Check(primary)) {
        int ret;
        CONFD_PY_WITH_C_STR(primary, primary_c_str) {
            size_t len = strlen(primary_c_str);
            if (len < MAXHOSTLEN) {
                memcpy(txid.primary, primary_c_str, len + 1);
                ret = 1;
            } else {
                PyErr_Format(PyExc_ValueError, "txid[3] (primary) %s too long",
                             primary_c_str);
                ret = 0;
            }
        }

        if (! ret) {
            return NULL;
        }
    } else if (primary == Py_None) {
        txid.primary[0] = '\0';
    } else {
        PyErr_Format(PyExc_TypeError,
                     "txid[3] (primary) must be a string or None");
        return NULL;
    }

    if (list != NULL) {
        if (!pylist2spoints(list, &spoints, &len)) {
            return NULL;
        }
    }

    CHECK_CONFD_ERR(cdb_replay_subscriptions(s, &txid, spoints, len));

    Py_RETURN_NONE;
}

#define READ_SUB_SOCK 1
#define READ_SUB_SOCK2 2

/* ------------------------------------------------------------------------- */

static PyObject *_cdb_read_subscription_socket_generic(PyObject *self,
                                                       PyObject *args,
                                                       PyObject *kwds,
                                                       int which_c_api,
                                                       struct timespec *_call)
{
    static char *kwlist[] = {
        "sock",
        NULL };

    int s;
    enum cdb_sub_notification type = 0;
    int flags = 0;
    int *subpoints;
    int resultlen = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&", kwlist, sock_arg, &s)) {
      return NULL;
    }

    CHECK_CONFD_ERR(
        cdb_read_subscription_socket2(s, &type,
                                      &flags, &subpoints, &resultlen)
    );

    {
        PyObject *spoints = PyList_New(resultlen);
        int i;
        for (i=0; i<resultlen; i++) {
            PyList_SetItem(spoints, i, PyInt_FromLong((long)subpoints[i]));
        }
        free(subpoints);

        /* which_c_api decides what to return. */
        /* If READ_SUB_SOCK,  dp.read_subscription_socket() was invoked */
        /* and we should only return spoints. */
        /* If READ_SUB_SOCK2,  dp.read_subscription_socket2() was invoked */
        /* and we should return type, flags and spoints. */
        if(which_c_api == READ_SUB_SOCK) {
            return spoints;
        } else if (which_c_api == READ_SUB_SOCK2) {
            return Py_BuildValue("(iiN)", type, flags, spoints);
        } else {
            PyErr_Format(PyExc_Exception,
                    "internal error which_c_api = %d", which_c_api);
            return NULL;
        }
    }
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_read_subscription_socket,
            EXT_API_FUN_CDB_READ_SUBSCRIPTION_SOCKET)
{
#ifndef CONFD_PY_EXT_API_TIMING
    struct timespec *_call = NULL;
#endif /* CONFD_PY_EXT_API_TIMING */
    return _cdb_read_subscription_socket_generic(self, args, kwds,
                                                 READ_SUB_SOCK, _call);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_read_subscription_socket2,
            EXT_API_FUN_CDB_READ_SUBSCRIPTION_SOCKET2)
{
#ifndef CONFD_PY_EXT_API_TIMING
    struct timespec *_call = NULL;
#endif /* CONFD_PY_EXT_API_TIMING */
    return _cdb_read_subscription_socket_generic(self, args, kwds,
                                                 READ_SUB_SOCK2, _call);
}

static enum cdb_iter_ret iterator(confd_hkeypath_t *kp, enum cdb_iter_op op,
                                  confd_value_t *oldv, confd_value_t *newv,
                                  void *statep)
{
    struct state {
        PyObject *proc;
        PyObject *opaque;
        int iterret;
    } *state = statep;

    PyObject *pykp;
    PyObject *pyop;
    PyObject *pyoldv;
    PyObject *pynewv;
    PyObject *pystate;
    PyObject *pyret;
    int ret;

    PyGILState_STATE gstate = PyGILState_Ensure();

    if (kp) {
        pykp = newConfdHKeypathRefNoAutoFree(kp);
    } else {
        Py_INCREF(Py_None);
        pykp = Py_None;
    }

    pyop = PyInt_FromLong(op);

    if (oldv) {
        pyoldv = (PyObject*)PyConfd_Value_New_DupTo(oldv);
    } else {
        Py_INCREF(Py_None);
        pyoldv = Py_None;
    }

    if (newv == NULL) {
        Py_INCREF(Py_None);
        pynewv = Py_None;
    } else if (op == MOP_MOVED_AFTER) {
        /* newv_ is a list of key values ending with C_NOEXISTS */
        pynewv = PyList_New(0);
        for (; newv->type != C_NOEXISTS; newv++) {
            PyList_Append(pynewv, PyConfd_Value_New_DupTo_Py(newv));
        }
    } else {
        /* not including special code for MOP_ATTR_SET (2-element
           array) as it is not sent to CDB subscribers */
        pynewv = (PyObject*)PyConfd_Value_New_DupTo(newv);
    }

    if (state->opaque) {
        pystate = state->opaque;
    } else {
        Py_INCREF(Py_None);
        pystate = Py_None;
    }

    pyret = PyObject_CallFunctionObjArgs(
            state->proc, pykp, pyop, pyoldv, pynewv, pystate, NULL);

    /* Inspired by _dp.c:_dcb_generic_cb */
    if (pyret == NULL) {
        ret = ITER_STOP;
    } else {
        if (pyret == Py_None) {
            ret = ITER_STOP;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
      } else {
            ret = ITER_STOP;
        }
    }

    unrefConfdHKeypathRef(pykp);
    Py_DECREF(pykp);
    Py_DECREF(pyop);
    Py_DECREF(pyoldv);
    Py_DECREF(pynewv);
    if (pystate == Py_None) {
        Py_DECREF(pystate);
    }
    if (pyret) {
        Py_DECREF(pyret);
    }

    PyGILState_Release(gstate);

    state->iterret = ret;

    return ret;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_diff_iterate, EXT_API_FUN_CDB_DIFF_ITERATE)
{
    static char *kwlist[] = {
        "sock",
        "subid",
        "iter",
        "flags",
        "initstate",
        NULL };

    int s;
    int id;
    int flags;

    struct state {
        PyObject *proc;
        PyObject *opaque;
        int iterret;
    } state;

    state.proc = NULL;
    state.opaque = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&iOiO",
                                     kwlist, sock_arg, &s, &id, &state.proc,
                                     &flags, &state.opaque)) {
        return NULL;
    }
    if (!PyCallable_Check(state.proc)) {
        PyErr_SetString(PyExc_TypeError, "iter argument must be callable");
        return NULL;
    }

    CHECK_CONFD_ERR(cdb_diff_iterate(s, id, iterator, flags, (void *)&state));

    if (PyErr_Occurred()) {
        return NULL;
    }

    return PyInt_FromLong(state.iterret);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_diff_iterate_resume, EXT_API_FUN_CDB_DIFF_ITERATE_RESUME)
{
    static char *kwlist[] = {
        "sock",
        "reply",
        "iter",
        "resumestate",
        NULL };

    int s, reply;

    struct state {
        PyObject *proc;
        PyObject *opaque;
        int iterret;
    } state;

    state.proc = NULL;
    state.opaque = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds,"O&iOO",
                                     kwlist,sock_arg, &s, &reply,
                                     &state.proc, &state.opaque)) {
        return NULL;
    }
    if (!PyCallable_Check(state.proc)) {
        PyErr_SetString(PyExc_TypeError, "iter argument must be callable");
        return NULL;
    }

    CHECK_CONFD_ERR(
            cdb_diff_iterate_resume(s, reply, iterator, (void *)&state));

    if (PyErr_Occurred()) {
        return NULL;
    }

    return PyInt_FromLong(state.iterret);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_modifications, EXT_API_FUN_CDB_GET_MODIFICATIONS)
{
    static char *kwlist[] = {
        "sock",
        "subid",
        "flags",
        "path",
        NULL };

    int s, subid, flags;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&iiO&",
                                     kwlist, sock_arg, &s, &subid, &flags,
                                     path_arg, &path)) {
        return NULL;
    }

    confd_tag_value_t *values;
    int nvalues;

    CHECK_CONFD_ERR_EXEC(
        cdb_get_modifications(s, subid, flags,
                              &values, &nvalues, path),
        free(path));

    PyObject *ret = PyList_New(nvalues);
    int c;

    for (c = 0; c < nvalues; c++) {
        PyObject *item = PyConfd_TagValue_New(&values[c]);

        if (item != NULL) {
            PyList_SetItem(ret, c, item);
        }
    }

    free_tag_values(values, nvalues);
    free(values);

    return ret;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_modifications_cli, EXT_API_FUN_CDB_GET_MODIFICATIONS_CLI)
{
    static char *kwlist[] = {
        "sock",
        "subid",
        "flags",
        NULL };

    int s, subid = 0, flags = 0;
    char *res = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&ii",
                                     kwlist, sock_arg, &s, &subid, &flags)) {
        return NULL;
    }
    CHECK_CONFD_ERR(cdb_get_modifications_cli(s, subid, flags, &res));
    if (res) {
        PyObject *ret = PyString_FromString((const char*)res);
        free(res);
        return ret;
    }
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_modifications_iter, EXT_API_FUN_CDB_GET_MODIFICATIONS_ITER)
{
    static char *kwlist[] = {
        "sock",
        "flags",
        NULL };

    int s, flags;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&i",
                                     kwlist, sock_arg, &s, &flags)) {
        return NULL;
    }

    confd_tag_value_t *values;
    int nvalues;

    CHECK_CONFD_ERR(
        cdb_get_modifications_iter(s, flags,
                                   &values, &nvalues));

    PyObject *ret = PyList_New(nvalues);
    int c;

    for (c = 0; c < nvalues; c++) {
        PyObject *item = PyConfd_TagValue_New(&values[c]);

        if (item != NULL) {
            PyList_SetItem(ret, c, item);
        }
    }

    free_tag_values(values, nvalues);
    free(values);

    return ret;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_sub_progress, EXT_API_FUN_CDB_SUB_PROGRESS)
{
    static char *kwlist[] = {
        "sock",
        "msg",
        NULL };

    int s;
    char *msg;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&s",
                                     kwlist, sock_arg, &s, &msg)) {
        return NULL;
    }
    CHECK_CONFD_ERR(cdb_sub_progress(s, msg));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_sync_subscription_socket,
            EXT_API_FUN_CDB_SYNC_SUBSCRIPTION_SOCKET)
{
    static char *kwlist[] = {
        "sock",
        "st",
        NULL };

    int s;
    enum cdb_subscription_sync_type st;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&i",
                                     kwlist, sock_arg, &s, &st)) {
        return NULL;
    }
    CHECK_CONFD_ERR(cdb_sync_subscription_socket(s, st));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_sub_abort_trans, EXT_API_FUN_CDB_SUB_ABORT_TRANS)
{
    static char *kwlist[] = {
        "sock",
        "code",
        "apptag_ns",
        "apptag_tag",
        "reason",
        NULL };

    int s, apptag_ns, apptag_tag;
    enum confd_errcode code;
    char *reason;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&iiis",
                                     kwlist, sock_arg, &s, &code, &apptag_ns,
                                     &apptag_tag, &reason)) {
        return NULL;
    }
    CHECK_CONFD_ERR(cdb_sub_abort_trans(s, code, 0, 0, "%s", reason));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_sub_abort_trans_info, EXT_API_FUN_CDB_SUB_ABORT_TRANS_INFO)
{
    static char *kwlist[] = {
        "sock",
        "code",
        "apptag_ns",
        "apptag_tag",
        "error_info",
        "reason",
        NULL };

    int c, n, s, apptag_ns, apptag_tag;
    enum confd_errcode code;
    char *reason;
    PyObject *pyerrors;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&iiiOs",
                                     kwlist, sock_arg, &s, &apptag_ns,
                                     &apptag_tag, &code,
                                     &pyerrors, &reason)) {
        return NULL;
    }

    if (!PyList_Check(pyerrors)) {
        PyErr_Format(PyExc_TypeError,
                     "error_info argument must be a list of"
                     CONFD_PY_MODULE ".TagValue instances");
        return NULL;
    }

    n = (int) PyList_Size(pyerrors);
    confd_tag_value_t errors[n];


    for (c = 0; c < n; c++) {
        PyObject *item = PyList_GetItem(pyerrors, c);

        if (!PyConfd_TagValue_CheckExact(item)) {
            PyErr_Format(PyExc_TypeError,
                         "values items must be a "
                         CONFD_PY_MODULE ".TagValue instances");
            return NULL;
        }

        const confd_tag_value_t *tv = PyConfd_TagValue_PTR(item);

        errors[c].tag = tv->tag;
        memcpy(&errors[c].v, &tv->v, sizeof(confd_value_t));
    }

    CHECK_CONFD_ERR(cdb_sub_abort_trans_info(s, code, apptag_ns, apptag_tag,
                                             errors, n,
                                             "%s", reason));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_set_elem, EXT_API_FUN_CDB_SET_ELEM)
{
    static char *kwlist[] = {
        "sock",
        "value",
        "path",
        NULL };

    int s;
    char *path;
    PyObject *cv;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&OO&",
                                     kwlist, sock_arg, &s, &cv,
                                     path_arg, &path)) {
        return NULL;
    }
    if (PyConfd_Value_CheckExact(cv)) {
        CHECK_CONFD_ERR_EXEC(
            cdb_set_elem(s,
              PyConfd_Value_PTR((PyConfd_Value_Object *)cv), path),
            free(path));
        Py_RETURN_NONE;
    }
    if (PyString_Check(cv)) {
        int ret;
        CONFD_PY_WITH_C_STR(cv, name) {
            CHECK_CONFD_ERR_EXEC(
                ret = cdb_set_elem2(s, name, path),
                free(path));
        }
        Py_RETURN_NONE;
    }

    free(path);
    PyErr_Format(PyExc_TypeError,
            "value argument must be a "
            CONFD_PY_MODULE ".Value or a string");
    return NULL;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_create, EXT_API_FUN_CDB_CREATE)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL };

    int s;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&",
                                     kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(cdb_create(s, path), free(path));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_delete, EXT_API_FUN_CDB_DELETE)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL };

    int s;
    char *path;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&",
                                     kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(cdb_delete(s, path), free(path));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_set_object, EXT_API_FUN_CDB_SET_OBJECT)
{
    static char *kwlist[] = {
        "sock",
        "values",
        "path",
        NULL };

    int s, c, n;
    char *path;
    PyObject *pyvalues;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&OO&",
                                     kwlist, sock_arg, &s, &pyvalues,
                                     path_arg, &path)) {
        return NULL;
    }

    if (!PyList_Check(pyvalues)) {
        PyErr_Format(PyExc_TypeError,
                     "values argument must be a list");
        return NULL;
    }

    n = (int) PyList_Size(pyvalues);
    confd_value_t values[n];

    for (c = 0; c < n; c++) {
        PyConfd_Value_Object *item =
            (PyConfd_Value_Object *) PyList_GetItem(pyvalues, c);

        if (!PyConfd_Value_CheckExact((PyObject *)item)) {
            PyErr_Format(PyExc_TypeError,
                         "values items must be "
                         CONFD_PY_MODULE ".Value instances");
            return NULL;
        }

        confd_value_t *v = PyConfd_Value_PTR(item);
        memcpy(&values[c], v, sizeof(confd_value_t));
    }

    CHECK_CONFD_ERR_EXEC(cdb_set_object(s, values, n, path),
        free(path));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_set_values, EXT_API_FUN_CDB_SET_VALUES)
{
    static char *kwlist[] = {
        "sock",
        "values",
        "path",
        NULL };

    int s;
    PyObject *pyvalues;
    char *path;
    int c;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&OO&",
                          kwlist, sock_arg, &s, &pyvalues, path_arg, &path)) {
        return NULL;
    }

    if (!PyList_Check(pyvalues)) {
        PyErr_Format(PyExc_TypeError,
                     "values argument must be a list");
        return NULL;
    }

    int n = (int) PyList_Size(pyvalues);
    confd_tag_value_t values[n];

    for (c = 0; c < n; c++) {
        PyObject *item = PyList_GetItem(pyvalues, c);

        if (!PyConfd_TagValue_CheckExact(item)) {
            PyErr_Format(PyExc_TypeError,
                         "values items must be "
                         CONFD_PY_MODULE ".TagValue instances");
            return NULL;
        }

        confd_tag_value_t *tv = PyConfd_TagValue_PTR(item);

        values[c].tag = tv->tag;
        memcpy(&values[c].v, &tv->v, sizeof(confd_value_t));
    }

    CHECK_CONFD_ERR_EXEC(cdb_set_values(s, values, n, path),
        free(path));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_get_case, EXT_API_FUN_CDB_GET_CASE)
{
    static char *kwlist[] = {
        "sock",
        "choice",
        "path",
        NULL };

    int s;
    char *choice;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&sO&",
                                     kwlist, sock_arg, &s, &choice,
                                     path_arg, &path))
        return NULL;

    PyConfd_Value_Object *rcase;
    if ((rcase = PyConfd_Value_New_NoInit()) == NULL) {
        return NULL;
    }

    CONFD_RET_CHECK_ERR(
        cdb_get_case(s, (const char *)choice,
                     PyConfd_Value_PTR(rcase),
                     (const char *)path), rcase,
        free(path));
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_set_case, EXT_API_FUN_CDB_SET_CASE)
{
    static char *kwlist[] = {
        "sock",
        "choice",
        "scase",
        "path",
        NULL };

    int s;
    char *choice;
    char *scase;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&ssO&",
                                     kwlist, sock_arg, &s, &choice,
                                     &scase, path_arg, &path))
        return NULL;

    CHECK_CONFD_ERR_EXEC(
        cdb_set_case(s, (const char *)choice,
                     (const char*)scase,
                     (const char *)path),
        free(path));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_cdb_cs_node_cd, EXT_API_FUN_CDB_CS_NODE_CD)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL };

    int s;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&O&", kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }

    struct confd_cs_node *node;
    CONFD_EXEC((node = cdb_cs_node_cd(s, path)));
    free(path);
    if (!node) {
        return confdPyConfdError();
    }

    return newConfdCsNode(node);
}

/* ------------------------------------------------------------------------- */

static PyObject *not_yet_implemented(PyObject *self, PyObject *args)
{
    return confdPyNotImplementedError();
}

#if 0
static PyObject *deprecated_function(PyObject *self, PyObject *args)
{
    return confdPyDeprecatedFunctionError();
}
#endif

PyDoc_STRVAR(doc_nyi, "Function not yet implemented.");

#if 0
PyDoc_STRVAR(doc_deprecated_function, "Function is deprecated.");
#endif

/* Skip cdb_diff_match */
#define _cdb_diff_match not_yet_implemented
#define doc_cdb_diff_match doc_nyi


#include "../doc/src/cdb_doc.c"


#define PYMOD_ENTRY(NAME) {# NAME, (PyCFunction)_cdb_ ## NAME, \
                           METH_VARARGS | METH_KEYWORDS, \
                           _cdb_ ## NAME ## __doc__}

static PyMethodDef _cdb_Methods[] = {

    PYMOD_ENTRY(get_replay_txids),
    PYMOD_ENTRY(replay_subscriptions),

    PYMOD_ENTRY(close),
    PYMOD_ENTRY(connect),
    PYMOD_ENTRY(connect_name),
    PYMOD_ENTRY(end_session),
    PYMOD_ENTRY(get),
    PYMOD_ENTRY(get_values),
    PYMOD_ENTRY(get_object),
    PYMOD_ENTRY(get_objects),

    PYMOD_ENTRY(get_modifications),
    PYMOD_ENTRY(get_modifications_cli),
    PYMOD_ENTRY(get_modifications_iter),

    PYMOD_ENTRY(mandatory_subscriber),
    PYMOD_ENTRY(read_subscription_socket),
    PYMOD_ENTRY(read_subscription_socket2),

    PYMOD_ENTRY(start_session),
    PYMOD_ENTRY(start_session2),

    PYMOD_ENTRY(sub_abort_trans),
    PYMOD_ENTRY(sub_abort_trans_info),
    PYMOD_ENTRY(sub_progress),

    PYMOD_ENTRY(subscribe),
    PYMOD_ENTRY(subscribe2),
    PYMOD_ENTRY(subscribe_done),
    PYMOD_ENTRY(sync_subscription_socket),

    PYMOD_ENTRY(set_namespace),
    PYMOD_ENTRY(wait_start),

    PYMOD_ENTRY(get_phase),
    PYMOD_ENTRY(get_txid),
    PYMOD_ENTRY(initiate_journal_compaction),
    PYMOD_ENTRY(get_user_session),
    PYMOD_ENTRY(get_transaction_handle),
    PYMOD_ENTRY(set_timeout),
    PYMOD_ENTRY(exists),
    PYMOD_ENTRY(cd),
    PYMOD_ENTRY(pushd),
    PYMOD_ENTRY(popd),
    PYMOD_ENTRY(getcwd),
    PYMOD_ENTRY(getcwd_kpath),
    PYMOD_ENTRY(num_instances),
    PYMOD_ENTRY(next_index),
    PYMOD_ENTRY(index),
    PYMOD_ENTRY(is_default),
    PYMOD_ENTRY(oper_subscribe),
    PYMOD_ENTRY(trigger_subscriptions),
    PYMOD_ENTRY(trigger_oper_subscriptions),
    PYMOD_ENTRY(diff_iterate),
    PYMOD_ENTRY(diff_iterate_resume),

    PYMOD_ENTRY(get_case),
    PYMOD_ENTRY(set_elem),
    PYMOD_ENTRY(set_case),
    PYMOD_ENTRY(create),
    PYMOD_ENTRY(delete),
    PYMOD_ENTRY(set_object),
    PYMOD_ENTRY(set_values),
    PYMOD_ENTRY(cs_node_cd),
    /*SKIP*/
    {"diff_match", _cdb_diff_match,
     METH_VARARGS, doc_cdb_diff_match},
    {NULL, NULL, 0, NULL}
};

/* ************************************************************************ */
/* Module initialization                                                    */
/* ************************************************************************ */

#define MODULE CONFD_PY_MODULE ".cdb"

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    MODULE,
    CDB_MODULE_DOCSTR(CONFD_PY_PRODUCT),
    0,
    _cdb_Methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyObject* init__cdb_module(void)
{
    PyObject *m = NULL;

    if ((m = PyModule_Create(&moduledef)) == NULL) {
        goto error;
    }

    /* Add constants */
#define ADD_CONST(C_NAME, PY_NAME)                      \
    (void)PyModule_AddIntConstant(m, PY_NAME, C_NAME);

#define ADD_CONST_STR(C_NAME, PY_NAME)                          \
    (void)PyModule_AddStringConstant(m, PY_NAME, C_NAME);


#include "gen_add_cdb_const.c"

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
