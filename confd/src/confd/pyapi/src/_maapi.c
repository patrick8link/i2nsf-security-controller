/*
 * Copyright 2013 Tail-F Systems AB
 *
 * Low-level Python MAAPI API
 *
 */

// include first, order is significant to get defines correct
#include "confdpy_config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/poll.h>

#include <confd.h>
#include <confd_maapi.h>

#include "confdpy_err.h"
#include "types.h"
#include "common.h"

#define INITIAL_BUF_SIZE 1024
#define MAX_RES_SIZE 1024

#define maapiCursor_Ptr(v) (&((v)->ob_val))
#define maapiCursor_Check(v) \
    (v != NULL && ((PyObject*)v)->ob_type == maapiCursorType)

typedef struct {
    PyObject_HEAD
    struct maapi_cursor ob_val;
    char *secondary_index;
    char *xpath_expr;
} maapiCursor;


static PyTypeObject *maapiCursorType = NULL;
static maapiCursor *newMaapiCursor(const char *secondary_index,
                                   const char *xpath_expr);
static confd_tag_value_t *mk_tagvalues_from_pylist(PyObject *list, int n);

/* ************************************************************************ */
/* confd_lib_maapi API functions                                            */
/* ************************************************************************ */
EXT_API_FUN(_maapi_connect, EXT_API_FUN_MAAPI_CONNECT)
{
    static char *kwlist[] = { "sock", "ip", "port", "path", NULL };

    PyObject *sock, *tmp;
    int s, family;
    char *ipstr = NULL;
    int port;
    char *pstr = NULL;

    struct in_addr in;
    struct sockaddr_in inaddr;
    struct sockaddr_in6 inaddr6;
    struct sockaddr_un unaddr;
    struct sockaddr *addr;
    socklen_t addrlen;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O|sis", kwlist, &sock, &ipstr, &port, &pstr)) {
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
        return 0;
    }
    family = (int)PyInt_AsLong(tmp);
    Py_DECREF(tmp);
    /* should check that type = SOCK_STREAM */

    switch (family) {
    case AF_UNIX:
        if (!pstr) {
            PyErr_SetString(PyExc_TypeError,
                    "path argument must be provided for an AF_UNIX socket");
            return NULL;
        }
        unaddr.sun_family = AF_UNIX;
        snprintf(unaddr.sun_path, sizeof(unaddr.sun_path), "%s", pstr);
        addr = (struct sockaddr *)&unaddr;
        addrlen = sizeof(unaddr);
        break;

    case AF_INET:
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

    CHECK_CONFD_ERR(maapi_connect(s, addr, addrlen));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_load_schemas, EXT_API_FUN_MAAPI_LOAD_SCHEMAS)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_load_schemas(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_load_schemas_list, EXT_API_FUN_MAAPI_LOAD_SCHEMAS_LIST)
{
    static char *kwlist[] = {
        "sock",
        "flags",
        "nshash",
        "nsflags",
        NULL
    };

    int s;
    int flags;
    PyObject *pynshash;
    PyObject *pynsflags;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOO", kwlist, sock_arg, &s, &flags, &pynshash, &pynsflags)) {
        return NULL;
    }

    py_u_int32_list_t nshash = {0};
    if (! confd_py_alloc_py_u_int32_list(pynshash, &nshash, "nshash")) {
        return NULL;
    }
    py_int_list_t nsflags = {0};
    if (! confd_py_alloc_py_int_list(pynsflags, &nsflags, "nsflags")) {
        confd_py_free_py_u_int32_list(&nshash);
        return NULL;
    }

    if (nshash.size != nsflags.size) {
        PyErr_Format(PyExc_TypeError,
                "nshash and nsflags lists must have same length");
        confd_py_free_py_int_list(&nsflags);
        confd_py_free_py_u_int32_list(&nshash);
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(maapi_load_schemas_list(s, flags, nshash.list,
                                                 nsflags.list, nshash.size),
                         {
                             confd_py_free_py_int_list(&nsflags);
                             confd_py_free_py_u_int32_list(&nshash);
                         });

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_close, EXT_API_FUN_MAAPI_CLOSE)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    PyObject *sock;
    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &sock)) {
        return NULL;
    }

    sock_arg(sock, &s);

    /* N.B. Don't call maapi_close here. */

    if (PyObject_CallMethod(sock, "close", NULL) == NULL) {
        /* CallMethod sets up the exception */
        return NULL;
    }

    Py_RETURN_NONE;
}

static int handle_start_user_session_args(
        PyObject *pygroups,
        const char *src_addr,
        py_string_list_t *groups_sl,
        struct confd_ip *ip)
{
    ip->af = AF_INET;
    if (inet_pton(AF_INET, src_addr, &(ip->ip.v4)) != 1) {
        ip->af = AF_INET6;

        if (inet_pton(AF_INET6, src_addr, &(ip->ip.v6)) != 1) {
            PyErr_Format(PyExc_ValueError, "Invalid source address.");
            return 0;
        }
    }

    if (! confd_py_alloc_py_string_list(pygroups, groups_sl, "groups")) {
        return 0;
    }

    return 1;
}

EXT_API_FUN(_maapi_start_user_session, EXT_API_FUN_MAAPI_START_USER_SESSION)
{
    static char *kwlist[] = {
        "sock",
        "username",
        "context",
        "groups",
        "src_addr",
        "prot",
        NULL
    };


    int s;
    char *user = 0;
    const char *context = NULL;
    PyObject* pygroups = NULL;
    const char *src_addr = NULL;
    int prot = 0;
    struct confd_ip ip;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ssOsi", kwlist,
                sock_arg, &s, &user, &context, &pygroups, &src_addr, &prot)) {
        return NULL;
    }

    py_string_list_t groups_sl = {0};
    if (!handle_start_user_session_args(pygroups, src_addr, &groups_sl, &ip)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(maapi_start_user_session(s, user, context,
                                                  (const char**)groups_sl.list,
                                                  groups_sl.size, &ip, prot),
                         confd_py_free_py_string_list(&groups_sl));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_start_user_session2, EXT_API_FUN_MAAPI_START_USER_SESSION2)
{
    static char *kwlist[] = {
        "sock",
        "username",
        "context",
        "groups",
        "src_addr",
        "src_port",
        "prot",
        NULL
    };


    int s;
    char *user = 0;
    const char *context = NULL;
    PyObject* pygroups = NULL;
    const char *src_addr = NULL;
    int src_port = 0;
    int prot = 0;
    struct confd_ip ip;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ssOsii", kwlist,
                sock_arg, &s, &user, &context, &pygroups,
                &src_addr, &src_port, &prot)) {
        return NULL;
    }

    py_string_list_t groups_sl = {0};
    if (!handle_start_user_session_args(pygroups, src_addr, &groups_sl, &ip)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(maapi_start_user_session2(s, user, context,
                                                   (const char**)groups_sl.list,
                                                   groups_sl.size, &ip,
                                                   src_port, prot),
                         confd_py_free_py_string_list(&groups_sl));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_start_user_session3, EXT_API_FUN_MAAPI_START_USER_SESSION3)
{
    static char *kwlist[] = {
        "sock",
        "username",
        "context",
        "groups",
        "src_addr",
        "src_port",
        "prot",
        "vendor",
        "product",
        "version",
        "client_id",
        NULL
    };


    int s;
    char *user = 0;
    const char *context = NULL;
    PyObject* pygroups = NULL;
    const char *src_addr = NULL;
    int src_port = 0;
    int prot = 0;
    struct confd_ip ip;
    const char *vendor = NULL;
    const char *product = NULL;
    const char *version = NULL;
    const char *client_id = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ssOsiizzzz", kwlist,
                sock_arg, &s, &user, &context, &pygroups,
                &src_addr, &src_port, &prot,
                &vendor, &product, &version, &client_id)) {
        return NULL;
    }

    py_string_list_t groups_sl = {0};
    if (!handle_start_user_session_args(pygroups, src_addr, &groups_sl, &ip)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(maapi_start_user_session3(s, user, context,
                                                   (const char**)groups_sl.list,
                                                   groups_sl.size, &ip,
                                                   src_port, prot,
                                                   vendor, product, version,
                                                   client_id),
                         confd_py_free_py_string_list(&groups_sl));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_end_user_session, EXT_API_FUN_MAAPI_END_USER_SESSION)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_end_user_session(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_kill_user_session, EXT_API_FUN_MAAPI_KILL_USER_SESSION)
{
    static char *kwlist[] = {
        "sock",
        "usessid",
        NULL
    };

    int s;
    int sid;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &sid)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_kill_user_session(s, sid));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_get_user_sessions, EXT_API_FUN_MAAPI_GET_USER_SESSIONS)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

#define MAX_SIDS 64

    int s;
    int sids[MAX_SIDS];
    int count;
    PyObject *ret;
    int c;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(count = maapi_get_user_sessions(s, sids, MAX_SIDS));

    if ((ret = PyList_New(count)) == NULL) {
        return NULL;
    }

    for (c = 0; c < count; c++) {
        PyList_SetItem(ret, c, PyInt_FromLong(sids[c]));
    }

    return ret;

#undef MAX_SIDS
}

EXT_API_FUN(_maapi_get_user_session, EXT_API_FUN_MAAPI_GET_USER_SESSION)
{
    static char *kwlist[] = {
        "sock",
        "usessid",
        NULL
    };

    int s;
    int sid;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &sid)) {
        return NULL;
    }

    struct confd_user_info *us =
        (struct confd_user_info*)malloc(sizeof(struct confd_user_info));
    memset(us, 0, sizeof(struct confd_user_info));

    CHECK_CONFD_ERR_EXECERR(result = maapi_get_user_session(s, sid, us),
                            free(us));

    return newConfdUserInfoFree(us);
}

EXT_API_FUN(_maapi_get_my_user_session_id,
            EXT_API_FUN_MAAPI_GET_MY_USER_SESSION_ID)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;
    int sid;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(sid = maapi_get_my_user_session_id(s));

    return Py_BuildValue("i", sid);
}

EXT_API_FUN(_maapi_set_user_session, EXT_API_FUN_MAAPI_SET_USER_SESSION)
{
    static char *kwlist[] = {
        "sock",
        "usessid",
        NULL
    };

    int s;
    int sid;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &sid)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_set_user_session(s, sid));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_get_user_session_identification,
            EXT_API_FUN_MAAPI_GET_USER_SESSION_IDENTIFICATION)
{
    static char *kwlist[] = {
        "sock",
        "usessid",
        NULL
    };

    int s;
    int sid;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &sid)) {
        return NULL;
    }

    struct confd_user_identification uident;

    CHECK_CONFD_ERR(maapi_get_user_session_identification(s, sid, &uident));

    PyObject *ret = PyDict_New();

    if (ret == NULL) {
        return ret;
    }


#define SET_AND_FREE_UIDENT_ITEM(attr) \
    if (uident.attr != NULL) { \
        PyDict_SetItemString(ret, #attr, PyString_FromString(uident.attr)); \
        free(uident.attr); \
    } else { \
        PyDict_SetItemString(ret, #attr, Py_None); \
    }

    SET_AND_FREE_UIDENT_ITEM(vendor);
    SET_AND_FREE_UIDENT_ITEM(product);
    SET_AND_FREE_UIDENT_ITEM(version);
    SET_AND_FREE_UIDENT_ITEM(client_identity);

    return ret;

#undef SET_AND_FREE_UIDENT_ITEM
}

EXT_API_FUN(_maapi_get_user_session_opaque,
            EXT_API_FUN_MAAPI_GET_USER_SESSION_OPAQUE)
{
    static char *kwlist[] = {
        "sock",
        "usessid",
        NULL
    };

    int s;
    int sid;
    char *opaque;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &sid)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_get_user_session_opaque(s, sid, &opaque));

    PyObject *ret = PyString_FromString(opaque);
    free(opaque);

    return ret;
}

EXT_API_FUN(_maapi_set_next_user_session_id,
            EXT_API_FUN_MAAPI_SET_NEXT_USER_SESSION_ID)
{
    static char *kwlist[] = {
        "sock",
        "usessid",
        NULL
    };

    int s;
    int usessid;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &usessid)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_set_next_user_session_id(s, usessid));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_get_authorization_info,
            EXT_API_FUN_MAAPI_GET_AUTHORIZATION_INFO)
{
    static char *kwlist[] = {
        "sock",
        "usessid",
        NULL
    };

    int s;
    int sid;
    struct confd_authorization_info *ainfo = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &sid)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_get_authorization_info(s, sid, &ainfo));

    PyObject *ret = newConfdAuthorizationInfo(ainfo);
    confd_free_authorization_info(ainfo);

    return ret;
}

EXT_API_FUN(_maapi_lock, EXT_API_FUN_MAAPI_LOCK)
{
    static char *kwlist[] = {
        "sock",
        "name",
        NULL
    };

    int s;
    int name;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &name)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_lock(s, name));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_unlock, EXT_API_FUN_MAAPI_UNLOCK)
{
    static char *kwlist[] = {
        "sock",
        "name",
        NULL
    };

    int s;
    int name;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &name)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_unlock(s, name));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_is_lock_set, EXT_API_FUN_MAAPI_IS_LOCK_SET)
{
    static char *kwlist[] = {
        "sock",
        "name",
        NULL
    };

    int s;
    int name;
    int usid;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &name)) {
        return NULL;
    }

    CHECK_CONFD_ERR(usid = maapi_is_lock_set(s, name));

    return Py_BuildValue("i", usid);
}

EXT_API_FUN(_maapi_lock_partial, EXT_API_FUN_MAAPI_LOCK_PARTIAL)
{
    static char *kwlist[] = {
        "sock",
        "name",
        "xpaths",
        NULL
    };

    int s;
    int name;
    PyObject *pyxpaths;
    int lockid;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO", kwlist, sock_arg, &s, &name, &pyxpaths)) {
        return NULL;
    }

    py_string_list_t xpaths_sl = {0};
    if (! confd_py_alloc_py_string_list(pyxpaths, &xpaths_sl, "xpaths")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(maapi_lock_partial(s, name,
                                            xpaths_sl.list, xpaths_sl.size,
                                            &lockid),
                         confd_py_free_py_string_list(&xpaths_sl));

    return Py_BuildValue("i", lockid);
}

EXT_API_FUN(_maapi_unlock_partial, EXT_API_FUN_MAAPI_UNLOCK_PARTIAL)
{
    static char *kwlist[] = {
        "sock",
        "lockid",
        NULL
    };

    int s;
    int lockid;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &lockid)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_unlock_partial(s, lockid));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_candidate_validate, EXT_API_FUN_MAAPI_CANDIDATE_VALIDATE)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_candidate_validate(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_candidate_commit, EXT_API_FUN_MAAPI_CANDIDATE_COMMIT)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_candidate_commit(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_candidate_confirmed_commit,
            EXT_API_FUN_MAAPI_CANDIDATE_CONFIRMED_COMMIT)
{
    static char *kwlist[] = {
        "sock",
        "timeoutsecs",
        NULL
    };

    int s;
    int timeoutsecs;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &timeoutsecs)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_candidate_confirmed_commit(s, timeoutsecs));

    Py_RETURN_NONE;
}


EXT_API_FUN(_maapi_candidate_commit_persistent,
            EXT_API_FUN_MAAPI_CANDIDATE_COMMIT_PERSISTENT)
{
    static char *kwlist[] = {
        "sock",
        "persist_id",
        NULL
    };

    int s;
    const char *persist_id;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&z", kwlist, sock_arg, &s, &persist_id)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_candidate_commit_persistent(s, persist_id));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_candidate_commit_info,
            EXT_API_FUN_MAAPI_CANDIDATE_COMMIT_INFO)
{
    static char *kwlist[] = {
        "sock",
        "persist_id",
        "label",
        "comment",
        NULL
    };

    int s;
    const char *persist_id;
    const char *label;
    const char *comment;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&zzz", kwlist, sock_arg, &s, &persist_id,
                 &label, &comment)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_candidate_commit_info(s, persist_id,
                                                label, comment));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_delete_config, EXT_API_FUN_MAAPI_DELETE_CONFIG)
{
    static char *kwlist[] = {
        "sock",
        "name",
        NULL
    };

    int s;
    int name;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &name)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_delete_config(s, name));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_candidate_confirmed_commit_persistent,
            EXT_API_FUN_MAAPI_CANDIDATE_CONFIRMED_COMMIT_PERSISTENT)
{
    static char *kwlist[] = {
        "sock",
        "timeoutsecs",
        "persist",
        "persist_id",
        NULL
    };

    int s;
    int timeoutsecs;
    char *persist;
    char *persist_id;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&izz", kwlist, sock_arg, &s, &timeoutsecs,
                &persist, &persist_id)) {
        return NULL;
    }

    CHECK_CONFD_ERR(
            maapi_candidate_confirmed_commit_persistent(
                s, timeoutsecs, persist, persist_id));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_candidate_confirmed_commit_info,
            EXT_API_FUN_MAAPI_CANDIDATE_CONFIRMED_COMMIT_INFO)
{
    static char *kwlist[] = {
        "sock",
        "timeoutsecs",
        "persist",
        "persist_id",
        "label",
        "comment",
        NULL
    };

    int s;
    int timeoutsecs;
    const char *persist;
    const char *persist_id;
    const char *label;
    const char *comment;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&izzzz", kwlist, sock_arg, &s, &timeoutsecs,
                 &persist, &persist_id, &label, &comment)) {
        return NULL;
    }

    CHECK_CONFD_ERR(
            maapi_candidate_confirmed_commit_info(
                s, timeoutsecs, persist, persist_id, label, comment));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_candidate_abort_commit,
            EXT_API_FUN_MAAPI_CANDIDATE_ABORT_COMMIT)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_candidate_abort_commit(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_candidate_abort_commit_persistent,
            EXT_API_FUN_MAAPI_CANDIDATE_ABORT_COMMIT_PERSISTENT)
{
    static char *kwlist[] = {
        "sock",
        "persist_id",
        NULL
    };

    int s;
    const char *persist_id;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&z", kwlist, sock_arg, &s, &persist_id)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_candidate_abort_commit_persistent(s, persist_id));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_candidate_reset, EXT_API_FUN_MAAPI_CANDIDATE_RESET)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_candidate_reset(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_confirmed_commit_in_progress,
            EXT_API_FUN_MAAPI_CONFIRMED_COMMIT_IN_PROGRESS)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_confirmed_commit_in_progress(s));

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_copy_running_to_startup,
            EXT_API_FUN_MAAPI_COPY_RUNNING_TO_STARTUP)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_copy_running_to_startup(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_is_running_modified, EXT_API_FUN_MAAPI_IS_RUNNING_MODIFIED)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_is_running_modified(s));

    if (result) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

EXT_API_FUN(_maapi_is_candidate_modified,
            EXT_API_FUN_MAAPI_IS_CANDIDATE_MODIFIED)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_is_candidate_modified(s));

    if (result) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

EXT_API_FUN(_maapi_start_trans, EXT_API_FUN_MAAPI_START_TRANS)
{
    static char *kwlist[] = {
        "sock",
        "name",
        "readwrite",
        NULL
    };

    int s;
    enum confd_dbname db = CONFD_RUNNING;
    enum confd_trans_mode rw = CONFD_READ;

    int th = -1;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist,sock_arg, &s, &db, &rw)) {
        return NULL;
    }

    CHECK_CONFD_ERR(th = maapi_start_trans(s, db, rw));

    return Py_BuildValue("i", th);
}


EXT_API_FUN(_maapi_start_trans2, EXT_API_FUN_MAAPI_START_TRANS2)
{
    static char *kwlist[] = {
        "sock",
        "name",
        "readwrite",
        "usid",
        NULL
    };

    int s;
    enum confd_dbname db = CONFD_RUNNING;
    enum confd_trans_mode rw = CONFD_READ;
    int usid = 0;

    int th = -1;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iii", kwlist,sock_arg, &s, &db, &rw, &usid)) {
        return NULL;
    }

    CHECK_CONFD_ERR(th = maapi_start_trans2(s, db, rw, usid));

    return Py_BuildValue("i", th);
}


EXT_API_FUN(_maapi_start_trans_flags, EXT_API_FUN_MAAPI_START_TRANS_FLAGS)
{
    static char *kwlist[] = {
        "sock",
        "name",
        "readwrite",
        "usid",
        "flags",
        NULL
    };

    int s;
    enum confd_dbname db = CONFD_RUNNING;
    enum confd_trans_mode rw = CONFD_READ;
    int usid = 0;
    int flags = 0;
    int th = -1;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iiii", kwlist,sock_arg, &s, &db, &rw, &usid, &flags)) {
        return NULL;
    }

    CHECK_CONFD_ERR(th = maapi_start_trans_flags(s, db, rw, usid, flags));

    return Py_BuildValue("i", th);
}


EXT_API_FUN(_maapi_start_trans_flags2, EXT_API_FUN_MAAPI_START_TRANS_FLAGS2)
{
    static char *kwlist[] = {
        "sock",
        "name",
        "readwrite",
        "usid",
        "flags",
        "vendor",
        "product",
        "version",
        "client_id",
        NULL
    };

    int s;
    enum confd_dbname db = CONFD_RUNNING;
    enum confd_trans_mode rw = CONFD_READ;
    int usid = 0;
    int flags = 0;
    int th = -1;
    const char *vendor = NULL;
    const char *product = NULL;
    const char *version = NULL;
    const char *client_id = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iiiizzzz", kwlist,sock_arg, &s, &db, &rw, &usid, &flags,
                &vendor, &product, &version, &client_id)) {
        return NULL;
    }

    CHECK_CONFD_ERR(th = maapi_start_trans_flags2(s, db, rw, usid, flags,
                            vendor, product, version, client_id));

    return Py_BuildValue("i", th);
}


EXT_API_FUN(_maapi_start_trans_in_trans, EXT_API_FUN_MAAPI_START_TRANS_IN_TRANS)
{
    static char *kwlist[] = {
        "sock",
        "readwrite",
        "usid",
        "thandle",
        NULL
    };

    int s;
    enum confd_trans_mode rw = CONFD_READ;
    int usid = 0;
    int thandle = 0;
    int th = -1;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iii", kwlist,sock_arg, &s, &rw, &usid, &thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(th = maapi_start_trans_in_trans(s, rw, usid, thandle));

    return Py_BuildValue("i", th);
}

EXT_API_FUN(_maapi_finish_trans, EXT_API_FUN_MAAPI_FINISH_TRANS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        NULL
    };

    int s;
    int thandle;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist,sock_arg, &s, &thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_finish_trans(s, thandle));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_validate_trans, EXT_API_FUN_MAAPI_VALIDATE_TRANS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "unlock",
        "forcevalidation",
        NULL
    };

    int s;
    int thandle;
    int unlock;
    int forcevalidation;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iii", kwlist,sock_arg, &s, &thandle, &unlock,
                &forcevalidation)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_validate_trans(s, thandle, unlock, forcevalidation));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_prepare_trans, EXT_API_FUN_MAAPI_PREPARE_TRANS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        NULL
    };

    int s;
    int thandle;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist,sock_arg, &s, &thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_prepare_trans(s, thandle));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_prepare_trans_flags, EXT_API_FUN_MAAPI_PREPARE_TRANS_FLAGS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "flags",
        NULL
    };

    int s;
    int thandle;
    int flags;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist,sock_arg, &s, &thandle, &flags)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_prepare_trans_flags(s, thandle, flags));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_commit_trans, EXT_API_FUN_MAAPI_COMMIT_TRANS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        NULL
    };

    int s;
    int thandle;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist,sock_arg, &s, &thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_commit_trans(s, thandle));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_abort_trans, EXT_API_FUN_MAAPI_ABORT_TRANS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        NULL
    };

    int s;
    int thandle;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist,sock_arg, &s, &thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_abort_trans(s, thandle));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_apply_trans, EXT_API_FUN_MAAPI_APPLY_TRANS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "keepopen",
        NULL
    };

    int s;
    int thandle;
    int keepopen;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist,sock_arg, &s, &thandle, &keepopen)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_apply_trans(s, thandle, keepopen));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_apply_trans_flags, EXT_API_FUN_MAAPI_APPLY_TRANS_FLAGS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "keepopen",
        "flags",
        NULL
    };

    int s;
    int thandle;
    int keepopen;
    int flags;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iii", kwlist,sock_arg, &s, &thandle, &keepopen, &flags)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_apply_trans_flags(s, thandle, keepopen, flags));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_get_rollback_id, EXT_API_FUN_MAAPI_GET_ROLLBACK_ID)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        NULL
    };

    int s;
    int thandle, fixed_id;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&i", kwlist,sock_arg, &s, &thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_get_rollback_id(s, thandle, &fixed_id));

    return PyInt_FromLong(fixed_id);
}

EXT_API_FUN(_maapi_set_namespace, EXT_API_FUN_MAAPI_SET_NAMESPACE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "hashed_ns",
        NULL
    };

    int s;
    int thandle;
    int hashed_ns;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist,sock_arg, &s, &thandle, &hashed_ns)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_set_namespace(s, thandle, hashed_ns));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_cd, EXT_API_FUN_MAAPI_CD)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",
        NULL
    };

    int s;
    int thandle;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&", kwlist,sock_arg, &s, &thandle, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_cd(s, thandle, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_pushd, EXT_API_FUN_MAAPI_PUSHD)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",
        NULL
    };

    int s;
    int thandle;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&", kwlist,sock_arg, &s, &thandle, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(maapi_pushd(s, thandle, path), free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_popd, EXT_API_FUN_MAAPI_POPD)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        NULL
    };

    int s;
    int thandle;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist,sock_arg, &s, &thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_popd(s, thandle));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_getcwd, EXT_API_FUN_MAAPI_GETCWD)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        NULL
    };

    int s;
    int thandle;
    size_t pathsz = INITIAL_BUF_SIZE;
    char path[INITIAL_BUF_SIZE];

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist,sock_arg, &s, &thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_getcwd2(s, thandle, &pathsz, path));
    if (pathsz < INITIAL_BUF_SIZE) {
        return PyString_FromString(path);
    } else {
        // buffer was not enough, alloc and try again.
        size_t path2sz = pathsz + 1;
        char *path2 = malloc(path2sz);
        PyObject *py_path2;
        CHECK_CONFD_ERR_EXECERR(maapi_getcwd2(s, thandle, &path2sz, path2),
                                free(path2));
        py_path2 = PyString_FromString(path2);
        free(path2);
        return py_path2;
    }
}

EXT_API_FUN(_maapi_getcwd_kpath, EXT_API_FUN_MAAPI_GETCWD_KPATH)
{

    static char *kwlist[] = {
        "sock",
        "thandle",
        NULL
    };

    int s;
    int thandle;
    confd_hkeypath_t *kp;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist,sock_arg, &s, &thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_getcwd_kpath(s, thandle, &kp));

    return newConfdHKeypathRefAutoFree(kp);

}

EXT_API_FUN(_maapi_exists, EXT_API_FUN_MAAPI_EXISTS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",
        NULL
    };

    int s;
    int thandle;
    char *path;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&", kwlist,sock_arg, &s, &thandle, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(result = maapi_exists(s, thandle, path),
            free(path));

    if (result) {
        Py_RETURN_TRUE;
    }
    else {
        Py_RETURN_FALSE;
    }
}

EXT_API_FUN(_maapi_num_instances, EXT_API_FUN_MAAPI_NUM_INSTANCES)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",
        NULL
    };

    int s;
    int thandle;
    char *path;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&", kwlist,sock_arg, &s, &thandle, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            result = maapi_num_instances(s, thandle, path),
            free(path));

    return PyInt_FromLong((long)result);
}

EXT_API_FUN(_maapi_get_elem, EXT_API_FUN_MAAPI_GET_ELEM)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",
        NULL
    };

    int s;
    int thandle;
    PyConfd_Value_Object *v;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&", kwlist, sock_arg, &s, &thandle, path_arg, &path)) {
        return NULL;
    }

    if ((v = PyConfd_Value_New_NoInit()) == NULL) {
        return NULL;
    }

    CONFD_RET_CHECK_ERR(
            maapi_get_elem(s, thandle, PyConfd_Value_PTR(v), path),
            v,
            free(path));
}

EXT_API_FUN(_maapi_init_cursor, EXT_API_FUN_MAAPI_INIT_CURSOR)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",
        "secondary_index",
        "xpath_expr",
        NULL
    };

    int s;
    int thandle;
    char *path;
    const char *secondary_index = NULL;
    const char *xpath_expr = NULL;
    maapiCursor *cur;
    struct maapi_cursor *mc;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&|zz", kwlist,sock_arg, &s, &thandle, path_arg, &path,
                &secondary_index, &xpath_expr)) {
        return NULL;
    }

    if ((cur = newMaapiCursor(secondary_index, xpath_expr)) == NULL) {
        return NULL;
    }

    mc = maapiCursor_Ptr(cur);
    CONFD_RET_ON_ERR(maapi_init_cursor(s, thandle, mc, path), cur);

    /* assign secondary index and xpath_expr _after_ init cursor, init
       sets them to NULL. */
    mc->secondary_index = cur->secondary_index;
    mc->xpath_expr = cur->xpath_expr;

    return (PyObject*)cur;
}

static PyObject *_py_cursor_ret_value(struct maapi_cursor *mc)
{
    if (mc->n > 0) {

        PyObject *list = PyList_New(mc->n);
        int c;

        for (c = 0; c < mc->n; c++) {
            PyConfd_Value_Object *v = PyConfd_Value_New_NoInit();

            if (v != NULL) {
                confd_value_dup_to(&mc->keys[c], PyConfd_Value_PTR(v));
                PyList_SetItem(list, c, (PyObject*) v);
            }
        }

        return list;
    } else {
        Py_RETURN_FALSE;
    }
}

EXT_API_FUN(_maapi_get_next, EXT_API_FUN_MAAPI_GET_NEXT)
{
    static char *kwlist[] = {
        "mc",
        NULL
    };

    maapiCursor *cur;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O", kwlist,&cur)) {
        return NULL;
    }

    if (maapiCursor_Check(cur)) {
        struct maapi_cursor *mc = maapiCursor_Ptr(cur);
        CHECK_CONFD_ERR(maapi_get_next(mc));

        return _py_cursor_ret_value(mc);

    } else {
        PyErr_Format(PyExc_TypeError,
                "mc argument must be a " CONFD_PY_MODULE ".maapi.Cursor");
        return NULL;
    }

}

EXT_API_FUN(_maapi_find_next, EXT_API_FUN_MAAPI_FIND_NEXT)
{
    static char *kwlist[] = {
        "mc",
        "type",
        "inkeys",
        NULL
    };

    maapiCursor *cur;
    int type;
    PyObject *pyinkeys;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "OiO", kwlist, &cur, &type, &pyinkeys)) {
        return NULL;
    }

    if (!maapiCursor_Check(cur)) {
        PyErr_Format(PyExc_TypeError,
                "mc argument must be a "
                CONFD_PY_MODULE ".maapi.Cursor instance");
        return NULL;
    }

    py_confd_value_t_list_t inkeys = {0};
    if (!alloc_py_confd_value_t_list(pyinkeys, &inkeys, "inkeys")) {
        return NULL;
    }


    struct maapi_cursor *mc = maapiCursor_Ptr(cur);

    CHECK_CONFD_ERR_EXEC(
            maapi_find_next(mc, type, inkeys.list, inkeys.size),
            free_py_confd_value_t_list(&inkeys));

    return _py_cursor_ret_value(mc);
}

EXT_API_FUN(_maapi_destroy_cursor, EXT_API_FUN_MAAPI_DESTROY_CURSOR)
{
    static char *kwlist[] = {
        "mc",
        NULL
    };

    maapiCursor *mc;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O", kwlist,&mc)) {
        return NULL;
    }

    if (maapiCursor_Check(mc)) {
        maapi_destroy_cursor(maapiCursor_Ptr(mc));
    } else {
        PyErr_Format(PyExc_TypeError,
                "mc argument must be a " CONFD_PY_MODULE ".maapi.Cursor");
        return NULL;
    }

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_set_elem, EXT_API_FUN_MAAPI_SET_ELEM)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "v",
        "path",
        NULL
    };

    int s;
    int thandle;
    char *path;
    PyObject *cv;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOO&", kwlist,sock_arg, &s, &thandle, &cv,
                path_arg, &path)) {
        return NULL;
    }

    if (PyConfd_Value_CheckExact(cv)) {
        CHECK_CONFD_ERR_EXEC(maapi_set_elem(s, thandle,
                    PyConfd_Value_PTR((PyConfd_Value_Object *)cv), path),
                    free(path));
        Py_RETURN_NONE;
    } else {
        free(path);
        PyErr_Format(PyExc_TypeError,
                "argument 3 must be confd.Value");
        return NULL;
    }
}

EXT_API_FUN(_maapi_set_elem2, EXT_API_FUN_MAAPI_SET_ELEM2)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "strval",
        "path",
        NULL
    };

    int s;
    int thandle;
    const char *strval;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&isO&", kwlist,sock_arg, &s, &thandle, &strval,
                path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_set_elem2(s, thandle, strval, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_create, EXT_API_FUN_MAAPI_CREATE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",
        NULL
    };

    int s;
    int thandle;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&", kwlist, sock_arg, &s, &thandle, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(maapi_create(s, thandle, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_delete, EXT_API_FUN_MAAPI_DELETE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",
        NULL
    };

    int s;
    int thandle;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&", kwlist, sock_arg, &s, &thandle, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(maapi_delete(s, thandle, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_get_object, EXT_API_FUN_MAAPI_GET_OBJECT)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "n",
        "keypath",
        NULL
    };

    int s;
    int thandle;
    int n;
    char *path;
    int result;
    int c;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iiO&", kwlist,sock_arg, &s, &thandle, &n, path_arg, &path)) {
        return NULL;
    }

    confd_value_t *values =
        (confd_value_t*)malloc(sizeof(confd_value_t) * n);

    CHECK_CONFD_ERR_EXECERR(
        result = maapi_get_object(s, thandle, values, n, path),
        {
            free(values);
            free(path);
        });

    free(path);

    if (result > n)
        result = n;

    PyObject *list = PyList_New(result);
    if (list == NULL) {
        goto error;
    }

    for (c = 0; c < result; c++) {
        PyList_SetItem(list, c,
                (PyObject *) PyConfd_Value_New_DupTo(&values[c]));
    }

error:

    for (c = 0; c < result; c++) {
        confd_free_value(&values[c]);
    }
    free(values);

    return list;
}

EXT_API_FUN(_maapi_get_objects, EXT_API_FUN_MAAPI_GET_OBJECTS)
{
    static char *kwlist[] = {
        "mc",
        "n",
        "nobj",
        NULL
    };

    maapiCursor *cur;
    int n;
    int nobj;
    int result;
    int row, col, nrows, ncols;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "Oii", kwlist,&cur, &n, &nobj)) {
        return NULL;
    }

    if (!maapiCursor_Check(cur)) {
        PyErr_Format(PyExc_TypeError,
                "mc argument must be a "
                CONFD_PY_MODULE ".maapi.Cursor instance");
        return NULL;
    }

    int rowsize = n;
    struct maapi_cursor *mc = maapiCursor_Ptr(cur);
    confd_value_t values[n*nobj];

    CHECK_CONFD_ERR(result = maapi_get_objects(mc, values, n, &nobj));

    nrows = nobj;
    ncols = result;

    PyObject *rows = PyList_New(nrows);
    if (rows == NULL) {
        goto error;
    }

    for (row = 0; row < nrows; row++) {
        PyObject *cols = PyList_New(ncols);

        if (cols == NULL) {
            goto error;
        }

        PyList_SetItem(rows, row, cols);

        for (col = 0; col < ncols; col++) {
            int ix = row * rowsize + col;

            PyList_SetItem(cols, col,
                (PyObject *) PyConfd_Value_New_DupTo(&values[ix]));
        }
    }

error:

    for (row = 0; row < nrows; row++) {
        for (col = 0; col < ncols; col++) {
            int ix = row * rowsize + col;
            confd_free_value(&values[ix]);
        }
    }

    return rows;
}

EXT_API_FUN(_maapi_get_values, EXT_API_FUN_MAAPI_GET_VALUES)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "values",
        "keypath",
        NULL
    };

    int s;
    int thandle;
    PyObject *pyvalues;
    char *path;
    int c;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOO&", kwlist,sock_arg, &s, &thandle, &pyvalues,
                path_arg, &path)) {
        return NULL;
    }


    if (!PyList_Check(pyvalues)) {
        PyErr_Format(PyExc_TypeError,
                     "values argument must be a list");
        return NULL;
    }

    int n = (int) PyList_Size(pyvalues);
    confd_tag_value_t *values = mk_tagvalues_from_pylist(pyvalues, n);
    if (values == NULL) {
        return NULL; /* error */
    }

    CHECK_CONFD_ERR_EXECERR(maapi_get_values(s, thandle, values, n, path),
            {
                free(values);
                free(path);
            });

    for (c = 0; c < n; c++) {
        confd_tag_value_t *tv =
            PyConfd_TagValue_PTR(PyList_GetItem(pyvalues, c));
        /* Memory clean up done in the PyConfd_TagValue_Object destructor */
        memcpy(&(tv->v), &(values[c].v), sizeof(confd_value_t));
    }

    free(values);
    free(path);
    Py_INCREF(pyvalues);
    return pyvalues;
}

EXT_API_FUN(_maapi_set_object, EXT_API_FUN_MAAPI_SET_OBJECT)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "values",
        "keypath",
        NULL
    };

    int s;
    int thandle;
    PyObject *pyvalues;
    char *path;
    int c;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOO&", kwlist,sock_arg, &s, &thandle, &pyvalues,
                path_arg, &path)) {
        return NULL;
    }

    if (!PyList_Check(pyvalues)) {
        PyErr_Format(PyExc_TypeError,
                     "values argument must be a list");
        return NULL;
    }

    int n = (int) PyList_Size(pyvalues);
    confd_value_t *values =
        (confd_value_t*)malloc(sizeof(confd_value_t) * n);

    for (c = 0; c < n; c++) {
        PyConfd_Value_Object *item =
            (PyConfd_Value_Object *) PyList_GetItem(pyvalues, c);

        if (!PyConfd_Value_CheckExact((PyObject *)item)) {
            PyErr_Format(PyExc_TypeError,
                         "values items must be "
                         CONFD_PY_MODULE ".Value instances");
            free(values);
            return NULL;
        }

        confd_value_t *v = PyConfd_Value_PTR(item);
        memcpy(&values[c], v, sizeof(confd_value_t));
    }

    CHECK_CONFD_ERR_EXEC(maapi_set_object(s, thandle, values, n, path),
            {
                free(values);
                free(path);
            });

    Py_RETURN_NONE;
}

static confd_tag_value_t *mk_tagvalues_from_pylist(PyObject *list, int n)
{
    int c;
    confd_tag_value_t *values =
        (confd_tag_value_t*)malloc(sizeof(confd_tag_value_t) * n);

    for (c = 0; c < n; c++) {
        PyObject *item = PyList_GetItem(list, c);

        if (!PyConfd_TagValue_CheckExact(item)) {
            PyErr_Format(PyExc_TypeError, "values items must be "
                         CONFD_PY_MODULE ".TagValue instances");
            free(values);
            return NULL;
        }

        confd_tag_value_t *tv = PyConfd_TagValue_PTR(item);

        values[c].tag = tv->tag;
        memcpy(&(values[c].v), &tv->v, sizeof(confd_value_t));
    }
    return values;
}

EXT_API_FUN(_maapi_set_values, EXT_API_FUN_MAAPI_SET_VALUES)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "values",
        "keypath",
        NULL
    };

    int s;
    int thandle;
    PyObject *pyvalues;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOO&", kwlist,sock_arg, &s, &thandle, &pyvalues,
                path_arg, &path)) {
        return NULL;
    }

    if (!PyList_Check(pyvalues)) {
        PyErr_Format(PyExc_TypeError, "values argument must be a list");
        return NULL;
    }

    int n = (int) PyList_Size(pyvalues);
    if (n == 0) {
        Py_RETURN_NONE;
    }

    confd_tag_value_t *values = mk_tagvalues_from_pylist(pyvalues, n);
    if (values == NULL) {
        return NULL; /* error */
    }

    CHECK_CONFD_ERR_EXEC(maapi_set_values(s, thandle, values, n, path),
            {
                free(values);
                free(path);
            });

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_get_case, EXT_API_FUN_MAAPI_GET_CASE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "choice",
        "keypath",
        NULL
    };

    int s;
    int thandle;
    const char *choice;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&isO&", kwlist,sock_arg, &s, &thandle, &choice,
                path_arg, &path)) {
        return NULL;
    }

    confd_value_t rcase;

    CHECK_CONFD_ERR_EXEC(
            maapi_get_case(s, thandle, choice, &rcase, path),
            free(path));

    PyConfd_Value_Object *ret = PyConfd_Value_New_DupTo(&rcase);

    confd_free_value(&rcase);

    return (PyObject *) ret;
}

EXT_API_FUN(_maapi_get_attrs, EXT_API_FUN_MAAPI_GET_ATTRS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "attrs",
        "keypath",
        NULL
    };

    int s;
    int thandle;
    PyObject *pyattrs;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOO&", kwlist,sock_arg, &s, &thandle, &pyattrs,
                path_arg, &path)) {
        return NULL;
    }

    if (!PyList_Check(pyattrs)) {
        PyErr_Format(PyExc_TypeError,
                     "attrs argument must be a list");
        return NULL;
    }


    int num_attrs = (int) PyList_Size(pyattrs);
    u_int32_t attrs[num_attrs];
    confd_attr_value_t *attr_vals;
    int num_vals;
    int c;

    for (c = 0; c < num_attrs; c++) {
        PyObject *item = PyList_GetItem(pyattrs, c);
        attrs[c] = (u_int32_t) PyLong_AsLong(item);
    }


    CHECK_CONFD_ERR_EXEC(
            maapi_get_attrs(s, thandle, attrs, num_attrs, &attr_vals,
                            &num_vals, path),
            free(path));

    PyObject *ret = PyList_New(num_vals);

    if (ret == NULL) {
        goto error;
    }

    for (c = 0; c < num_vals; c++) {
        PyObject *item =
            PyConfd_AttrValue_New_DupTo_Py(&attr_vals[c]);
        PyList_SetItem(ret, c, (PyObject *) item);
    }

error:

    if (num_vals > 0) {
        for (c = 0; c < num_vals; c++) {
            confd_free_value(&attr_vals[c].v);
        }
        free(attr_vals);
    }

    return (PyObject *) ret;
}

EXT_API_FUN(_maapi_set_attr, EXT_API_FUN_MAAPI_SET_ATTR)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "attr",
        "v",
        "keypath",
        NULL
    };

    int s;
    int thandle;
    u_int32_t attr;
    PyObject *pyv;
    char *path;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iIOO&", kwlist,sock_arg, &s, &thandle, &attr, &pyv,
                path_arg, &path)) {
        return NULL;
    }

    if (PyConfd_Value_CheckExact(pyv)) {
        confd_value_t *v = PyConfd_Value_PTR((PyConfd_Value_Object *) pyv);

        CHECK_CONFD_ERR_EXEC(
                maapi_set_attr(s, thandle, attr, v, path),
                free(path));
        Py_RETURN_NONE;
    }

    if (!PyList_CheckExact(pyv)) {
        PyErr_Format(PyExc_TypeError,
                     "v argument must be a "
                     CONFD_PY_MODULE ".Value instance or a list");
        return NULL;
    }

    // Python list

    int n = (int) PyList_Size(pyv);

    if (n > 0) {
        confd_value_t tag[n];
        confd_value_t tags;

        int c;

        for (c = 0; c < n; c++) {
            PyObject *item = PyList_GetItem(pyv, c);

            if (!PyConfd_Value_CheckExact(item)) {
                PyErr_Format(PyExc_TypeError,
                                "item %d in v must be a "
                                CONFD_PY_MODULE ".Value instance", c);

                return NULL;
            }

            memcpy(&tag[c], PyConfd_Value_PTR((PyConfd_Value_Object *) item),
                    sizeof(confd_value_t));
        }

        CONFD_SET_LIST(&tags, tag, n);
        CHECK_CONFD_ERR_EXEC(
                maapi_set_attr(s, thandle, attr, &tags, path),
                free(path));
    }

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_delete_all, EXT_API_FUN_MAAPI_DELETE_ALL)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "how",
        NULL
    };

    int s;
    int thandle;
    enum maapi_delete_how how;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist,sock_arg, &s, &thandle, &how)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_delete_all(s, thandle, how));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_revert, EXT_API_FUN_MAAPI_REVERT)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        NULL
    };

    int s;
    int thandle;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist,sock_arg, &s, &thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_revert(s, thandle));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_set_flags, EXT_API_FUN_MAAPI_SET_FLAGS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "flags",
        NULL
    };

    int s;
    int thandle;
    int flags;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist,sock_arg, &s, &thandle, &flags)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_set_flags(s, thandle, flags));

    Py_RETURN_NONE;
}


EXT_API_FUN(_maapi_set_delayed_when, EXT_API_FUN_MAAPI_SET_DELAYED_WHEN)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "on",
        NULL
    };

    int s;
    int thandle;
    int result;
    int on;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist,sock_arg, &s, &thandle, &on)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_set_delayed_when(s, thandle, on));

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_set_label, EXT_API_FUN_MAAPI_SET_LABEL)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "label",
        NULL
    };

    int s;
    int thandle;
    const char *label;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&is", kwlist,sock_arg, &s, &thandle, &label)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_set_label(s, thandle, label));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_set_comment, EXT_API_FUN_MAAPI_SET_COMMENT)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "comment",
        NULL
    };

    int s;
    int thandle;
    const char *comment;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&is", kwlist,sock_arg, &s, &thandle, &comment)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_set_comment(s, thandle, comment));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_copy, EXT_API_FUN_MAAPI_COPY)
{
    static char *kwlist[] = {
        "sock",
        "from_thandle",
        "to_thandle",
        NULL
    };

    int s;
    int from_thandle;
    int to_thandle;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist, sock_arg, &s, &from_thandle, &to_thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_copy(s, from_thandle, to_thandle));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_copy_path, EXT_API_FUN_MAAPI_COPY_PATH)
{
    static char *kwlist[] = {
        "sock",
        "from_thandle",
        "to_thandle",
        "path",
        NULL
    };

    int s;
    int from_thandle;
    int to_thandle;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iiO&", kwlist,
                sock_arg, &s, &from_thandle, &to_thandle, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_copy_path(s, from_thandle, to_thandle, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_copy_tree, EXT_API_FUN_MAAPI_COPY_TREE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "frompath",
        "topath",
        NULL
    };

    int s;
    int thandle;
    const char *from;
    const char *topath;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&isO&", kwlist,
                sock_arg, &s, &thandle, &from, path_arg, &topath)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_copy_tree(s, thandle, from, topath),
            free((void *) topath));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_insert, EXT_API_FUN_MAAPI_INSERT)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",
        NULL
    };

    int s;
    int thandle;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&", kwlist,
                sock_arg, &s, &thandle, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_insert(s, thandle, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_move, EXT_API_FUN_MAAPI_MOVE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "tokey",
        "path",
        NULL
    };

    int s;
    int thandle;
    PyObject *pytokey;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOO&", kwlist,
                sock_arg, &s, &thandle, &pytokey, path_arg, &path)) {
        return NULL;
    }

    py_confd_value_t_list_t tokey = {0};
    if (!alloc_py_confd_value_t_list(pytokey, &tokey, "tokey")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_move(s, thandle, tokey.list, tokey.size, path),
            {
                free_py_confd_value_t_list(&tokey);
                free(path);
            });

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_move_ordered, EXT_API_FUN_MAAPI_MOVE_ORDERED)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "where",
        "tokey",
        "path",
        NULL
    };

    int s;
    int thandle;
    int where;
    PyObject *pytokey;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iiOO&", kwlist,
                sock_arg, &s, &thandle, &where, &pytokey, path_arg, &path)) {
        return NULL;
    }

    py_confd_value_t_list_t tokey = {0};
    if (pytokey == Py_None) {
        tokey.size = 0;
        tokey.list = NULL;
    } else {
        if (!alloc_py_confd_value_t_list(pytokey, &tokey, "tokey")) {
            return NULL;
        }
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_move_ordered(s, thandle, where, tokey.list, tokey.size, path),
            {
                free_py_confd_value_t_list(&tokey);
                free(path);
            });

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_authenticate, EXT_API_FUN_MAAPI_AUTHENTICATE)
{
    static char *kwlist[] = {
        "sock",
        "user",
        "password",
        "n",
        NULL
    };

    int s;
    const char *user;
    const char *pass;
    int n;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ssi", kwlist, sock_arg, &s, &user, &pass, &n)) {
        return NULL;
    }

    char *groups[n + 1];

    CHECK_CONFD_ERR(result = maapi_authenticate(s, user, pass, groups, n));

    int groupC = 0;
    while (groups[groupC]) {
        groupC++;
    }

    PyObject *ret = NULL;

    if (result == 0) {
        ret = PyTuple_New(2);
        if (ret != NULL) {
            PyTuple_SetItem(ret, 0, PyInt_FromLong(result));
            const char* cfd_lasterr = confd_lasterr();
            PyTuple_SetItem(ret, 1, PyString_FromString(cfd_lasterr));
        } else {
            Py_XDECREF(ret);
            ret = NULL;
        }
    } else {
        if (groupC == 0) {
            return PyInt_FromLong(result);

        } else {
            // Authenticate ok and we have groups
            ret = PyTuple_New(2);

            if (ret != NULL) {
                PyTuple_SetItem(ret, 0, PyInt_FromLong(result));

                PyObject *l = PyList_New(groupC);

                if (l) {
                    int c;
                    for (c = 0; c < groupC; c++) {
                        PyList_SetItem(l, c, PyString_FromString(groups[c]));
                        free(groups[c]);
                    }

                    PyTuple_SetItem(ret, 1, l);
                } else {
                    Py_XDECREF(ret);
                    ret = NULL;
                }
            }
        }
    }
    return ret;
}

EXT_API_FUN(_maapi_authenticate2, EXT_API_FUN_MAAPI_AUTHENTICATE2)
{
    static char *kwlist[] = {
        "sock",
        "user",
        "password",
        "src_addr",
        "src_port",
        "context",
        "prot",
        "n",
        NULL
    };

    int s;
    const char *user;
    const char *pass;
    char *src_addr = NULL;
    int src_port;
    const char *context = NULL;
    int prot = 0;
    int n;
    struct confd_ip ip;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&sssisii", kwlist, sock_arg, &s, &user,
                                     &pass, &src_addr, &src_port, &context,
                                     &prot, &n)) {
        return NULL;
    }

    char *groups[n + 1];

    ip.af = AF_INET;
    if (inet_pton(AF_INET, src_addr, &(ip.ip.v4)) != 1) {
        ip.af = AF_INET6;

        if (inet_pton(AF_INET6, src_addr, &(ip.ip.v6)) != 1) {
            PyErr_Format(PyExc_ValueError, "Invalid source address.");
            return 0;
        }
    }

    CHECK_CONFD_ERR(result = maapi_authenticate2(s, user, pass, &ip,
                                                 src_port, context, prot,
                                                 groups, n));

    int groupC = 0;
    while (groups[groupC]) {
        groupC++;
    }

    PyObject *ret = NULL;

    if (result == 0) {
        ret = PyTuple_New(2);
        if (ret != NULL) {
            PyTuple_SetItem(ret, 0, PyInt_FromLong(result));
            const char* cfd_lasterr = confd_lasterr();
            PyTuple_SetItem(ret, 1, PyString_FromString(cfd_lasterr));
        } else {
            Py_XDECREF(ret);
            ret = NULL;
        }
    } else {
        if (groupC == 0) {
            return PyInt_FromLong(result);

        } else {
            // Authenticate ok and we have groups
            ret = PyTuple_New(2);

            if (ret != NULL) {
                PyTuple_SetItem(ret, 0, PyInt_FromLong(result));

                PyObject *l = PyList_New(groupC);

                if (l) {
                    int c;
                    for (c = 0; c < groupC; c++) {
                        PyList_SetItem(l, c, PyString_FromString(groups[c]));
                        free(groups[c]);
                    }

                    PyTuple_SetItem(ret, 1, l);
                } else {
                    Py_XDECREF(ret);
                    ret = NULL;
                }
            }
        }
    }

    return ret;
}

EXT_API_FUN(_maapi_attach, EXT_API_FUN_MAAPI_ATTACH)
{
    static char *kwlist[] = {
        "sock",
        "hashed_ns",
        "ctx",
        NULL
    };

    int s;
    int hashed_ns;
    confdTransCtxRef *tctx;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO", kwlist, sock_arg, &s, &hashed_ns, &tctx)) {
        return NULL;
    }


    if (!isConfdTransCtxRef((PyObject *) tctx)) {
        PyErr_Format(PyExc_TypeError,
                     "ctx argument must be a "
                     CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_attach(s, hashed_ns, tctx->tc));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_attach2, EXT_API_FUN_MAAPI_ATTACH2)
{
    static char *kwlist[] = {
        "sock",
        "hashed_ns",
        "usid",
        "thandle",
        NULL
    };

    int s;
    int hashed_ns;
    int usid;
    int thandle;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iii", kwlist, sock_arg, &s, &hashed_ns, &usid, &thandle)) {
        return NULL;
    }


    CHECK_CONFD_ERR(maapi_attach2(s, hashed_ns, usid, thandle));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_attach_init, EXT_API_FUN_MAAPI_ATTACH_INIT)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;
    int thandle;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_attach_init(s, &thandle));

    return PyInt_FromLong(thandle);
}

EXT_API_FUN(_maapi_detach, EXT_API_FUN_MAAPI_DETACH)
{
    static char *kwlist[] = {
        "sock",
        "ctx",
        NULL
    };

    int s;
    confdTransCtxRef *tctx;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&O", kwlist, sock_arg, &s, &tctx)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *) tctx)) {
        PyErr_Format(PyExc_TypeError,
                     "ctx argument must be a "
                     CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_detach(s, tctx->tc));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_detach2, EXT_API_FUN_MAAPI_DETACH2)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        NULL
    };

    int s;
    int thandle;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &thandle)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_detach2(s, thandle));

    Py_RETURN_NONE;
}


EXT_API_FUN(_maapi_get_schema_file_path, EXT_API_FUN_MAAPI_GET_SCHEMA_FILE_PATH)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;
    char *path;
    PyObject *tmp;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_get_schema_file_path(s, &path));

    tmp = PyString_FromString(path);
    free(path);

    return tmp;
}


/* ************************************************************************* */

typedef struct {
    int pyerror;
    PyObject *iter;
} diff_iterate_iter_cb_state_t;

static enum maapi_iter_ret _maapi_diff_iterate_iter_cb(
        confd_hkeypath_t *kp_, enum maapi_iter_op op_,
        confd_value_t *oldv_, confd_value_t *newv_, void *state_)
{
    diff_iterate_iter_cb_state_t *state =
        (diff_iterate_iter_cb_state_t *) state_;

    enum maapi_iter_ret ret = ITER_STOP;

    PyObject *kp = NULL;
    PyObject *op = NULL;
    PyObject *oldv = NULL;
    PyObject *newv = NULL;

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    if ((kp = newConfdHKeypathRefNoAutoFree(kp_)) == NULL) {
        goto decref;
    }

    if ((op = PyLong_FromLong(op_)) == NULL) {
        goto decref;
    }

    if (oldv_ == NULL) {
        Py_INCREF(Py_None);
        oldv = Py_None;
    }
    else {
        if ((oldv = PyConfd_Value_New_DupTo_Py(oldv_)) == NULL)
            goto decref;
    }

    if (newv_ == NULL) {
        Py_INCREF(Py_None);
        newv = Py_None;
    }
    else {
        if (op_ == MOP_ATTR_SET) {
            /* newv_ is a 2-element array of confd_value_t [attr, value] */
            newv = PyTuple_New(2);
            PyTuple_SetItem(newv, 0, PyConfd_Value_New_DupTo_Py(&newv_[0]));
            PyTuple_SetItem(newv, 1, PyConfd_Value_New_DupTo_Py(&newv_[1]));
        }
        else if (op_ == MOP_MOVED_AFTER) {
            /* newv_ is a list of key values ending with C_NOEXISTS */
            newv = PyList_New(0);
            for (; newv_[0].type != C_NOEXISTS; newv_++) {
                PyList_Append(newv, PyConfd_Value_New_DupTo_Py(&newv_[0]));
            }
        }
        else {
            if ((newv = PyConfd_Value_New_DupTo_Py(newv_)) == NULL)
                goto decref;
        }
    }

    PyObject *pret = PyObject_CallFunctionObjArgs(state->iter,
                                kp, op, oldv, newv, NULL);

    if (pret != NULL) {
        ret = ITER_RECURSE;

        if (PyInt_Check(pret)) {
            ret = (enum maapi_iter_ret) PyLong_AsLong(pret);
        }

    } else {
        state->pyerror = 1;
        ret = ITER_STOP;
    }

decref:
    unrefConfdHKeypathRef(kp);
    Py_XDECREF(newv);
    Py_XDECREF(oldv);
    Py_XDECREF(op);
    Py_XDECREF(kp);

    PyGILState_Release(gstate);

    return ret;
}

EXT_API_FUN(_maapi_diff_iterate, EXT_API_FUN_MAAPI_DIFF_ITERATE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "iter",
        "flags",
        NULL
    };

    int s;
    int thandle;
    PyObject *iter;
    int flags;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOi", kwlist, sock_arg, &s, &thandle, &iter, &flags)) {
        return NULL;
    }

    if (!PyCallable_Check(iter)) {
        PyErr_SetString(PyExc_TypeError, "iter argument must be callable");
        return NULL;
    }

    diff_iterate_iter_cb_state_t state;
    state.pyerror = 0;
    state.iter = iter;

    CONFD_EXEC(result = maapi_diff_iterate(s, thandle,
                                _maapi_diff_iterate_iter_cb, flags, &state));

    if (state.pyerror) {
        return NULL;
    }

    CHECK_CONFD_ERR(result);
    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_keypath_diff_iterate, EXT_API_FUN_MAAPI_KEYPATH_DIFF_ITERATE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "iter",
        "flags",
        "path",
        NULL
    };

    int s;
    int thandle;
    PyObject *iter;
    int flags;
    char *path;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOiO&", kwlist,
                sock_arg, &s, &thandle, &iter, &flags, path_arg, &path)) {
        return NULL;
    }

    if (!PyCallable_Check(iter)) {
        PyErr_SetString(PyExc_TypeError, "iter argument must be callable");
        return NULL;
    }

    diff_iterate_iter_cb_state_t state;
    state.pyerror = 0;
    state.iter = iter;

    // Reusing _maapi_diff_iterate_iter_cb from _maapi_diff_iterate
    CONFD_EXEC(result = maapi_keypath_diff_iterate(s, thandle,
                                        _maapi_diff_iterate_iter_cb, flags,
                                        &state, path, NULL));

    free(path);
    if (state.pyerror) {
        return NULL;
    }

    CHECK_CONFD_ERR(result);
    Py_RETURN_NONE;
}


/* ************************************************************************* */

typedef struct {
    int pyerror;
    PyObject *iter;
} iterate_iter_cb_state_t;

static enum maapi_iter_ret _maapi_iterate_iter_cb(
        confd_hkeypath_t *kp_, confd_value_t *v_,
        confd_attr_value_t *attr_vals_, int num_attr_vals_, void *state_)
{
    iterate_iter_cb_state_t *state =
        (iterate_iter_cb_state_t *) state_;

    enum maapi_iter_ret ret = ITER_STOP;

    PyObject *kp = NULL;
    PyObject *v = NULL;
    PyObject *attr = NULL;

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();


    state->pyerror = 1;

    if ((kp = newConfdHKeypathRefNoAutoFree(kp_)) == NULL) {
        goto decref;
    }

    if (v_ == NULL) {
        Py_INCREF(Py_None);
        v = Py_None;
    }
    else {
        if ((v = PyConfd_Value_New_DupTo_Py(v_)) == NULL)
            goto decref;
    }

    if (attr_vals_ == NULL) {
        Py_INCREF(Py_None);
        attr = Py_None;
    }
    else {
        if ((attr = PyList_New(num_attr_vals_)) == NULL)
            goto decref;

        int c;
        for (c = 0; c < num_attr_vals_; c++) {
            PyObject *item = PyConfd_AttrValue_New_DupTo_Py(&attr_vals_[c]);
            PyList_SetItem(attr, c, item);
        }
    }

    state->pyerror = 0;

    PyObject *pret = PyObject_CallFunctionObjArgs(state->iter,
                                kp, v, attr, NULL);

    if (pret != NULL) {
        ret = ITER_RECURSE;

        if (PyInt_Check(pret)) {
            ret = (enum maapi_iter_ret) PyLong_AsLong(pret);
        }
    } else {
        state->pyerror = 1;
        ret = ITER_STOP;
    }

decref:
    unrefConfdHKeypathRef(kp);
    Py_XDECREF(attr);
    Py_XDECREF(v);
    Py_XDECREF(kp);

    PyGILState_Release(gstate);

    return ret;
}

EXT_API_FUN(_maapi_iterate, EXT_API_FUN_MAAPI_ITERATE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "iter",
        "flags",
        "path",
        NULL
    };

    int s;
    int thandle;
    PyObject *iter;
    int flags;
    char *path;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOiO&", kwlist,
                sock_arg, &s, &thandle, &iter, &flags, path_arg, &path)) {
        return NULL;
    }

    if (!PyCallable_Check(iter)) {
        PyErr_SetString(PyExc_TypeError, "iter argument must be callable");
        return NULL;
    }

    iterate_iter_cb_state_t state;
    state.pyerror = 0;
    state.iter = iter;

    CONFD_EXEC(result = maapi_iterate(s, thandle,
                            _maapi_iterate_iter_cb, flags, &state, path));

    free(path);

    if (state.pyerror) {
        return NULL;
    }

    CHECK_CONFD_ERR(result);
    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_get_running_db_status,
            EXT_API_FUN_MAAPI_GET_RUNNING_DB_STATUS)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_get_running_db_status(s));

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_set_running_db_status,
            EXT_API_FUN_MAAPI_SET_RUNNING_DB_STATUS)
{
    static char *kwlist[] = {
        "sock",
        "status",
        NULL
    };

    int s;
    int status;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &status)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_set_running_db_status(s, status));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_list_rollbacks, EXT_API_FUN_MAAPI_LIST_ROLLBACKS)
{
    static char *kwlist[] = {
        "sock",
        "rp_size",
        NULL
    };

    int s;
    int rp_size;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &rp_size)) {
        return NULL;
    }

    struct maapi_rollback rollbacks[rp_size];

    CHECK_CONFD_ERR(maapi_list_rollbacks(s, rollbacks, &rp_size));

    PyObject *ret;

    if ((ret = PyList_New(rp_size)) == NULL) {
        return NULL;
    }

    int c;
    for (c = 0; c < rp_size; c++) {
        PyObject *item = (PyObject *)
            PyConfd_MaapiRollback_New(&rollbacks[c]);
        PyList_SetItem(ret, c, item);
    }

    return ret;
}

EXT_API_FUN(_maapi_load_rollback, EXT_API_FUN_MAAPI_LOAD_ROLLBACK)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "rollback_num",
        NULL
    };

    int s;
    int thandle;
    int rollback_num;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist, sock_arg, &s, &thandle, &rollback_num)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_load_rollback(s, thandle, rollback_num));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_load_rollback_fixed, EXT_API_FUN_MAAPI_LOAD_ROLLBACK_FIXED)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "fixed_num",
        NULL
    };

    int s;
    int thandle;
    int fixed_num;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist, sock_arg, &s, &thandle, &fixed_num)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_load_rollback_fixed(s, thandle, fixed_num));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_request_action, EXT_API_FUN_MAAPI_REQUEST_ACTION)
{
    static char *kwlist[] = {
        "sock",
        "params",
        "hashed_ns",
        "path",
        NULL
    };

    int s;
    PyObject *pyparams;
    int hashed_ns;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&OiO&", kwlist, sock_arg, &s, &pyparams, &hashed_ns,
                path_arg, &path)) {
        return NULL;
    }

    py_confd_tag_value_t_list_t params = {0};
    if (!alloc_py_confd_tag_value_t_list(pyparams, &params, "params")) {
        return NULL;
    }

    confd_tag_value_t *values;
    int nvalues;

    CHECK_CONFD_ERR_EXEC(
            maapi_request_action(s, params.list,
                    params.size, &values, &nvalues, hashed_ns, path),
            {
                free_py_confd_tag_value_t_list(&params);
                free(path);
            });

    PyObject *ret = PyList_New(nvalues);
    int c;

    for (c = 0; c < nvalues; c++) {
        PyObject *item = PyConfd_TagValue_New(&values[c]);

        if (item != NULL) {
            PyList_SetItem(ret, c, item);
        }
    }

    if (nvalues > 0) {
        for (c = 0; c < nvalues; c++) {
            confd_free_value(CONFD_GET_TAG_VALUE(&values[c]));
        }
        free(values);
    }

    return ret;
}

EXT_API_FUN(_maapi_request_action_th, EXT_API_FUN_MAAPI_REQUEST_ACTION_TH)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "params",
        "path",
        NULL
    };

    int s;
    PyObject *pyparams;
    int thandle;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOO&", kwlist, sock_arg, &s, &thandle, &pyparams,
                path_arg, &path)) {
        return NULL;
    }

    py_confd_tag_value_t_list_t params = {0};
    if (!alloc_py_confd_tag_value_t_list(pyparams, &params, "params")) {
        return NULL;
    }

    confd_tag_value_t *values;
    int nvalues;

    CHECK_CONFD_ERR_EXEC(
            maapi_request_action_th(s, thandle, params.list, params.size,
                                    &values, &nvalues, path),
            {
                free_py_confd_tag_value_t_list(&params);
                free(path);
            });

    PyObject *ret = PyList_New(nvalues);
    int c;

    for (c = 0; c < nvalues; c++) {
        PyObject *item = PyConfd_TagValue_New(&values[c]);

        if (item != NULL) {
            PyList_SetItem(ret, c, item);
        }
    }

    if (nvalues > 0) {
        for (c = 0; c < nvalues; c++) {
            confd_free_value(CONFD_GET_TAG_VALUE(&values[c]));
        }
        free(values);
    }

    return ret;
}

EXT_API_FUN(_maapi_request_action_str_th,
            EXT_API_FUN_MAAPI_REQUEST_ACTION_STR_TH)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "cmd",
        "path",
        NULL
    };

    int s;
    int th;
    char *cmd, *path;
    char *output = NULL;

    PyObject *ret;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&isO&", kwlist,
                                     sock_arg, &s, &th, &cmd,
                                     path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_request_action_str_th(s, th, &output, cmd, path),
            free(path));

    if (output) {
        ret = PyString_FromString(output);
        free(output);
        return ret;
    } else {
        Py_RETURN_NONE;
    }
}

EXT_API_FUN(_maapi_xpath2kpath, EXT_API_FUN_MAAPI_XPATH2KPATH)
{
    static char *kwlist[] = {
        "sock",
        "xpath",
        NULL
    };

    int s;
    char *xpath;
    PyObject *ret;

    confd_hkeypath_t *hkp;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&s", kwlist,
                                     sock_arg, &s, &xpath)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_xpath2kpath(s, xpath, &hkp));

    ret = newConfdHKeypathRefAutoFree(hkp);

    return ret;
}

EXT_API_FUN(_maapi_xpath2kpath_th, EXT_API_FUN_MAAPI_XPATH2KPATH_TH)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "xpath",
        NULL
    };

    int s;
    int th;
    char *xpath;
    PyObject *ret;

    confd_hkeypath_t *hkp;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&is", kwlist,
                                     sock_arg, &s, &th, &xpath)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_xpath2kpath_th(s, th, xpath, &hkp));

    ret = newConfdHKeypathRefAutoFree(hkp);

    return ret;
}

EXT_API_FUN(_maapi_user_message, EXT_API_FUN_MAAPI_USER_MESSAGE)
{
    static char *kwlist[] = {
        "sock",
        "to",
        "message",
        "sender",
        NULL
    };

    int s;
    const char *to;
    const char *message;
    const char *sender;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&sss", kwlist,sock_arg, &s, &to, &message, &sender)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_user_message(s, to, message, sender));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_sys_message, EXT_API_FUN_MAAPI_SYS_MESSAGE)
{
    static char *kwlist[] = {
        "sock",
        "to",
        "message",
        NULL
    };

    int s;
    const char *to;
    const char *message;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ss", kwlist,sock_arg, &s, &to, &message)) {
        return NULL;
    }


    CHECK_CONFD_ERR(maapi_sys_message(s, to, message));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_prio_message, EXT_API_FUN_MAAPI_PRIO_MESSAGE)
{
    static char *kwlist[] = {
        "sock",
        "to",
        "message",
        NULL
    };

    int s;
    const char *to;
    const char *message;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ss", kwlist,sock_arg, &s, &to, &message)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_prio_message(s, to, message));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_cli_diff_cmd, EXT_API_FUN_MAAPI_CLI_DIFF_CMD)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "thandle_old",
        "flags",
        "path",
        "size",
        NULL
    };

    int s;
    int thandle;
    int thandle_old;
    int flags;
    char *path;
    int size = MAX_RES_SIZE;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iiiO&|i", kwlist,sock_arg, &s, &thandle, &thandle_old,
                &flags, path_arg, &path, &size)) {
        return NULL;
    }

    if (size <= 0) {
        PyErr_Format(PyExc_ValueError, "size must be > 0");
        return NULL;
    }


    char res[size];

    CHECK_CONFD_ERR_EXEC(
            maapi_cli_diff_cmd(s, thandle, thandle_old,
                res, size, flags, path),
            free(path));

    return PyString_FromString(res);
}

EXT_API_FUN(_maapi_cli_accounting, EXT_API_FUN_MAAPI_CLI_ACCOUNTING)
{
    static char *kwlist[] = {
        "sock",
        "user",
        "usid",
        "cmdstr",
        NULL
    };

    int s;
    const char *user;
    int usid;
    const char *cmdstr;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&sis", kwlist,sock_arg, &s, &user, &usid, &cmdstr)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_cli_accounting(s, user, usid, cmdstr));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_cli_path_cmd, EXT_API_FUN_MAAPI_CLI_PATH_CMD)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "flags",
        "path",
        "size",
        NULL
    };

    int s;
    int thandle;
    int flags;
    char *path;
    int size = MAX_RES_SIZE;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iiO&|i", kwlist,sock_arg, &s, &thandle,
                &flags, path_arg, &path, &size)) {
        return NULL;
    }

    if (size <= 0) {
        PyErr_Format(PyExc_ValueError, "size must be > 0");
        return NULL;
    }

    char res[size];

    CHECK_CONFD_ERR_EXEC(
            maapi_cli_path_cmd(s, thandle, res, size, flags, path),
            free(path));

    return PyString_FromString(res);
}

EXT_API_FUN(_maapi_cli_cmd_to_path, EXT_API_FUN_MAAPI_CLI_CMD_TO_PATH)
{
    static char *kwlist[] = {
        "sock",
        "line",
        "nsize",
        "psize",
        NULL
    };

    int s;
    const char *line;
    int nsize, psize;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&sii", kwlist,sock_arg, &s, &line, &nsize, &psize)) {
        return NULL;
    }

    if (nsize <= 0) {
        PyErr_Format(PyExc_ValueError, "nsize must be > 0");
        return NULL;
    }

    if (psize <= 0) {
        PyErr_Format(PyExc_ValueError, "psize must be > 0");
        return NULL;
    }


    char ns[nsize];
    char path[psize];

    CHECK_CONFD_ERR(maapi_cli_cmd_to_path(s, line, ns, nsize, path, psize));

    PyObject *ret = PyTuple_New(2);

    if (ret == NULL) {
        return NULL;
    }

    PyTuple_SetItem(ret, 0, PyString_FromString(ns));
    PyTuple_SetItem(ret, 1, PyString_FromString(path));

    return ret;
}

EXT_API_FUN(_maapi_cli_cmd_to_path2, EXT_API_FUN_MAAPI_CLI_CMD_TO_PATH2)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "line",
        "nsize",
        "psize",
        NULL
    };

    int s;
    int th;
    const char *line;
    int nsize, psize;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&isii", kwlist,sock_arg, &s, &th, &line, &nsize, &psize)) {
        return NULL;
    }

    if (nsize <= 0) {
        PyErr_Format(PyExc_ValueError, "nsize must be > 0");
        return NULL;
    }

    if (psize <= 0) {
        PyErr_Format(PyExc_ValueError, "psize must be > 0");
        return NULL;
    }


    char ns[nsize];
    char path[psize];

    CHECK_CONFD_ERR(
            maapi_cli_cmd_to_path2(s, th, line, ns, nsize, path, psize));

    PyObject *ret = PyTuple_New(2);

    if (ret == NULL) {
        return NULL;
    }

    PyTuple_SetItem(ret, 0, PyString_FromString(ns));
    PyTuple_SetItem(ret, 1, PyString_FromString(path));

    return ret;
}

EXT_API_FUN(_maapi_cli_write, EXT_API_FUN_MAAPI_CLI_WRITE)
{
    static char *kwlist[] = {
        "sock",
        "usess",
        "buf",
        NULL
    };

    int s;
    int usess;
    const char *buf;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&is", kwlist,sock_arg, &s, &usess, &buf)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_cli_write(s, usess, buf, (int) strlen(buf)));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_cli_cmd, EXT_API_FUN_MAAPI_CLI_CMD)
{
    static char *kwlist[] = {
        "sock",
        "usess",
        "buf",
        NULL
    };

    int s;
    int usess;
    const char *buf;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&is", kwlist,sock_arg, &s, &usess, &buf)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_cli_cmd(s, usess, buf, (int) strlen(buf)));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_cli_cmd2, EXT_API_FUN_MAAPI_CLI_CMD2)
{
    static char *kwlist[] = {
        "sock",
        "usess",
        "buf",
        "flags",
        NULL
    };

    int s;
    int usess;
    const char *buf;
    int flags;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&isi", kwlist,sock_arg, &s, &usess, &buf, &flags)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_cli_cmd2(s, usess, buf, (int) strlen(buf), flags));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_cli_cmd3, EXT_API_FUN_MAAPI_CLI_CMD3)
{
    static char *kwlist[] = {
        "sock",
        "usess",
        "buf",
        "flags",
        "unhide",
        NULL
    };

    int s;
    int usess;
    const char *buf;
    int flags;
    const char *unhide;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&isis", kwlist,sock_arg, &s, &usess, &buf, &flags, &unhide)) {
        return NULL;
    }

    CHECK_CONFD_ERR(
            maapi_cli_cmd3(s, usess, buf, (int) strlen(buf), flags,
                           unhide, (int) strlen(unhide)));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_cli_cmd4, EXT_API_FUN_MAAPI_CLI_CMD4)
{
    static char *kwlist[] = {
        "sock",
        "usess",
        "buf",
        "flags",
        "unhide",
        NULL
    };

    int s;
    int usess;
    const char *buf;
    int flags;
    PyObject *pyunhide;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&isiO", kwlist,sock_arg, &s, &usess, &buf,
                &flags, &pyunhide)) {

        return NULL;
    }

    py_string_list_t unhide = {0};
    if (! confd_py_alloc_py_string_list(pyunhide, &unhide, "unhide")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_cli_cmd4(s, usess, buf, (int) strlen(buf), flags,
                           (char **) unhide.list, unhide.size),
            confd_py_free_py_string_list(&unhide));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_cli_set, EXT_API_FUN_MAAPI_CLI_SET)
{
    static char *kwlist[] = {
        "sock",
        "usess",
        "opt",
        "value",
        NULL
    };

    int s;
    int usess;
    const char *opt;
    const char *value;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iss", kwlist,sock_arg, &s, &usess, &opt, &value)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_cli_set(s, usess, opt, value));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_cli_get, EXT_API_FUN_MAAPI_CLI_GET)
{
    static char *kwlist[] = {
        "sock",
        "usess",
        "opt",
        "size",
        NULL
    };

    int s;
    int usess;
    const char *opt;
    int size = MAX_RES_SIZE;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&is|i", kwlist,
                                     sock_arg, &s, &usess, &opt, &size)) {
        return NULL;
    } else if (size < 0) {
        PyErr_SetString(PyExc_ValueError, "size must be >= 0");
        return NULL;
    }

    char res[size];

    CHECK_CONFD_ERR(maapi_cli_get(s, usess, opt, res, size));

    return PyString_FromString(res);
}

EXT_API_FUN(_maapi_set_readonly_mode, EXT_API_FUN_MAAPI_SET_READONLY_MODE)
{
    static char *kwlist[] = {
        "sock",
        "flag",
        NULL
    };

    int s;
    int flag;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist,sock_arg, &s, &flag)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_set_readonly_mode(s, flag));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_disconnect_remote, EXT_API_FUN_MAAPI_DISCONNECT_REMOTE)
{
    static char *kwlist[] = {
        "sock",
        "address",
        NULL
    };

    int s;
    const char *address;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&s", kwlist,sock_arg, &s, &address)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_disconnect_remote(s, address));

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_disconnect_sockets, EXT_API_FUN_MAAPI_DISCONNECT_SOCKETS)
{
    static char *kwlist[] = {
        "sock",
        "sockets",
        NULL
    };

    int s;
    PyObject *pysockets;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&O", kwlist,sock_arg, &s, &pysockets)) {
        return NULL;
    }

    py_int_list_t sockets = {0};
    if (! confd_py_alloc_py_int_list(pysockets, &sockets, "sockets")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_disconnect_sockets(s, sockets.list, sockets.size),
            confd_py_free_py_int_list(&sockets));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_cli_prompt, EXT_API_FUN_MAAPI_CLI_PROMPT)
{
    static char *kwlist[] = {
        "sock",
        "usess",
        "prompt",
        "echo",
        "size",
        NULL
    };

    int s;
    int usess;
    const char *prompt;
    int echo;
    int size = MAX_RES_SIZE;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&isi|i", kwlist,
                                     sock_arg, &s, &usess, &prompt,
                                     &echo, &size)) {
        return NULL;
    } else if (size < 0) {
        PyErr_SetString(PyExc_ValueError, "size must be >= 0");
        return NULL;
    }

    char res[size];

    CHECK_CONFD_ERR(
            maapi_cli_prompt(s, usess, prompt, echo, res, size));

    return PyString_FromString(res);
}

EXT_API_FUN(_maapi_save_config, EXT_API_FUN_MAAPI_SAVE_CONFIG)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "flags",
        "path",
        NULL
    };

    int s;
    int thandle;
    int flags;
    char *path;
    int result;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iiO&", kwlist, sock_arg, &s, &thandle, &flags,
                path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            result = maapi_save_config(s, thandle, flags, path),
            free(path));

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_save_config_result, EXT_API_FUN_MAAPI_SAVE_CONFIG_RESULT)
{
    static char *kwlist[] = {
        "sock",
        "id",
        NULL
    };

    int s;
    int id;
    int result;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &id)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_save_config_result(s, id));

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_load_config, EXT_API_FUN_MAAPI_LOAD_CONFIG)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "flags",
        "filename",
        NULL
    };

    int s;
    int th;
    int flags;
    const char *filename;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iis", kwlist, sock_arg, &s, &th, &flags, &filename)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_load_config(s, th, flags, filename));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_load_config_cmds, EXT_API_FUN_MAAPI_LOAD_CONFIG_CMDS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "flags",
        "cmds",
        "path",
        NULL
    };

    int s;
    int th;
    int flags;
    const char *cmds;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iisO&", kwlist, sock_arg, &s, &th, &flags, &cmds,
                path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_load_config_cmds(s, th, flags, cmds, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_load_config_stream, EXT_API_FUN_MAAPI_LOAD_CONFIG_STREAM)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "flags",
        NULL
    };

    int s;
    int th;
    int flags;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist, sock_arg, &s, &th, &flags)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_load_config_stream(s, th, flags));

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_load_config_stream_result,
            EXT_API_FUN_MAAPI_LOAD_CONFIG_STREAM_RESULT)
{
    static char *kwlist[] = {
        "sock",
        "id",
        NULL
    };

    int s;
    int id;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &id)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_load_config_stream_result(s, id));

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_roll_config, EXT_API_FUN_MAAPI_ROLL_CONFIG)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",
        NULL
    };

    int s;
    int th;
    char *path;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&", kwlist, sock_arg, &s, &th, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            result = maapi_roll_config(s, th, path),
            free(path));

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_roll_config_result, EXT_API_FUN_MAAPI_ROLL_CONFIG_RESULT)
{
    static char *kwlist[] = {
        "sock",
        "id",
        NULL
    };

    int s;
    int id;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &id)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_roll_config_result(s, id));

    return PyInt_FromLong(result);
}


EXT_API_FUN(_maapi_get_stream_progress, EXT_API_FUN_MAAPI_GET_STREAM_PROGRESS)
{
    static char *kwlist[] = {
        "sock",
        "id",
        NULL
    };

    int s;
    int id;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &id)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_get_stream_progress(s, id));

    return PyInt_FromLong(result);
}


/* ************************************************************************* */

typedef struct {
    int pyerror;
    PyObject *result;
} _maapi_xpath_eval_result_state_t;

static int _maapi_xpath_eval_result(confd_hkeypath_t *kp_, confd_value_t *v_,
                        void *state_)
{
    int ret = ITER_STOP;

    PyObject *kp = NULL;
    PyObject *v = NULL;

    _maapi_xpath_eval_result_state_t *state =
        (_maapi_xpath_eval_result_state_t *) state_;

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    state->pyerror = 1;

    if ((kp = newConfdHKeypathRefNoAutoFree(kp_)) == NULL) {
        goto decref;
    }

    if (v_ == NULL) {
        Py_INCREF(Py_None);
        v = Py_None;
    } else {
        if ((v = PyConfd_Value_New_DupTo_Py(v_)) == NULL) {
            goto decref;
        }
    }

    state->pyerror = 0;

    PyObject *pret = PyObject_CallFunctionObjArgs(state->result,
                                kp, v, NULL);

    if (pret != NULL) {
        ret = ITER_CONTINUE;

        if (PyInt_Check(pret)) {
            ret = (enum maapi_iter_ret) PyLong_AsLong(pret);
        }

        Py_XDECREF(pret);
    } else {
        state->pyerror = 1;
        ret = ITER_STOP;
    }

decref:
    unrefConfdHKeypathRef(kp);
    Py_XDECREF(v);
    Py_XDECREF(kp);

    PyGILState_Release(gstate);

    return ret;
}

typedef struct {
    int pyerror;
    PyObject *cb_trace;
} _maapi_xpath_eval_trace_cb_t;

static _maapi_xpath_eval_trace_cb_t _maapi_xpath_eval_trace_cb = {
    0,
    0
};

static void _maapi_xpath_eval_trace(char *s)
{
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    PyObject *pys = NULL;

    if ((pys = PyString_FromString(s)) == NULL) {
        goto decref;
    }

    PyObject *pret = PyObject_CallFunctionObjArgs(
                        _maapi_xpath_eval_trace_cb.cb_trace,
                        pys, NULL);

    if (pret == NULL) {
        _maapi_xpath_eval_trace_cb.pyerror = 1;
    }

    Py_XDECREF(pret);

decref:

    Py_XDECREF(pys);
    PyGILState_Release(gstate);
}


EXT_API_FUN(_maapi_xpath_eval, EXT_API_FUN_MAAPI_XPATH_EVAL)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "expr",
        "result",
        "trace",
        "path",
        NULL
    };

    int s;
    int th;
    const char *expr;
    PyObject *pyresult;
    PyObject *pytrace;
    char *path;

    void (*trace)(char *) = NULL;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&isOOO&", kwlist,
                sock_arg, &s, &th, &expr, &pyresult,
                &pytrace, path_arg, &path)) {
        return NULL;
    }

    if (!PyCallable_Check(pyresult)) {
        PyErr_SetString(PyExc_TypeError,
                "result argument must be callable");
         return NULL;
    }

    if (pytrace != Py_None) {

        if (!PyCallable_Check(pytrace)) {
            PyErr_SetString(PyExc_TypeError,
                            "trace argument must be callable");
            return NULL;
        }

        if (_maapi_xpath_eval_trace_cb.cb_trace != NULL) {
            PyErr_SetString(PyExc_TypeError,
                    "xpath_eval callback already in use");
            return NULL;
         }

        _maapi_xpath_eval_trace_cb.pyerror = 0;
        _maapi_xpath_eval_trace_cb.cb_trace = pytrace;
        trace = _maapi_xpath_eval_trace;
    }

    _maapi_xpath_eval_result_state_t state;
    state.pyerror = 0;
    state.result = pyresult;

    CHECK_CONFD_ERR_EXEC(
            maapi_xpath_eval(s, th, expr, _maapi_xpath_eval_result,
                             trace, &state, path),
            {
                _maapi_xpath_eval_trace_cb.cb_trace = NULL;
                free(path);
            });

    if (state.pyerror) {
        return NULL;
    }

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_xpath_eval_expr, EXT_API_FUN_MAAPI_XPATH_EVAL_EXPR)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "expr",
        "trace",
        "path",
        NULL
    };

    int s;
    int th;
    const char *expr;
    PyObject *pytrace;
    char *path;

    void (*trace)(char *) = NULL;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&isOO&", kwlist,
                sock_arg, &s, &th, &expr, &pytrace, path_arg, &path)) {
        return NULL;
    }

    if (pytrace != Py_None) {

        if (!PyCallable_Check(pytrace)) {
            PyErr_SetString(PyExc_TypeError,
                    "trace argument must be callable");
            return NULL;
        }

        // Re-using xpath_eval trace callback

        if (_maapi_xpath_eval_trace_cb.cb_trace != NULL) {
            PyErr_SetString(PyExc_TypeError,
                    "xpath_eval_expr callback already in use");
            return NULL;
         }

        _maapi_xpath_eval_trace_cb.pyerror = 0;
        _maapi_xpath_eval_trace_cb.cb_trace = pytrace;

        trace = _maapi_xpath_eval_trace;
    }

    char *res = NULL;

    CHECK_CONFD_ERR_EXEC(
            maapi_xpath_eval_expr(s, th, expr, &res, trace, path),
            {
                _maapi_xpath_eval_trace_cb.cb_trace = NULL;
                free(path);
            });

    if (res == NULL) {
        PyErr_Format(PyExc_ValueError,
            "C maapi_xpath_eval_expr returned res==NULL");
        return NULL;
    } else {
        PyObject *ret = NULL;

        if (!_maapi_xpath_eval_trace_cb.pyerror) {
            ret = PyString_FromString(res);
        }

        free(res);

        return ret;
    }
}

EXT_API_FUN(_maapi_query_start, EXT_API_FUN_MAAPI_QUERY_START)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "expr",
        "context_node",
        "chunk_size",
        "initial_offset",
        "result_as",
        "select",
        "sort",
        NULL
    };

    int s;
    int th;
    const char *expr;
    const char *context_node;
    int chunk_size;
    int initial_offset;
    int result_as;
    PyObject *pyselect;
    PyObject *pysort;

    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&isziiiOO", kwlist,
                sock_arg, &s, &th,
                &expr, &context_node,
                &chunk_size, &initial_offset,
                &result_as,
                &pyselect, &pysort)) {

        return NULL;
    }

    py_string_list_t select = {0};
    if (! confd_py_alloc_py_string_list(pyselect, &select, "select")) {
        return NULL;
    }
    py_string_list_t sort = {0};
    if (! confd_py_alloc_py_string_list(pysort, &sort, "sort")) {
        confd_py_free_py_string_list(&select);
        return NULL;
    }


    CONFD_EXEC(result = maapi_query_start(s, th,
                                    expr, context_node,
                                    chunk_size, initial_offset, result_as,
                                    select.size, (const char **)select.list,
                                    sort.size, (const char **)sort.list));

    confd_py_free_py_string_list(&sort);
    confd_py_free_py_string_list(&select);

    CHECK_CONFD_ERR(result);

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_query_result, EXT_API_FUN_MAAPI_QUERY_RESULT)
{
    static char *kwlist[] = {
        "sock",
        "qh",
        NULL
    };

    int s;
    int qh;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &qh)) {
        return NULL;
    }

    struct confd_query_result *qrs;

    CHECK_CONFD_ERR(maapi_query_result(s, qh, &qrs));

    return (PyObject *) PyConfd_QueryResult_New(qrs);
}

EXT_API_FUN(_maapi_query_result_count, EXT_API_FUN_MAAPI_QUERY_RESULT_COUNT)
{
    static char *kwlist[] = {
        "sock",
        "qh",
        NULL
    };

    int s;
    int qh;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &qh)) {
        return NULL;
    }

    CHECK_CONFD_ERR(result = maapi_query_result_count(s, qh));

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_query_free_result, EXT_API_FUN_MAAPI_QUERY_FREE_RESULT)
{
    static char *kwlist[] = {
        "qrs",
        NULL
    };

    PyObject *pyqrs;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O", kwlist, &pyqrs)) {
        return NULL;
    }

    if (!PyConfd_QueryResult_CheckExact(pyqrs)) {
        PyErr_Format(PyExc_TypeError,
                "qrs argument must be a "
                CONFD_PY_MODULE ".QueryResult instance");

        return NULL;
    }

    PyConfd_QueryResult_Object *pqrs = (PyConfd_QueryResult_Object *) pyqrs;

    CHECK_CONFD_ERR_EXEC(maapi_query_free_result(pqrs->qrs),
                         pqrs->qrs = NULL);

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_query_reset_to, EXT_API_FUN_MAAPI_QUERY_RESET_TO)
{
    static char *kwlist[] = {
        "sock",
        "qh",
        "offset",
        NULL
    };

    int s;
    int qh;
    int offset;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist, sock_arg, &s, &qh, &offset)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_query_reset_to(s, qh, offset));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_query_reset, EXT_API_FUN_MAAPI_QUERY_RESET)
{
    static char *kwlist[] = {
        "sock",
        "qh",
        NULL
    };

    int s;
    int qh;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &qh)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_query_reset(s, qh));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_query_stop, EXT_API_FUN_MAAPI_QUERY_STOP)
{
    static char *kwlist[] = {
        "sock",
        "qh",
        NULL
    };

    int s;
    int qh;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &qh)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_query_stop(s, qh));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_do_display, EXT_API_FUN_MAAPI_DO_DISPLAY)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",

        NULL
    };

    int s;
    int th;
    char *path;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&", kwlist, sock_arg, &s, &th, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            result = maapi_do_display(s, th, path),
            free(path));

    return PyInt_FromLong(result);
}

EXT_API_FUN(_maapi_install_crypto_keys, EXT_API_FUN_MAAPI_INSTALL_CRYPTO_KEYS)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_install_crypto_keys(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_init_upgrade, EXT_API_FUN_MAAPI_INIT_UPGRADE)
{
    static char *kwlist[] = {
        "sock",
        "timeoutsecs",
        "flags",
        NULL
    };

    int s;
    int timeoutsecs;
    int flags;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist, sock_arg, &s, &timeoutsecs, &flags)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_init_upgrade(s, timeoutsecs, flags));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_perform_upgrade, EXT_API_FUN_MAAPI_PERFORM_UPGRADE)
{
    static char *kwlist[] = {
        "sock",
        "loadpathdirs",
        NULL
    };

    int s;
    PyObject *pyloadpathdirs;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&O", kwlist, sock_arg, &s, &pyloadpathdirs)) {
        return NULL;
    }

    py_string_list_t loadpathdirs = {0};
    if (! confd_py_alloc_py_string_list(pyloadpathdirs, &loadpathdirs,
                                        "loadpathdirs")) {
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(maapi_perform_upgrade(s,
                                               (const char**)loadpathdirs.list,
                                               loadpathdirs.size),
                         confd_py_free_py_string_list(&loadpathdirs));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_commit_upgrade, EXT_API_FUN_MAAPI_COMMIT_UPGRADE)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_commit_upgrade(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_abort_upgrade, EXT_API_FUN_MAAPI_ABORT_UPGRADE)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_abort_upgrade(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_aaa_reload, EXT_API_FUN_MAAPI_AAA_RELOAD)
{
    static char *kwlist[] = {
        "sock",
        "synchronous",
        NULL
    };

    int s;
    int synchronous;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &synchronous)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_aaa_reload(s, synchronous));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_snmpa_reload, EXT_API_FUN_MAAPI_SNMPA_RELOAD)
{
    static char *kwlist[] = {
        "sock",
        "synchronous",
        NULL
    };

    int s;
    int synchronous;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &synchronous)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_snmpa_reload(s, synchronous));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_aaa_reload_path, EXT_API_FUN_MAAPI_AAA_RELOAD_PATH)
{
    static char *kwlist[] = {
        "sock",
        "synchronous",
        "path",
        NULL
    };

    int s;
    int synchronous;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iO&", kwlist, sock_arg, &s, &synchronous, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_aaa_reload_path(s, synchronous, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_start_phase, EXT_API_FUN_MAAPI_START_PHASE)
{
    static char *kwlist[] = {
        "sock",
        "phase",
        "synchronous",
        NULL
    };

    int s;
    int phase;
    int synchronous;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist, sock_arg, &s, &phase, &synchronous)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_start_phase(s, phase, synchronous));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_wait_start, EXT_API_FUN_MAAPI_WAIT_START)
{
    static char *kwlist[] = {
        "sock",
        "phase",
        NULL
    };

    int s;
    int phase;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &phase)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_wait_start(s, phase));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_reload_config, EXT_API_FUN_MAAPI_RELOAD_CONFIG)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_reload_config(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_reopen_logs, EXT_API_FUN_MAAPI_REOPEN_LOGS)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&", kwlist, sock_arg, &s)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_reopen_logs(s));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_stop, EXT_API_FUN_MAAPI_STOP)
{
    static char *kwlist[] = {
        "sock",
        "synchronous",
        NULL
    };

    int s;
    int synchronous;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &synchronous)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_stop(s, synchronous));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_rebind_listener, EXT_API_FUN_MAAPI_REBIND_LISTENER)
{
    static char *kwlist[] = {
        "sock",
        "listener",
        NULL
    };

    int s;
    int listener;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &listener)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_rebind_listener(s, listener));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_clear_opcache, EXT_API_FUN_MAAPI_CLEAR_OPCACHE)
{
    static char *kwlist[] = {
        "sock",
        "path",
        NULL
    };

    int s;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&O&", kwlist, sock_arg, &s, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_clear_opcache(s, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_cs_node_cd, EXT_API_FUN_MAAPI_CS_NODE_CD)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "path",
        NULL };

    int s;
    int th;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&iO&", kwlist, sock_arg, &s, &th, path_arg, &path)) {
        return NULL;
    }

    struct confd_cs_node *node;
    CONFD_EXEC((node = maapi_cs_node_cd(s, th, path)));
    free(path);
    if (!node) {
        return confdPyConfdError();
    }

    return newConfdCsNode(node);
}

EXT_API_FUN(_maapi_cs_node_children, EXT_API_FUN_MAAPI_CS_NODE_CHILDREN)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "mount_point",
        "path",
        NULL
    };

    int s;
    int th;
    PyObject *mount_point;
    char *path;
    struct confd_cs_node **children;
    int num_children;
    int result;
    int i;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOO&", kwlist, sock_arg, &s, &th, &mount_point,
                path_arg, &path)) {
        return NULL;
    }

    if (!isConfdCsNode(mount_point)) {
        PyErr_Format(PyExc_TypeError,
                "mount_point argument must be a "
                CONFD_PY_MODULE ".CsNode instance");
        return NULL;
    }

    struct confd_cs_node *mp = ((confdCsNode*)mount_point)->node;

    if (!(mp->info.flags & CS_NODE_HAS_MOUNT_POINT)) {
        PyErr_Format(PyExc_TypeError,
                "mount_point argument must be a mount point");
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
        result = maapi_cs_node_children(
                    s, th, mp, &children, &num_children, path),
        free(path));
    PyObject *ret = PyList_New(num_children);

    for (i = 0; i < num_children; i++) {
        PyList_SetItem(ret, i, newConfdCsNode(children[i]));
    }

    free(children);

    return ret;
}

EXT_API_FUN(_maapi_report_progress, EXT_API_FUN_MAAPI_REPORT_PROGRESS)
{
    enum confd_progress_verbosity verbosity;
    const char *msg;
    int sock, thandle;
    static char *kwlist[] = {
        "sock",
        "thandle",
        "verbosity",
        "msg",
        NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&iis", kwlist, sock_arg, &sock,
                                     &thandle, &verbosity, &msg)) {
        return NULL;
    }
    CHECK_CONFD_ERR(maapi_report_progress(
                        sock, thandle, verbosity, msg));
    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_report_progress_start,
            EXT_API_FUN_MAAPI_REPORT_PROGRESS_START)
{
    enum confd_progress_verbosity verbosity;
    const char *msg, *package;
    int sock, thandle;
    unsigned long long ts;
    static char *kwlist[] = {
        "sock",
        "thandle",
        "verbosity",
        "msg",
        "package",
        NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&iisz", kwlist, sock_arg, &sock,
                                     &thandle, &verbosity, &msg, &package)) {
        return NULL;
    }
    CHECK_CONFD_ERR(ts = maapi_report_progress_start(
                        sock, thandle, verbosity, msg, package));
    return PyLong_FromUnsignedLongLong(ts);
}

EXT_API_FUN(_maapi_report_progress_stop, EXT_API_FUN_MAAPI_REPORT_PROGRESS_STOP)
{
    enum confd_progress_verbosity verbosity;
    const char *msg, *annotation, *package;
    unsigned long long timestamp;
    int sock, thandle;
    static char *kwlist[] = {
        "sock",
        "thandle",
        "verbosity",
        "msg",
        "annotation",
        "package",
        "timestamp",
        NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&iiszzK", kwlist, sock_arg, &sock,
                                     &thandle, &verbosity, &msg, &annotation,
                                     &package, &timestamp)) {
        return NULL;
    }
    CHECK_CONFD_ERR(maapi_report_progress_stop(
                        sock, thandle, verbosity, msg, annotation,
                        package, timestamp));
    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_netconf_ssh_call_home,
            EXT_API_FUN_MAAPI_NETCONF_SSH_CALL_HOME)
{
    static char *kwlist[] = {
        "sock",
        "host",
        "port",
        NULL
    };

    int s;
    confd_value_t host;
    char *host_str;
    int port;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&si", kwlist, sock_arg,
                                     &s, &host_str, &port)) {
        return NULL;
    }

    if (inet_pton(AF_INET, host_str, &host.val.ip) == 1) {
        host.type = C_IPV4;
    } else if (inet_pton(AF_INET6, host_str, &host.val.ip6) == 1) {
        host.type = C_IPV6;
    } else {
        CONFD_SET_STR(&host, host_str);
    }

    CHECK_CONFD_ERR(maapi_netconf_ssh_call_home(s, &host, port));

    Py_RETURN_NONE;
}


EXT_API_FUN(_maapi_netconf_ssh_call_home_opaque,
            EXT_API_FUN_MAAPI_NETCONF_SSH_CALL_HOME_OPAQUE)
{
    static char *kwlist[] = {
        "sock",
        "host",
        "opaque",
        "port",
        NULL
    };

    int s;
    confd_value_t host;
    char *host_str;
    const char *opaque;
    int port;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&ssi", kwlist, sock_arg,
                                     &s, &host_str, &opaque, &port)) {
        return NULL;
    }

    if (inet_pton(AF_INET, host_str, &host.val.ip) == 1) {
        host.type = C_IPV4;
    } else if (inet_pton(AF_INET6, host_str, &host.val.ip6) == 1) {
        host.type = C_IPV6;
    } else {
        CONFD_SET_STR(&host, host_str);
    }

    CHECK_CONFD_ERR(maapi_netconf_ssh_call_home_opaque(s,
                                                       &host,
                                                       opaque,
                                                       port));

    Py_RETURN_NONE;
}


/* Services API */
#ifdef CONFD_PY_PRODUCT_NCS


EXT_API_FUN(_maapi_shared_create, EXT_API_FUN_MAAPI_SHARED_CREATE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "flags",
        "path",
        NULL
    };

    int sock, thandle, flags;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&iiO&", kwlist, sock_arg, &sock,
                                     &thandle, &flags, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_shared_create(sock, thandle, flags, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_shared_set_elem, EXT_API_FUN_MAAPI_SHARED_SET_ELEM)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "v",
        "flags",
        "path",
        NULL
    };

    int sock, thandle, flags;
    char *path;
    PyObject *cv;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&iOiO&", kwlist,sock_arg, &sock,
                                     &thandle, &cv, &flags,
                                     path_arg, &path)) {
        return NULL;
    }

    if (PyConfd_Value_CheckExact(cv)) {
        CHECK_CONFD_ERR_EXEC(
                maapi_shared_set_elem(sock, thandle,
                    PyConfd_Value_PTR((PyConfd_Value_Object *)cv), flags, path),
                free(path));
        Py_RETURN_NONE;
    } else {
        PyErr_Format(PyExc_TypeError,
                "argument 3 must be confd.Value");
        return NULL;
    }
}

EXT_API_FUN(_maapi_shared_set_elem2, EXT_API_FUN_MAAPI_SHARED_SET_ELEM2)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "strval",
        "flags",
        "path",
        NULL
    };

    int sock, thandle, flags;
    const char *strval;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&isiO&", kwlist,sock_arg, &sock, &thandle, &strval,
                                     &flags, path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_shared_set_elem2(sock, thandle, strval, flags, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_shared_set_values, EXT_API_FUN_MAAPI_SHARED_SET_VALUES)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "values",
        "flags",
        "path",
        NULL
    };

    int s, thandle, flags;
    PyObject *pyvalues;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iOiO&", kwlist, sock_arg, &s, &thandle, &pyvalues,
                                     &flags, path_arg, &path)) {
        return NULL;
    }

    if (!PyList_Check(pyvalues)) {
        PyErr_Format(PyExc_TypeError, "values argument must be a list");
        return NULL;
    }

    int n = (int) PyList_Size(pyvalues);
    if (n == 0) {
        Py_RETURN_NONE;
    }

    confd_tag_value_t *values = mk_tagvalues_from_pylist(pyvalues, n);
    if (values == NULL) {
        return NULL; /* error */
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_shared_set_values(s, thandle, values, n, flags, path),
            {
                free(values);
                free(path);
            });

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_shared_insert, EXT_API_FUN_MAAPI_SHARED_INSERT)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "flags",
        "path",
        NULL
    };

    int sock, thandle, flags;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iiO&", kwlist, sock_arg, &sock, &thandle, &flags,
                path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_shared_insert(sock, thandle, flags, path),
            free(path));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_shared_copy_tree, EXT_API_FUN_MAAPI_SHARED_COPY_TREE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "flags",
        "frompath",
        "topath",
        NULL
    };

    int s, thandle, flags;
    const char *from;
    const char *topath;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&iisO&", kwlist,
                                     sock_arg, &s, &thandle, &flags, &from,
                                     path_arg, &topath)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_shared_copy_tree(s, thandle, flags, from, topath),
            free((void *) topath));

    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_apply_template, EXT_API_FUN_MAAPI_APPLY_TEMPLATE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "template",
        "variables",
        "flags",
        "rootpath",
        NULL
    };

    int sock, thandle, flags, ret;
    char *template;
    PyObject *rootpath;
    PyObject *variables;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&isOiO", kwlist, sock_arg, &sock,
                                     &thandle, &template, &variables,
                                     &flags, &rootpath)) {
        return NULL;
    }

    if (!PyString_Check(rootpath) && !isConfdHKeypathRef(rootpath)) {
        PyErr_Format(PyExc_TypeError,
                     "rootpath must be a string or a "
                     CONFD_PY_MODULE ".HKeypathRef instance");
        return NULL;
    }

    py_prop_list_t proplist = {0};
    if (variables != Py_None
        && ! confd_py_alloc_py_prop_list(variables, &proplist, "variables")) {
        return NULL;
    }

    if (PyString_Check(rootpath)) {
        CONFD_PY_WITH_C_STR(rootpath, crootpath) {
            CONFD_EXEC(ret = maapi_ncs_apply_template(sock, thandle,
                                                      template,
                                                      proplist.list,
                                                      proplist.size,
                                                      flags, "%s",
                                                      crootpath));
        }
    } else {
        confd_hkeypath_t *kp = ((confdHKeypathRef*)rootpath)->kp;
        CONFD_EXEC(ret = maapi_ncs_apply_template(sock, thandle,
                                                  template,
                                                  proplist.list,
                                                  proplist.size,
                                                  flags, "%h", kp));
    }

    confd_py_free_py_prop_list(&proplist);
    if (ret == CONFD_ERR) {
        return confdPyConfdError();
    } else if (ret == CONFD_EOF) {
        return confdPyEofError();
    }
    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_shared_apply_template,
            EXT_API_FUN_MAAPI_SHARED_APPLY_TEMPLATE)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "template",
        "variables",
        "flags",
        "rootpath",
        NULL
    };

    int ret, sock, thandle, flags;
    char *template;
    PyObject *rootpath;
    PyObject *variables;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&isOiO", kwlist, sock_arg, &sock,
                                     &thandle, &template, &variables,
                                     &flags, &rootpath)) {
        return NULL;
    }

    if (! PyString_Check(rootpath) && !isConfdHKeypathRef(rootpath)) {
        PyErr_Format(PyExc_TypeError,
                     "rootpath must be a string or a "
                     CONFD_PY_MODULE ".HKeypathRef instance");
        return NULL;
    }

    py_prop_list_t proplist = {0};
    if (variables != Py_None
        && ! confd_py_alloc_py_prop_list(variables, &proplist, "variables")) {
        return NULL;
    }

    if (PyString_Check(rootpath)) {
        CONFD_PY_WITH_C_STR(rootpath, crootpath) {
            CONFD_EXEC(ret = maapi_shared_ncs_apply_template(sock, thandle,
                                                             template,
                                                             proplist.list,
                                                             proplist.size,
                                                             flags, "%s",
                                                             crootpath));
        }
    } else {
        confd_hkeypath_t *kp = ((confdHKeypathRef*)rootpath)->kp;
        CONFD_EXEC(ret = maapi_shared_ncs_apply_template(sock, thandle,
                                                         template,
                                                         proplist.list,
                                                         proplist.size,
                                                         flags, "%h", kp));
    }

    confd_py_free_py_prop_list(&proplist);
    if (ret == CONFD_ERR) {
        return confdPyConfdError();
    } else if (ret == CONFD_EOF) {
        return confdPyEofError();
    }
    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_get_templates, EXT_API_FUN_MAAPI_GET_TEMPLATES)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    char **templates;
    int i, num_templates, sock;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&", kwlist, sock_arg, &sock)) {
        return NULL;
    }
    CHECK_CONFD_ERR(maapi_ncs_get_templates(sock, &templates,
                                            &num_templates));


    PyObject *ret = PyList_New(num_templates);

    for (i = 0; i < num_templates; i++) {
        PyObject *item = PyString_FromString(templates[i]);
        if (item != NULL) {
            PyList_SetItem(ret, i, item);
        }
        free(templates[i]);
    }
    free(templates);

    return ret;
}

EXT_API_FUN(_maapi_write_service_log_entry,
            EXT_API_FUN_MAAPI_WRITE_SERVICE_LOG_ENTRY)
{
    char *path, *msg;
    PyObject *ctype, *clevel;
    PyConfd_Value_Object *type, *level;
    int sock;
    static char *kwlist[] = {
        "sock",
        "path",
        "msg",
        "type",
        "level",
        NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&O&sOO", kwlist, sock_arg, &sock,
                                     path_arg, &path, &msg, &ctype, &clevel)) {
        return NULL;
    }
    if (PyConfd_Value_CheckExact(ctype)) {
        type = (PyConfd_Value_Object *)ctype;
    } else {
        PyErr_Format(PyExc_TypeError, "argument 3 must be confd.Value");
        return NULL;
    }
    if (PyConfd_Value_CheckExact(clevel)) {
        level = (PyConfd_Value_Object *)clevel;
    } else {
        PyErr_Format(PyExc_TypeError, "argument 4 must be confd.Value");
        return NULL;
    }
    CHECK_CONFD_ERR_EXEC(
            maapi_ncs_write_service_log_entry(
                        sock, msg, PyConfd_Value_PTR(type),
                        PyConfd_Value_PTR(level), path),
            free(path));
    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_report_progress2, EXT_API_FUN_MAAPI_REPORT_PROGRESS2)
{
    enum confd_progress_verbosity verbosity;
    const char *msg, *package;
    int sock, thandle;
    static char *kwlist[] = {
        "sock",
        "thandle",
        "verbosity",
        "msg",
        "package",
        NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&iiss", kwlist, sock_arg, &sock,
                                     &thandle, &verbosity, &msg, &package)) {
        return NULL;
    }
    CHECK_CONFD_ERR(maapi_report_progress2(
                        sock, thandle, verbosity, msg, package));
    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_report_service_progress,
            EXT_API_FUN_MAAPI_REPORT_SERVICE_PROGRESS)
{
    enum confd_progress_verbosity verbosity;
    char *path, *msg;
    int sock, thandle;
    static char *kwlist[] = {
        "sock",
        "thandle",
        "verbosity",
        "msg",
        "path",
        NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&iisO&", kwlist, sock_arg, &sock,
                                     &thandle, &verbosity, &msg,
                                     path_arg, &path)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_report_service_progress(
                        sock, thandle, verbosity, msg, path),
            free(path));
    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_report_service_progress2,
            EXT_API_FUN_MAAPI_REPORT_SERVICE_PROGRESS2)
{
    enum confd_progress_verbosity verbosity;
    char *path, *msg, *package;
    int sock, thandle;
    static char *kwlist[] = {
        "sock",
        "thandle",
        "verbosity",
        "msg",
        "path",
        "package",
        NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&iisO&s", kwlist, sock_arg, &sock,
                                     &thandle, &verbosity, &msg,
                                     path_arg, &path, &package)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_report_service_progress2(
                        sock, thandle, verbosity, msg, package, path),
            free(path));
    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_report_service_progress_start,
            EXT_API_FUN_MAAPI_REPORT_SERVICE_PROGRESS_START)
{
    enum confd_progress_verbosity verbosity;
    char *path, *msg, *package;
    int sock, thandle;
    unsigned long long ts;
    static char *kwlist[] = {
        "sock",
        "thandle",
        "verbosity",
        "msg",
        "path",
        "package",
        NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&iisO&s", kwlist, sock_arg, &sock,
                                     &thandle, &verbosity, &msg,
                                     path_arg, &path, &package)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            ts = maapi_report_service_progress_start(
                        sock, thandle, verbosity,
                        msg, package, path),
            free(path));
    return PyLong_FromUnsignedLongLong(ts);
}

EXT_API_FUN(_maapi_report_service_progress_stop,
            EXT_API_FUN_MAAPI_REPORT_SERVICE_PROGRESS_STOP)
{
    enum confd_progress_verbosity verbosity;
    char *path, *msg, *annotation, *package;
    unsigned long long timestamp;
    int sock, thandle;
    static char *kwlist[] = {
        "sock",
        "thandle",
        "verbosity",
        "msg",
        "annotation",
        "path",
        "package",
        "timestamp",
        NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     "O&iiszO&sK", kwlist, sock_arg, &sock,
                                     &thandle, &verbosity, &msg, &annotation,
                                     path_arg, &path, &package, &timestamp)) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            maapi_report_service_progress_stop(
                        sock, thandle, verbosity,
                        msg, annotation, package, timestamp, path),
            free(path));
    Py_RETURN_NONE;
}

EXT_API_FUN(_maapi_commit_queue_result, EXT_API_FUN_MAAPI_COMMIT_QUEUE_RESULT)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "timeout",
        NULL
    };

    int s;
    int thandle;
    int timeout;
    struct ncs_commit_queue_result reply;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&ii", kwlist,sock_arg, &s, &thandle, &timeout)) {
        return NULL;
    }

    CHECK_CONFD_ERR(maapi_commit_queue_result(s, thandle, timeout, &reply));

    PyObject *ret = PyTuple_New(2);

    if (ret == NULL) {
        return NULL;
    }

    PyTuple_SetItem(ret, 0, PyInt_FromLong(reply.queue_id));
    PyTuple_SetItem(ret, 1, PyInt_FromLong(reply.status));

    return ret;
}

EXT_API_FUN(_maapi_apply_trans_params, EXT_API_FUN_MAAPI_APPLY_TRANS_PARAMS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        "keepopen",
        "params",
        NULL
    };

    int s;
    int thandle;
    int keepopen;
    PyObject *pyparams;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&iiO", kwlist, sock_arg, &s, &thandle, &keepopen,
                                     &pyparams)) {
        return NULL;
    }

    if (!PyList_Check(pyparams)) {
        PyErr_Format(PyExc_TypeError,
                     "params argument must be a list");
        return NULL;
    }

    int n = (int) PyList_Size(pyparams);
    confd_tag_value_t params[n];

    int c;

    for (c = 0; c < n; c++) {
        PyObject *item = PyList_GetItem(pyparams, c);

        if (!PyConfd_TagValue_CheckExact(item)) {
            PyErr_Format(PyExc_TypeError,
                         "params items must be "
                         CONFD_PY_MODULE ".TagValue instances");
            return NULL;
        }

        confd_tag_value_t *tv = PyConfd_TagValue_PTR(item);

        params[c].tag = tv->tag;
        memcpy(&params[c].v, &tv->v, sizeof(confd_value_t));
    }

    confd_tag_value_t *values;
    int nvalues;

    CHECK_CONFD_ERR(maapi_ncs_apply_trans_params(s, thandle, keepopen,
                                             params, n,
                                             &values, &nvalues));

    PyObject *ret = PyList_New(nvalues);

    for (c = 0; c < nvalues; c++) {
        PyObject *item = PyConfd_TagValue_New(&values[c]);

        if (item != NULL) {
            PyList_SetItem(ret, c, item);
        }
    }

    if (nvalues > 0) {
        for (c = 0; c < nvalues; c++) {
            confd_free_value(CONFD_GET_TAG_VALUE(&values[c]));
        }
        free(values);
    }

    return ret;
}

EXT_API_FUN(_maapi_get_trans_params, EXT_API_FUN_MAAPI_GET_TRANS_PARAMS)
{
    static char *kwlist[] = {
        "sock",
        "thandle",
        NULL
    };

    int s;
    int thandle;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "O&i", kwlist, sock_arg, &s, &thandle)) {
        return NULL;
    }

    confd_tag_value_t *values;
    int nvalues;

    CHECK_CONFD_ERR(maapi_ncs_get_trans_params(s, thandle, &values, &nvalues));

    PyObject *ret = PyList_New(nvalues);
    if (nvalues > 0) {
        for (int i = 0; i < nvalues; i++) {
            PyObject *item = PyConfd_TagValue_New(&values[i]);
            if (item != NULL) {
                PyList_SetItem(ret, i, item);
            }
            confd_free_value(CONFD_GET_TAG_VALUE(&values[i]));
        }
        free(values);
    }

    return ret;
}

#endif /* CONFD_PY_PRODUCT_NCS*/

/* ************************************************************************* */
/*                                                                           */
/* ************************************************************************* */


static PyObject *not_yet_implemented(PyObject *self, PyObject *args)
{
    return PyErr_Format(ConfdError, "Function not yet implemented");
}

/* FIXME: implement these */
#define _maapi_cli_prompt_oneof not_yet_implemented
#define _maapi_cli_prompt_oneof2 not_yet_implemented
#define _maapi_cli_read_eof not_yet_implemented
#define _maapi_cli_read_eof2 not_yet_implemented

#include "../doc/src/maapi_doc.c"

#define PYMOD_ENTRY(NAME) {# NAME, (PyCFunction)_maapi_ ## NAME, \
            METH_VARARGS | METH_KEYWORDS,                        \
            _maapi_ ## NAME ## __doc__}

static PyMethodDef _maapi_Methods[] = {


    PYMOD_ENTRY(connect),

    PYMOD_ENTRY(load_schemas),
    PYMOD_ENTRY(load_schemas_list),
    PYMOD_ENTRY(close),
    PYMOD_ENTRY(start_user_session),
    PYMOD_ENTRY(start_user_session2),
    PYMOD_ENTRY(start_user_session3),
    PYMOD_ENTRY(end_user_session),
    PYMOD_ENTRY(kill_user_session),
    PYMOD_ENTRY(get_user_sessions),
    PYMOD_ENTRY(get_user_session),
    PYMOD_ENTRY(get_my_user_session_id),
    PYMOD_ENTRY(set_user_session),
    PYMOD_ENTRY(get_user_session_identification),
    PYMOD_ENTRY(get_user_session_opaque),
    PYMOD_ENTRY(get_authorization_info),

    /* database api */

    PYMOD_ENTRY(lock),
    PYMOD_ENTRY(unlock),
    PYMOD_ENTRY(is_lock_set),
    PYMOD_ENTRY(lock_partial),
    PYMOD_ENTRY(unlock_partial),
    PYMOD_ENTRY(candidate_validate),
    PYMOD_ENTRY(delete_config),
    PYMOD_ENTRY(candidate_commit),
    PYMOD_ENTRY(candidate_commit_persistent),
    PYMOD_ENTRY(candidate_commit_info),
    PYMOD_ENTRY(candidate_confirmed_commit),
    PYMOD_ENTRY(candidate_confirmed_commit_persistent),
    PYMOD_ENTRY(candidate_confirmed_commit_info),
    PYMOD_ENTRY(candidate_abort_commit),
    PYMOD_ENTRY(candidate_abort_commit_persistent),
    PYMOD_ENTRY(candidate_reset),
    PYMOD_ENTRY(confirmed_commit_in_progress),
    PYMOD_ENTRY(copy_running_to_startup),
    PYMOD_ENTRY(is_running_modified),
    PYMOD_ENTRY(is_candidate_modified),

    /* transaction api */

    PYMOD_ENTRY(start_trans),
    PYMOD_ENTRY(start_trans2),
    PYMOD_ENTRY(start_trans_flags),
    PYMOD_ENTRY(start_trans_flags2),
    PYMOD_ENTRY(start_trans_in_trans),
    PYMOD_ENTRY(finish_trans),
    PYMOD_ENTRY(validate_trans),
    PYMOD_ENTRY(prepare_trans),
    PYMOD_ENTRY(prepare_trans_flags),
    PYMOD_ENTRY(commit_trans),
    PYMOD_ENTRY(abort_trans),
    PYMOD_ENTRY(apply_trans),
    PYMOD_ENTRY(apply_trans_flags),
    PYMOD_ENTRY(get_rollback_id),

    /* read/write api towards a transaction */

    PYMOD_ENTRY(set_namespace),
    PYMOD_ENTRY(cd),
    PYMOD_ENTRY(pushd),
    PYMOD_ENTRY(popd),
    PYMOD_ENTRY(getcwd),
    PYMOD_ENTRY(getcwd_kpath),
    PYMOD_ENTRY(exists),
    PYMOD_ENTRY(num_instances),
    PYMOD_ENTRY(get_elem),
    PYMOD_ENTRY(init_cursor),
    PYMOD_ENTRY(get_next),
    PYMOD_ENTRY(find_next),
    PYMOD_ENTRY(destroy_cursor),
    PYMOD_ENTRY(set_elem),
    PYMOD_ENTRY(set_elem2),
    PYMOD_ENTRY(create),
    PYMOD_ENTRY(delete),
    PYMOD_ENTRY(get_object),
    PYMOD_ENTRY(get_objects),
    PYMOD_ENTRY(get_values),
    PYMOD_ENTRY(set_object),
    PYMOD_ENTRY(set_values),
    PYMOD_ENTRY(get_case),
    PYMOD_ENTRY(get_attrs),
    PYMOD_ENTRY(set_attr),
    PYMOD_ENTRY(delete_all),
    PYMOD_ENTRY(revert),
    PYMOD_ENTRY(set_flags),
    PYMOD_ENTRY(set_delayed_when),
    PYMOD_ENTRY(set_label),
    PYMOD_ENTRY(set_comment),

    /* miscellaneous */

    PYMOD_ENTRY(copy),
    PYMOD_ENTRY(copy_path),
    PYMOD_ENTRY(copy_tree),
    PYMOD_ENTRY(insert),
    PYMOD_ENTRY(move),
    PYMOD_ENTRY(move_ordered),
    PYMOD_ENTRY(authenticate),
    PYMOD_ENTRY(authenticate2),
    PYMOD_ENTRY(attach),
    PYMOD_ENTRY(attach2),
    PYMOD_ENTRY(attach_init),
    PYMOD_ENTRY(detach),
    PYMOD_ENTRY(detach2),
    PYMOD_ENTRY(diff_iterate),
    PYMOD_ENTRY(keypath_diff_iterate),
    PYMOD_ENTRY(iterate),
    PYMOD_ENTRY(get_running_db_status),
    PYMOD_ENTRY(set_running_db_status),
    PYMOD_ENTRY(list_rollbacks),
    PYMOD_ENTRY(load_rollback),
    PYMOD_ENTRY(load_rollback_fixed),
    PYMOD_ENTRY(request_action),
    PYMOD_ENTRY(request_action_th),
    PYMOD_ENTRY(request_action_str_th),
    PYMOD_ENTRY(xpath2kpath),
    PYMOD_ENTRY(xpath2kpath_th),
    PYMOD_ENTRY(user_message),
    PYMOD_ENTRY(sys_message),
    PYMOD_ENTRY(prio_message),
    PYMOD_ENTRY(cli_prompt),
    PYMOD_ENTRY(cli_prompt_oneof),
    PYMOD_ENTRY(cli_prompt_oneof2),
    PYMOD_ENTRY(cli_read_eof),
    PYMOD_ENTRY(cli_read_eof2),
    PYMOD_ENTRY(cli_diff_cmd),
    PYMOD_ENTRY(cli_accounting),
    PYMOD_ENTRY(cli_path_cmd),
    PYMOD_ENTRY(cli_cmd_to_path),
    PYMOD_ENTRY(cli_cmd_to_path2),
    PYMOD_ENTRY(cli_write),
    PYMOD_ENTRY(cli_cmd),
    PYMOD_ENTRY(cli_cmd2),
    PYMOD_ENTRY(cli_cmd3),
    PYMOD_ENTRY(cli_cmd4),
    PYMOD_ENTRY(cli_set),
    PYMOD_ENTRY(cli_get),
    PYMOD_ENTRY(set_readonly_mode),
    PYMOD_ENTRY(disconnect_remote),
    PYMOD_ENTRY(disconnect_sockets),
    PYMOD_ENTRY(save_config),
    PYMOD_ENTRY(save_config_result),
    PYMOD_ENTRY(load_config),
    PYMOD_ENTRY(load_config_cmds),
    PYMOD_ENTRY(load_config_stream),
    PYMOD_ENTRY(load_config_stream_result),
    PYMOD_ENTRY(roll_config),
    PYMOD_ENTRY(roll_config_result),
    PYMOD_ENTRY(get_stream_progress),
    PYMOD_ENTRY(do_display),
    PYMOD_ENTRY(install_crypto_keys),
    PYMOD_ENTRY(init_upgrade),
    PYMOD_ENTRY(perform_upgrade),
    PYMOD_ENTRY(commit_upgrade),
    PYMOD_ENTRY(abort_upgrade),
    PYMOD_ENTRY(aaa_reload),
    PYMOD_ENTRY(aaa_reload_path),
    PYMOD_ENTRY(start_phase),
    PYMOD_ENTRY(wait_start),
    PYMOD_ENTRY(reload_config),
    PYMOD_ENTRY(reopen_logs),
    PYMOD_ENTRY(stop),
    PYMOD_ENTRY(rebind_listener),
    PYMOD_ENTRY(clear_opcache),
    PYMOD_ENTRY(xpath_eval),
    PYMOD_ENTRY(xpath_eval_expr),
    PYMOD_ENTRY(query_start),
    PYMOD_ENTRY(query_result),
    PYMOD_ENTRY(query_result_count),
    PYMOD_ENTRY(query_free_result),
    PYMOD_ENTRY(query_reset_to),
    PYMOD_ENTRY(query_reset),
    PYMOD_ENTRY(query_stop),
    PYMOD_ENTRY(set_next_user_session_id),
    PYMOD_ENTRY(get_schema_file_path),
    PYMOD_ENTRY(snmpa_reload),
    PYMOD_ENTRY(cs_node_children),
    PYMOD_ENTRY(cs_node_cd),
    PYMOD_ENTRY(report_progress),
    PYMOD_ENTRY(report_progress_start),
    PYMOD_ENTRY(report_progress_stop),
    PYMOD_ENTRY(netconf_ssh_call_home),
    PYMOD_ENTRY(netconf_ssh_call_home_opaque),

#ifdef CONFD_PY_PRODUCT_NCS

    PYMOD_ENTRY(shared_create),
    PYMOD_ENTRY(shared_set_elem),
    PYMOD_ENTRY(shared_set_elem2),
    PYMOD_ENTRY(shared_set_values),
    PYMOD_ENTRY(shared_insert),
    PYMOD_ENTRY(shared_copy_tree),
    PYMOD_ENTRY(apply_template),
    PYMOD_ENTRY(shared_apply_template),
    PYMOD_ENTRY(get_templates),
    PYMOD_ENTRY(write_service_log_entry),
    PYMOD_ENTRY(report_progress2),
    PYMOD_ENTRY(report_service_progress),
    PYMOD_ENTRY(report_service_progress2),
    PYMOD_ENTRY(report_service_progress_start),
    PYMOD_ENTRY(report_service_progress_stop),
    PYMOD_ENTRY(commit_queue_result),
    PYMOD_ENTRY(apply_trans_params),
    PYMOD_ENTRY(get_trans_params),

#endif /* CONFD_PY_PRODUCT_NCS */

    {NULL, NULL, 0, NULL}
};

/* ************************************************************************ */
/* maapi_cursor representation                                              */
/* ************************************************************************ */

static void maapiCursor_dealloc(maapiCursor *self)
{
    free(self->xpath_expr);
    free(self->secondary_index);
    maapi_destroy_cursor(&self->ob_val);

    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *maapiCursor_str(maapiCursor *self)
{
    struct maapi_cursor *cur = maapiCursor_Ptr(self);
    return PyString_FromFormat("confd.maapi.Cursor : n=%d", cur->n);
}


static PyObject *maapiCursor_repr(maapiCursor *self)
{
    return maapiCursor_str(self);
}

static int maapiCursor_init(maapiCursor *self, PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
maapiCursor_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    maapiCursor *self = (maapiCursor *)PY_TP_ALLOC(type);

    if (self != NULL) {
        memset(&self->ob_val, 0, sizeof(struct maapi_cursor));
    }
    return (PyObject *)self;
}


static PyMethodDef maapiCursor_methods[] = {
    {NULL}  /* Sentinel */
};

static int setup_type_confd_maapicursor(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = maapiCursor_new },
        { .slot = Py_tp_init,        .pfunc = maapiCursor_init },
        { .slot = Py_tp_dealloc,     .pfunc = maapiCursor_dealloc },
        { .slot = Py_tp_methods,     .pfunc = maapiCursor_methods },
        { .slot = Py_tp_doc,         .pfunc = "struct maapi_cursor object" },
        { .slot = Py_tp_repr,        .pfunc = maapiCursor_repr },
        { .slot = Py_tp_str,         .pfunc = maapiCursor_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".maapi.Cursor",
        .basicsize = sizeof(maapiCursor),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    maapiCursorType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (maapiCursorType == NULL)
        return -1;
    return 0;
}

static maapiCursor *newMaapiCursor(const char *secondary_index,
                                   const char *xpath_expr)
{
    maapiCursor *self =
        (maapiCursor*) PyObject_New(maapiCursor, maapiCursorType);
    self->secondary_index = secondary_index ? strdup(secondary_index) : NULL;
    self->xpath_expr = xpath_expr ? strdup(xpath_expr) : NULL;
    return self;
}


/* ************************************************************************ */
/* Module initialization                                                    */
/* ************************************************************************ */

#define MODULE CONFD_PY_MODULE ".maapi"

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        MODULE,
        MAAPI_MODULE_DOCSTR(CONFD_PY_PRODUCT),
        0,
        _maapi_Methods,
        NULL,
        NULL,
        NULL,
        NULL
};

PyObject* init__maapi_module(void)
{
    PyObject *m = NULL;

    if ((m = PyModule_Create(&moduledef)) == NULL) {
        goto error;
    }

    init_maapi_types(m);

    /* Setup of maapi_cursor */
    if (setup_type_confd_maapicursor() < 0)
        goto error;
    PyModule_AddObject(m, "Cursor", (PyObject *)maapiCursorType);

    /* Add constants */
#define ADD_CONST(C_NAME, PY_NAME) \
    (void)PyModule_AddIntConstant(m, PY_NAME, C_NAME);

#define ADD_CONST_STR(C_NAME, PY_NAME) \
    (void)PyModule_AddStringConstant(m, PY_NAME, C_NAME);

#include "gen_add_maapi_const.c"

#undef ADD_CONST
#undef ADD_CONST_STR

    PyModule_AddStringConstant(m, "PRODUCT", CONFD_PY_PRODUCT);

error:
    if (PyErr_Occurred()) {
        PyErr_SetString(PyExc_ImportError, MODULE " : init failed");
        return NULL;
    } else {
        return m;
    }
}
