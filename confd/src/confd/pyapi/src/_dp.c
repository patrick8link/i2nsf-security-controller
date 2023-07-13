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
#include <pthread.h>

#include <confd.h>
#include "confdpy_err.h"
#include "types.h"
#include "confd_errcode.h"
#include "common.h"
#include "types.h"

/* Per deamon callback holders */
typedef struct {
    PyObject *trans_cb_ctx;
    PyObject *db_cb_ctx;
    PyObject *authorization_ctx;
    PyObject *usess_ctx;
    PyObject *trans_validate_cb;
} py_dp_daemon_extra_t;

/* Python VM global object to for confd_register_auth_cb.
 *
 * struct confd_auth_ctx lacks context information so we can only
 * have one single callback per VM
 */
static PyObject* g_db_auth_cb = NULL;
static pthread_mutex_t g_db_auth_cb_lock;


/* Python VM global object to for confd_register_error_cb.
 *
 * There is no context information in the callbacks so we only
 * have one single callback per VM
 */
static PyObject* g_error_cb = NULL;
static pthread_mutex_t g_error_cb_lock;


#define GET_DAEMON_EXTRA(_ctx) \
    (py_dp_daemon_extra_t *)_ctx->ctx->d_opaque

#define GET_TRANS_DAEMON_EXTRA(tctx) \
    (py_dp_daemon_extra_t *)tctx->dx->d_opaque

#define GET_DB_DAEMON_EXTRA(dbctx) \
    (py_dp_daemon_extra_t *) dbctx->dx->d_opaque

#define GET_AUTHORIZATION_DAEMON_EXTRA(actx) \
    (py_dp_daemon_extra_t *) actx->dx->d_opaque


static void _confd_py_trans_seterr(struct confd_trans_ctx *tctx,
                                   const char *txt)
{
    if (PyErr_Occurred() != NULL) {
        PyErr_Print();
        confd_trans_seterr(tctx, "%s", txt);
    }
}

#define IMPLEMENT_CONFD_PY_SETERR(TYPE, NAME) \
    static void _confd_py_## NAME ##_seterr_fetch(struct TYPE *NAME, \
                                                  const char *method) \
    { \
        PyObject *ptype, *pvalue, *ptraceback; \
        PyErr_Fetch(&ptype, &pvalue, &ptraceback); \
        CONFD_PY_WITH_C_STR(pvalue, errstr) { \
            if (errstr) { \
                confd_## NAME ##_seterr(NAME, "Python %s error. %s", \
                                        method, errstr); \
            } else { \
                confd_## NAME ##_seterr(NAME, "Python %s error.", \
                                        method); \
            } \
        } \
        Py_XDECREF(ptype); \
        Py_XDECREF(pvalue); \
        Py_XDECREF(ptraceback); \
    }

IMPLEMENT_CONFD_PY_SETERR(confd_trans_ctx, trans);
IMPLEMENT_CONFD_PY_SETERR(confd_user_info, action);
IMPLEMENT_CONFD_PY_SETERR(confd_auth_ctx, auth);
IMPLEMENT_CONFD_PY_SETERR(confd_db_ctx, db);
IMPLEMENT_CONFD_PY_SETERR(confd_user_info, error);

static void _confd_py_notification_seterr_fetch(
                                          struct confd_notification_ctx *nctx,
                                          const char *method)
{
    PyObject *ptype, *pvalue, *ptraceback;
    PyErr_Fetch(&ptype, &pvalue, &ptraceback);
    CONFD_PY_WITH_C_STR(pvalue, errstr_) {
        if (errstr_) {
            confd_notification_seterr(nctx, "Python %s error. %s",
                                      method, errstr_);
        } else {
            confd_notification_seterr(nctx, "Python %s error.", method);
        }
    }
    Py_XDECREF(ptype);
    Py_XDECREF(pvalue);
    Py_XDECREF(ptraceback);
}


/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_init_daemon, EXT_API_FUN_DP_INIT_DAEMON)
{
    static char *kwlist[] = {
        "name",
        NULL
    };
    char *name;
    struct confd_daemon_ctx *ctx;
    PyConfd_DaemonCtxRef_Object *pyCtx;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &name)) {
        return NULL;
    }

    if ((ctx = confd_init_daemon(name)) == NULL) {
        return confdPyConfdError();
    }

    if ((pyCtx = PyConfd_DaemonCtxRef_New(ctx)) == NULL) {
        confd_release_daemon(ctx);
        return NULL;
    }

    ctx->d_opaque = calloc(1, sizeof(py_dp_daemon_extra_t));
    if (ctx->d_opaque == NULL) {
        Py_DECREF(pyCtx);
        confd_release_daemon(ctx);
        return NULL;
    }

    return (PyObject *) pyCtx;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_release_daemon, EXT_API_FUN_DP_RELEASE_DAEMON)
{
    static char *kwlist[] = {
        "dx",
        NULL
    };
    PyConfd_DaemonCtxRef_Object *ctx;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &ctx)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    py_dp_daemon_extra_t *extra = GET_DAEMON_EXTRA(ctx);
    if (extra->trans_validate_cb != NULL) {
        Py_DECREF(extra->trans_validate_cb);
    }
    free(ctx->ctx->d_opaque);

    confd_release_daemon(ctx->ctx);

    /* Set the python object ctx to NULL so that we don't try to use
        * during tp_dealloc
        */

    ctx->ctx = NULL;

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_set_daemon_flags, EXT_API_FUN_DP_SET_DAEMON_FLAGS)
{
    static char *kwlist[] = {"dx", "flags", NULL};
    PyConfd_DaemonCtxRef_Object *ctx;
    int flags;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oi", kwlist, &ctx, &flags)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_set_daemon_flags(ctx->ctx, flags));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_connect, EXT_API_FUN_DP_CONNECT)
{
    static char *kwlist[] =
        { "dx", "sock", "type", "ip", "port", "path", NULL };
    PyObject *sock, *tmp;
    PyConfd_DaemonCtxRef_Object *ctx;
    int socketType;

    int s, family;
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
            args, kwds, "OOi|ziz", kwlist,
            &ctx, &sock, &socketType, &ipstr, &port, &pstr)) {
        return NULL;
    }


    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) ctx)) {
        PyErr_Format(PyExc_TypeError,
                "dx must be a " CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
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
            PyErr_Format(PyExc_ValueError, "invalid IP address: %s", ipstr);
            return NULL;
        }
        inaddr.sin_family = AF_INET;
        inaddr.sin_addr.s_addr = in.s_addr;
        inaddr.sin_port = htons(port);
        addr = (struct sockaddr *)&inaddr;
        addrlen = sizeof(inaddr);
    }
        break;
    case AF_INET6 : {
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
    }
        break;
    default:
        PyErr_Format(PyExc_TypeError, "unsupported socket family: %d", family);
        return NULL;
    }

    CHECK_CONFD_ERR(confd_connect(ctx->ctx, s, socketType, addr, addrlen));

    Py_RETURN_NONE;
}






/* ************************************************************************* */
/* _dp_register_trans_cb                                                     */
/* ************************************************************************* */
/*
struct confd_trans_cbs {
    int (*init)(struct confd_trans_ctx *tctx);
    int (*trans_lock)(struct confd_trans_ctx *sctx);
    int (*trans_unlock)(struct confd_trans_ctx *sctx);
    int (*write_start)(struct confd_trans_ctx *sctx);
    int (*prepare)(struct confd_trans_ctx *tctx);
    int (*abort)(struct confd_trans_ctx *tctx);
    int (*commit)(struct confd_trans_ctx *tctx);
    int (*finish)(struct confd_trans_ctx *tctx);
    void (*interrupt)(struct confd_trans_ctx *tctx);
};
*/

static int _cb_trans_generic(struct confd_trans_ctx *tctx,
                             const char *py_mth_name)
{
    int ret = CONFD_OK;
    PyObject *cbs = NULL;
    confdTransCtxRef *ctxRef = NULL;

    PyObject *cbname = NULL, *pyret = NULL;

    py_dp_daemon_extra_t *extra = GET_TRANS_DAEMON_EXTRA(tctx);

    if (extra == NULL) {
        /* Should never happen */
        confd_trans_seterr(tctx, "Internal, extra == NULL");
        return CONFD_ERR;
    }

    if (extra->trans_cb_ctx == NULL) {
        /* Should never happen */
        confd_trans_seterr(tctx,
            "Internal, extra->trans_cb_ctx == NULL");
        return CONFD_ERR;
    }

    PyGILState_STATE gstate = PyGILState_Ensure();

    ret = CONFD_ERR;
    if ((ctxRef = (confdTransCtxRef *)
                    newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((cbname = PyString_FromString(py_mth_name)) == NULL) goto decref;

    /* Don't have to incref the cbs pointer */
    cbs = extra->trans_cb_ctx;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, ctxRef, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, py_mth_name);
        ret = CONFD_ERR;
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_trans_seterr(tctx,
                           "Python %s error. Invalid return type.",
                           py_mth_name);
        ret = CONFD_ERR;
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);

    return ret;
}


static int _cb_trans_init(struct confd_trans_ctx *tctx)
{
    return _cb_trans_generic(tctx, "cb_init");
}

static int _cb_trans_trans_lock(struct confd_trans_ctx *tctx)
{
    return _cb_trans_generic(tctx, "cb_trans_lock");
}

static int _cb_trans_trans_unlock(struct confd_trans_ctx *tctx)
{
    return _cb_trans_generic(tctx, "cb_trans_unlock");
}

static int _cb_trans_write_start(struct confd_trans_ctx *tctx)
{
    return _cb_trans_generic(tctx, "cb_write_start");
}

static int _cb_trans_prepare(struct confd_trans_ctx *tctx)
{
    return _cb_trans_generic(tctx, "cb_prepare");
}

static int _cb_trans_abort(struct confd_trans_ctx *tctx)
{
    return _cb_trans_generic(tctx, "cb_abort");
}

static int _cb_trans_commit(struct confd_trans_ctx *tctx)
{
    return _cb_trans_generic(tctx, "cb_commit");
}

static int _cb_trans_finish(struct confd_trans_ctx *tctx)
{
    return _cb_trans_generic(tctx, "cb_finish");
}

static void _cb_trans_interrupt(struct confd_trans_ctx *tctx)
{
    PyObject *cbs = NULL;
    confdTransCtxRef *ctxRef = NULL;

    PyObject *cbname = NULL, *pyret = NULL;

    py_dp_daemon_extra_t *extra = GET_TRANS_DAEMON_EXTRA(tctx);

    if (extra == NULL) {
        /* Should never happen */
        confd_trans_seterr(tctx, "Internal, extra == NULL");
        return;
    }

    if (extra->trans_cb_ctx == NULL) {
        /* Should never happen */
        confd_trans_seterr(tctx,
            "Internal, extra->trans_cb_ctx == NULL");
        return;
    }

    PyGILState_STATE gstate = PyGILState_Ensure();

    if ((ctxRef = (confdTransCtxRef *)
                    newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_interrupt")) == NULL) goto decref;

    /* Don't have to incref the cbs pointer */
    cbs = extra->trans_cb_ctx;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, ctxRef, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_interrupt");
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_trans_cb, EXT_API_FUN_DP_REGISTER_TRANS_CB)
{
    static char *kwlist[] = {
        "dx",
        "trans",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;
    PyObject *cbs;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist, &ctx, &cbs)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) ctx)) {
        PyErr_Format(PyExc_TypeError,
            "dx argument must be a "
            CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    struct confd_trans_cbs trans;
    py_dp_daemon_extra_t *extra = GET_DAEMON_EXTRA(ctx);

    CHECK_CB_MTH(cbs, "cb_init", 2);

    if (extra->trans_cb_ctx != NULL) {
        PyErr_Format(PyExc_Exception,
            "Can only handle one transaction callback");
        return NULL;
    }

    memset(&trans, 0, sizeof(struct confd_trans_cbs));
    trans.init = _cb_trans_init;

    if (PyObject_HasAttrString(cbs, "cb_trans_lock")) {
        CHECK_CB_MTH(cbs, "cb_trans_lock", 2);
        trans.trans_lock = _cb_trans_trans_lock;
    }
    if (PyObject_HasAttrString(cbs, "cb_trans_unlock")) {
        CHECK_CB_MTH(cbs, "cb_trans_unlock", 2);
        trans.trans_unlock = _cb_trans_trans_unlock;
    }
    if (PyObject_HasAttrString(cbs, "cb_write_start")) {
        CHECK_CB_MTH(cbs, "cb_write_start", 2);
        trans.write_start = _cb_trans_write_start;
    }
    if (PyObject_HasAttrString(cbs, "cb_prepare")) {
        CHECK_CB_MTH(cbs, "cb_prepare", 2);
        trans.prepare = _cb_trans_prepare;
    }
    if (PyObject_HasAttrString(cbs, "cb_abort")) {
        CHECK_CB_MTH(cbs, "cb_abort", 2);
        trans.abort = _cb_trans_abort;
    }
    if (PyObject_HasAttrString(cbs, "cb_commit")) {
        CHECK_CB_MTH(cbs, "cb_commit", 2);
        trans.commit = _cb_trans_commit;
    }
    if (PyObject_HasAttrString(cbs, "cb_finish")) {
        CHECK_CB_MTH(cbs, "cb_finish", 2);
        trans.finish = _cb_trans_finish;
    }
    if (PyObject_HasAttrString(cbs, "cb_interrupt")) {
        CHECK_CB_MTH(cbs, "cb_interrupt", 2);
        trans.interrupt = _cb_trans_interrupt;
    }

    CHECK_CONFD_ERR( confd_register_trans_cb(ctx->ctx, &trans) );

    Py_INCREF(cbs);
    extra->trans_cb_ctx = cbs;

    Py_RETURN_NONE;
}

/* ************************************************************************* */
/* _dp_register_data_cb                                                      */
/* ************************************************************************* */
/*
struct confd_data_cbs {
    char callpoint[MAX_CALLPOINT_LEN];

    int (*exists_optional)(struct confd_trans_ctx *tctx,
                           confd_hkeypath_t *kp);
    int (*get_elem)(struct confd_trans_ctx *tctx,
                    confd_hkeypath_t *kp);
    int (*get_next)(struct confd_trans_ctx *tctx,
                    confd_hkeypath_t *kp, long next);
    int (*set_elem)(struct confd_trans_ctx *tctx,
                    confd_hkeypath_t *kp,
                    confd_value_t *newval);
    int (*create)(struct confd_trans_ctx *tctx,
                  confd_hkeypath_t *kp);
    int (*remove)(struct confd_trans_ctx *tctx,
                  confd_hkeypath_t *kp);

    int (*find_next)(struct confd_trans_ctx *tctx,
                     confd_hkeypath_t *kp,
                     enum confd_find_next_type type,
                     confd_value_t *keys, int nkeys);

    int (*num_instances)(struct confd_trans_ctx *tctx,
                         confd_hkeypath_t *kp);
    int (*get_object)(struct confd_trans_ctx *tctx,
                      confd_hkeypath_t *kp);
    int (*get_next_object)(struct confd_trans_ctx *tctx,
                           confd_hkeypath_t *kp, long next);
    int (*find_next_object)(struct confd_trans_ctx *tctx,
                            confd_hkeypath_t *kp,
                            enum confd_find_next_type type,
                            confd_value_t *keys, int nkeys);

    int (*get_case)(struct confd_trans_ctx *tctx,
                    confd_hkeypath_t *kp, confd_value_t *choice);
    int (*set_case)(struct confd_trans_ctx *tctx,
                    confd_hkeypath_t *kp, confd_value_t *choice,
                    confd_value_t *caseval);

    int (*get_attrs)(struct confd_trans_ctx *tctx,
                     confd_hkeypath_t *kp,
                     u_int32_t *attrs, int num_attrs);
    int (*set_attr)(struct confd_trans_ctx *tctx,
                    confd_hkeypath_t *kp,
                    u_int32_t attr, confd_value_t *v);

    int (*move_after)(struct confd_trans_ctx *tctx,
                      confd_hkeypath_t *kp, confd_value_t *prevkeys);
    int (*write_all)(struct confd_trans_ctx *tctx,
                     confd_hkeypath_t *kp);
    void *cb_opaque;
};
*/

static int _dcb_generic_cb(struct confd_trans_ctx *tctx,
                           confd_hkeypath_t *kp,
                           const char *py_mth_name)
{
    PyObject* cbs = (PyObject *) tctx->cb_opaque;
    PyObject *ctxref = NULL;
    PyObject *kpref = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((ctxref = newConfdTransCtxRef(tctx)) == NULL) goto decref;

    if (kp) {
        if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) {
            goto decref;
        }
    }
    else {
        Py_INCREF(Py_None);
        kpref = Py_None;
    }

    if ((cbname = PyString_FromString(py_mth_name)) == NULL) goto decref;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, ctxref, kpref, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, py_mth_name);
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx, "Python %s invalid return type",
                               py_mth_name);
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxref);

    PyGILState_Release(gstate);

    return ret;
}

static int _dcb_exists_optional_cb(struct confd_trans_ctx *tctx,
                                   confd_hkeypath_t *kp)
{
    return _dcb_generic_cb(tctx, kp, "cb_exists_optional");
}

static int _dcb_get_elem_cb(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    return _dcb_generic_cb(tctx, kp, "cb_get_elem");
}

static int _dcb_create_cb(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    return _dcb_generic_cb(tctx, kp, "cb_create");
}

static int _dcb_remove_cb(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    return _dcb_generic_cb(tctx, kp, "cb_remove");
}

static int _dcb_num_instances_cb(struct confd_trans_ctx *tctx,
                                 confd_hkeypath_t *kp)
{
    return _dcb_generic_cb(tctx, kp, "cb_num_instances");
}

static int _dcb_get_object_cb(struct confd_trans_ctx *tctx,
                              confd_hkeypath_t *kp)
{
    return _dcb_generic_cb(tctx, kp, "cb_get_object");
}

static int _dcb_write_all_cb(struct confd_trans_ctx *tctx,
                             confd_hkeypath_t *kp)
{
    return _dcb_generic_cb(tctx, kp, "cb_write_all");
}

static int _dcb_get_next_cb(struct confd_trans_ctx *tctx,
                         confd_hkeypath_t *kp,
                         long next)
{
    PyObject* cbs = (PyObject *) tctx->cb_opaque;
    PyObject *ctxref = NULL;
    PyObject *kpref = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;
    PyObject *pynext = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((ctxref = newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_get_next")) == NULL) goto decref;
    if ((pynext = PyLong_FromLong(next)) == NULL) goto decref;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxref, kpref, pynext, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_get_next");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx, "Python cb_get_next invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxref);
    Py_XDECREF(pynext);

    PyGILState_Release(gstate);

    return ret;
}

static int _dcb_set_elem_cb(struct confd_trans_ctx *tctx,
                            confd_hkeypath_t *kp,
                            confd_value_t *newval)
{
    PyObject* cbs = (PyObject *) tctx->cb_opaque;
    PyObject *ctxref = NULL;
    PyObject *kpref = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;
    PyConfd_Value_Object *pyval = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((ctxref = newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_set_elem")) == NULL) goto decref;
    if ((pyval = PyConfd_Value_New_DupTo(newval)) == NULL) goto decref;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxref, kpref, pyval, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_set_elem");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx, "Python cb_set_elem invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxref);
    Py_XDECREF(pyval);

    PyGILState_Release(gstate);

    return ret;
}

static int _dcb_find_next_cb(struct confd_trans_ctx *tctx,
                            confd_hkeypath_t *kp,
                            enum confd_find_next_type type,
                            confd_value_t *keys, int nkeys)
{
    PyObject* cbs = (PyObject *) tctx->cb_opaque;
    PyObject *ctxref = NULL;
    PyObject *kpref = NULL;
    PyObject *cbname = NULL;
    PyObject *pytype = NULL;
    PyObject *pykeys = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((ctxref = newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_find_next")) == NULL) goto decref;
    if ((pytype = PyInt_FromLong(type)) == NULL) goto decref;
    if ((pykeys = PyConfd_Values_New_DupTo_PyList(keys, nkeys)) == NULL)
        goto decref;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxref, kpref, pytype, pykeys, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_find_next");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx, "Python cb_find_next invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxref);
    Py_XDECREF(pytype);
    Py_XDECREF(pykeys);

    PyGILState_Release(gstate);

    return ret;
}

static int _dcb_get_next_object_cb(struct confd_trans_ctx *tctx,
                                   confd_hkeypath_t *kp, long next)
{
    PyObject* cbs = (PyObject *) tctx->cb_opaque;
    PyObject *ctxref = NULL;
    PyObject *kpref = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;
    PyObject *pynext = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((ctxref = newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_get_next_object")) == NULL)
        goto decref;
    if ((pynext = PyLong_FromLong(next)) == NULL) goto decref;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxref, kpref, pynext, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_get_next_object");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx, "Python cb_get_next_object "
                                     "invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxref);
    Py_XDECREF(pynext);

    PyGILState_Release(gstate);

    return ret;
}

static int _dcb_find_next_object_cb(struct confd_trans_ctx *tctx,
                                    confd_hkeypath_t *kp,
                                    enum confd_find_next_type type,
                                    confd_value_t *keys, int nkeys)
{
    PyObject* cbs = (PyObject *) tctx->cb_opaque;
    PyObject *ctxref = NULL;
    PyObject *kpref = NULL;
    PyObject *cbname = NULL;
    PyObject *pytype = NULL;
    PyObject *pykeys = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((ctxref = newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_find_next_object")) == NULL)
        goto decref;
    if ((pytype = PyInt_FromLong(type)) == NULL) goto decref;
    if ((pykeys = PyConfd_Values_New_DupTo_PyList(keys, nkeys)) == NULL)
        goto decref;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxref, kpref, pytype, pykeys, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_find_next_object");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx, "Python cb_find_next_object "
                                     "invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxref);
    Py_XDECREF(pytype);
    Py_XDECREF(pykeys);

    PyGILState_Release(gstate);

    return ret;
}

static int _dcb_get_case_cb(struct confd_trans_ctx *tctx,
                            confd_hkeypath_t *kp, confd_value_t *choice)
{
    PyObject* cbs = (PyObject *) tctx->cb_opaque;
    PyObject *ctxref = NULL;
    PyObject *kpref = NULL;
    PyObject *cbname = NULL;
    PyObject *pychoice = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((ctxref = newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_get_case")) == NULL)
        goto decref;
    if ((pychoice = PyConfd_Value_New_DupTo_Py(choice)) == NULL)
        goto decref;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxref, kpref, pychoice, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_get_case");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx, "Python cb_get_case invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxref);
    Py_XDECREF(pychoice);

    PyGILState_Release(gstate);

    return ret;
}

static int _dcb_set_case_cb(struct confd_trans_ctx *tctx,
                            confd_hkeypath_t *kp, confd_value_t *choice,
                            confd_value_t *caseval)
{
    PyObject* cbs = (PyObject *) tctx->cb_opaque;
    PyObject *ctxref = NULL;
    PyObject *kpref = NULL;
    PyObject *cbname = NULL;
    PyObject *pychoice = NULL;
    PyObject *pycaseval = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((ctxref = newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_set_case")) == NULL) goto decref;
    if ((pychoice = PyConfd_Value_New_DupTo_Py(choice)) == NULL) goto decref;
    if ((pycaseval = PyConfd_Value_New_DupTo_Py(caseval)) == NULL) goto decref;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxref, kpref, pychoice, pycaseval, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_set_case");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx, "Python cb_set_case invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxref);
    Py_XDECREF(pychoice);
    Py_XDECREF(pycaseval);

    PyGILState_Release(gstate);

    return ret;
}

static int _dcb_get_attrs_cb(struct confd_trans_ctx *tctx,
                             confd_hkeypath_t *kp,
                             u_int32_t *attrs, int num_attrs)
{
    PyObject* cbs = (PyObject *) tctx->cb_opaque;
    PyObject *ctxref = NULL;
    PyObject *kpref = NULL;
    PyObject *cbname = NULL;
    PyObject *pyattrs = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((ctxref = newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_get_attrs")) == NULL) goto decref;
    if ((pyattrs = PyList_New(num_attrs)) == NULL) goto decref;

    Py_ssize_t i;
    for (i = 0; i < num_attrs; i++) {
        PyList_SetItem(pyattrs, i, PyLong_FromLong(attrs[i]));
    }

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxref, kpref, pyattrs, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_get_attrs");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx, "Python cb_get_attrs invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxref);
    Py_XDECREF(pyattrs);

    PyGILState_Release(gstate);

    return ret;
}

static int _dcb_set_attr_cb(struct confd_trans_ctx *tctx,
                            confd_hkeypath_t *kp,
                            u_int32_t attr, confd_value_t *v)
{
    PyObject* cbs = (PyObject *) tctx->cb_opaque;
    PyObject *ctxref = NULL;
    PyObject *kpref = NULL;
    PyObject *cbname = NULL;
    PyObject *pyattr = NULL;
    PyObject *pyret = NULL;
    PyObject *pyvalue = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((ctxref = newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_set_attr")) == NULL) goto decref;
    if ((pyattr = PyLong_FromLong(attr)) == NULL) goto decref;
    if (v) {
        if ((pyvalue = PyConfd_Value_New_DupTo_Py(v)) == NULL) goto decref;
    } else {
        Py_INCREF(Py_None);
        pyvalue = Py_None;
    }

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxref, kpref, pyattr, pyvalue, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_set_attr");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx, "Python cb_set_attr invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxref);
    Py_XDECREF(pyattr);
    Py_XDECREF(pyvalue);

    PyGILState_Release(gstate);

    return ret;
}

static int _dcb_move_after_cb(struct confd_trans_ctx *tctx,
                              confd_hkeypath_t *kp, confd_value_t *prevkeys)
{
    PyObject* cbs = (PyObject *) tctx->cb_opaque;
    PyObject *ctxref = NULL;
    PyObject *kpref = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;
    PyObject *pyprevkeys = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((ctxref = newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_move_after")) == NULL) goto decref;

    if (prevkeys) {
        /* array of key values terminated with a value of type C_NOEXISTS */
        int len = 0, i;
        while (prevkeys[len].type != C_NOEXISTS) len++;
        pyprevkeys = PyList_New(len);
        for (i = 0; i < len; i++) {
            PyList_SetItem(pyprevkeys, i,
                           PyConfd_Value_New_DupTo_Py(&prevkeys[i]));
        }
    } else {
        Py_INCREF(Py_None);
        pyprevkeys = Py_None;
    }

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxref, kpref, pyprevkeys, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_move_after");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx,
                    "Python cb_move_after invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxref);
    Py_XDECREF(pyprevkeys);

    PyGILState_Release(gstate);

    return ret;
}

/* ------------------------------------------------------------------------- */

static void *setup_confd_data_cbs(
        struct confd_data_cbs *dcb,
        const char *callpoint,
        PyObject *cbs,
        int flags)
{
    if (strlen(callpoint) > MAX_CALLPOINT_LEN - 1) {
        PyErr_Format(PyExc_Exception,
            "callpoint argument can be at most %d characters in length",
            MAX_CALLPOINT_LEN - 1);
        return NULL;
    }

    memset(dcb, 0, sizeof(struct confd_data_cbs));
    memcpy(dcb->callpoint, callpoint, strlen(callpoint) + 1);
    dcb->flags = flags;

    if (PyObject_HasAttrString(cbs, "cb_get_elem")) {
        CHECK_CB_MTH(cbs, "cb_get_elem", 3);
        dcb->get_elem = _dcb_get_elem_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_exists_optional")) {
        CHECK_CB_MTH(cbs, "cb_exists_optional", 3);
        dcb->exists_optional = _dcb_exists_optional_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_get_next")) {
        CHECK_CB_MTH(cbs, "cb_get_next", 4);
        dcb->get_next = _dcb_get_next_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_set_elem")) {
        CHECK_CB_MTH(cbs, "cb_set_elem", 4);
        dcb->set_elem = _dcb_set_elem_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_create")) {
        CHECK_CB_MTH(cbs, "cb_create", 3);
        dcb->create = _dcb_create_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_remove")) {
        CHECK_CB_MTH(cbs, "cb_remove", 3);
        dcb->remove = _dcb_remove_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_find_next")) {
        CHECK_CB_MTH(cbs, "cb_find_next", 5);
        dcb->find_next = _dcb_find_next_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_num_instances")) {
        CHECK_CB_MTH(cbs, "cb_num_instances", 3);
        dcb->num_instances = _dcb_num_instances_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_get_object")) {
        CHECK_CB_MTH(cbs, "cb_get_object", 3);
        dcb->get_object = _dcb_get_object_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_get_next_object")) {
        CHECK_CB_MTH(cbs, "cb_get_next_object", 4);
        dcb->get_next_object = _dcb_get_next_object_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_find_next_object")) {
        CHECK_CB_MTH(cbs, "cb_find_next_object", 5);
        dcb->find_next_object = _dcb_find_next_object_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_get_case")) {
        CHECK_CB_MTH(cbs, "cb_get_case", 4);
        dcb->get_case = _dcb_get_case_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_set_case")) {
        CHECK_CB_MTH(cbs, "cb_set_case", 5);
        dcb->set_case = _dcb_set_case_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_get_attrs")) {
        CHECK_CB_MTH(cbs, "cb_get_attrs", 4);
        dcb->get_attrs = _dcb_get_attrs_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_set_attr")) {
        CHECK_CB_MTH(cbs, "cb_set_attr", 5);
        dcb->set_attr = _dcb_set_attr_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_move_after")) {
        CHECK_CB_MTH(cbs, "cb_move_after", 4);
        dcb->move_after = _dcb_move_after_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_write_all")) {
        CHECK_CB_MTH(cbs, "cb_write_all", 3);
        dcb->write_all = _dcb_write_all_cb;
    }

    dcb->cb_opaque = (void*) cbs;

    return (void*)1;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_data_cb, EXT_API_FUN_DP_REGISTER_DATA_CB)
{
    static char *kwlist[] = {
        "dx",
        "callpoint",
        "data",
        "flags",
        NULL
    };
    PyConfd_DaemonCtxRef_Object *ctx;
    char *cpName;
    int flags = 0;

    PyObject *cbs;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OsO|i", kwlist,
                                     &ctx, &cpName, &cbs, &flags)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) ctx)) {
        PyErr_Format(PyExc_TypeError,
            "dx argument must be a " CONFD_PY_MODULE ".dp.DaemonCtxRef");
        return NULL;
    }

    struct confd_data_cbs dcb;

    if (setup_confd_data_cbs(&dcb, cpName, cbs, flags) == NULL) {
        return NULL;
    }

    CHECK_CONFD_ERR(confd_register_data_cb(ctx->ctx, &dcb) );

    Py_INCREF(cbs);

    Py_RETURN_NONE;
}


/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_range_data_cb, EXT_API_FUN_DP_REGISTER_RANGE_DATA_CB)
{
    static char *kwlist[] = {
        "dx",
        "callpoint",
        "data",
        "lower",
        "upper",
        "path",
        NULL
    };
    PyConfd_DaemonCtxRef_Object *ctx;
    char *cpName;
    PyObject *cbs;
    PyObject *lower;
    PyObject *upper;
    char *path;
    int flags = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OsOOOO&|i", kwlist,
                &ctx, &cpName, &cbs, &lower, &upper, path_arg, &path, &flags)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) ctx)) {
        PyErr_Format(PyExc_TypeError,
            "dx argument must be a " CONFD_PY_MODULE ".dp.DaemonCtxRef");
        return NULL;
    }

    py_confd_value_t_list_t lower_ = {0};
    py_confd_value_t_list_t upper_ = {0};
    if (PyList_Check(lower) && PyList_Check(upper)) {
        if (PyList_Size(lower) != PyList_Size(upper)) {
            PyErr_Format(PyExc_TypeError,
                         "lower and upper lists must be of the same length");
            return NULL;
        }

        alloc_py_confd_value_t_list(lower, &lower_, "lower");
        alloc_py_confd_value_t_list(upper, &upper_, "upper");
    }
    else if (lower != Py_None && upper != Py_None) {
        PyErr_Format(PyExc_TypeError,
                        "lower and upper arguments must either both be a list "
                        "of " CONFD_PY_MODULE ".Value or None");
        return NULL;
    }

    struct confd_data_cbs dcb;

    if (setup_confd_data_cbs(&dcb, cpName, cbs, flags) == NULL) {
        return NULL;
    }

    int ret;

    CONFD_EXEC(ret = confd_register_range_data_cb(
                ctx->ctx, &dcb, lower_.list, upper_.list, lower_.size, path));

    free(path);
    free_py_confd_value_t_list(&lower_);
    free_py_confd_value_t_list(&upper_);

    CHECK_CONFD_ERR(ret);

    Py_INCREF(cbs);

    Py_RETURN_NONE;
}


/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_done, EXT_API_FUN_DP_REGISTER_DONE)
{
    static char *kwlist[] = {
        "dx",
        NULL
    };
    PyConfd_DaemonCtxRef_Object *ctx;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &ctx)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) ctx)) {
        PyErr_Format(PyExc_TypeError, "argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR( confd_register_done(ctx->ctx) );
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_fd_ready, EXT_API_FUN_DP_FD_READY)
{
    static char *kwlist[] = {
        "dx",
        "sock",
        NULL
    };
    PyConfd_DaemonCtxRef_Object *ctx;
    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO&", kwlist,
                &ctx, sock_arg, &s)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) ctx)) {
        PyErr_Format(PyExc_TypeError,
            "dx argument must be a "
            CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR( confd_fd_ready(ctx->ctx, s) );
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_trans_set_fd, EXT_API_FUN_DP_TRANS_SET_FD)
{
    static char *kwlist[] = {
        "tctx",
        "sock",
        NULL
    };
    confdTransCtxRef *ctx;
    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO&", kwlist,
                &ctx, sock_arg, &s)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
            "tctx argument must be a "
            CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CONFD_EXEC(confd_trans_set_fd(ctx->tc, s));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_trans_seterr, EXT_API_FUN_DP_TRANS_SETERR)
{
    static char *kwlist[] = {
        "tctx",
        "errstr",
        NULL
    };
    confdTransCtxRef *ctx;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Os", kwlist,
                &ctx, &errstr)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
            "tctx argument must be a "
            CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CONFD_EXEC(confd_trans_seterr(ctx->tc, "%s", errstr));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_trans_seterr_extended, EXT_API_FUN_DP_TRANS_SETERR_EXTENDED)
{
    static char *kwlist[] = {
        "tctx",
        "code",
        "apptag_ns",
        "apptag_tag",
        "errstr",
        NULL
    };
    confdTransCtxRef *ctx;
    int code;
    u_int32_t apptag_ns;
    u_int32_t apptag_tag;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OiIIs", kwlist,
                &ctx, &code, &apptag_ns, &apptag_tag, &errstr)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
            "tctx argument must be a "
            CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CONFD_EXEC(confd_trans_seterr_extended(
                ctx->tc, code, apptag_ns, apptag_tag, "%s", errstr));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_trans_seterr_extended_info,
            EXT_API_FUN_DP_TRANS_SETERR_EXTENDED_INFO)
{
    static char *kwlist[] = {
        "tctx",
        "code",
        "apptag_ns",
        "apptag_tag",
        "error_info",
        "errstr",
        NULL
    };
    confdTransCtxRef *ctx;
    int code;
    u_int32_t apptag_ns;
    u_int32_t apptag_tag;
    PyObject *error_info;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OiIIOs", kwlist,
                &ctx, &code, &apptag_ns, &apptag_tag, &error_info, &errstr)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
            "tctx argument must be a "
            CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    if (!PyList_Check(error_info)) {
        PyErr_Format(PyExc_TypeError,
            "error_info argument must be a list of "
            CONFD_PY_MODULE ".TagValue instances");
        return NULL;
    }

    if (PyList_Size(error_info) < 1) {
        PyErr_Format(PyExc_TypeError,
            "Number of error_info must be at least 1");
        return NULL;
    }

    py_confd_tag_value_t_list_t tv = {0};
    if (!alloc_py_confd_tag_value_t_list(error_info, &tv, "error_info")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_trans_seterr_extended_info(
                ctx->tc, code, apptag_ns, apptag_tag,
                tv.list, tv.size, "%s", errstr),
            free_py_confd_tag_value_t_list(&tv));

    Py_RETURN_NONE;
}

/* ************************************************************************* */
/* _dp_register_trans_validate_cb                                            */
/* ************************************************************************* */

static int _dp_register_trans_validate_cb_init(struct confd_trans_ctx *tctx)
{
    py_dp_daemon_extra_t *extra = GET_TRANS_DAEMON_EXTRA(tctx);
    if (extra->trans_validate_cb == NULL) {
        confd_trans_seterr(tctx, "trans_validate_cb == NULL");
        return CONFD_ERR;
    }

    int ret = CONFD_OK;


    // Enter Python environment

    PyGILState_STATE gstate = PyGILState_Ensure();

    confdTransCtxRef *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;

    if ((ctxRef = (confdTransCtxRef *) newConfdTransCtxRef(tctx)) == NULL) {
        confd_trans_seterr(tctx,
                "_dp_register_trans_validate_cb_init : ctxRef == NULL");
        ret = CONFD_ERR;
        goto error;
    }

    if ((cbname = PyString_FromString("cb_init")) == NULL) {
        confd_trans_seterr(tctx,
                "_dp_register_trans_validate_cb_init : cbname == NULL");
         ret = CONFD_ERR;
        goto error;
    }

    pyret = PyObject_CallMethodObjArgs(extra->trans_validate_cb,
                cbname, ctxRef, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr(tctx, "_dp_register_trans_validate_cb_init");
        ret = CONFD_ERR;
    }

error:
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    // Exit Python environment
    PyGILState_Release(gstate);

    return ret;
}

static int _dp_register_trans_validate_cb_stop(struct confd_trans_ctx *tctx)
{
    py_dp_daemon_extra_t *extra = GET_TRANS_DAEMON_EXTRA(tctx);
    if (extra->trans_validate_cb == NULL) {
        confd_trans_seterr(tctx, "trans_validate_cb == NULL");
        return CONFD_ERR;
    }

    int ret = CONFD_OK;

    // Enter Python environment

    PyGILState_STATE gstate = PyGILState_Ensure();

    confdTransCtxRef *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;

    if ((ctxRef = (confdTransCtxRef *) newConfdTransCtxRef(tctx)) == NULL) {
        confd_trans_seterr(tctx,
                "_dp_register_trans_validate_cb_stop : ctxRef == NULL");
        ret = CONFD_ERR;
        goto error;
    }

    if ((cbname = PyString_FromString("cb_stop")) == NULL) {
        confd_trans_seterr(tctx,
                "_dp_register_trans_validate_cb_stop : cbname == NULL");
         ret = CONFD_ERR;
        goto error;
    }

    pyret = PyObject_CallMethodObjArgs(extra->trans_validate_cb,
                cbname, ctxRef, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr(tctx, "_dp_register_trans_validate_cb_stop");
        ret = CONFD_ERR;
    }

error:

    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    // Exit Python environment
    PyGILState_Release(gstate);

    return ret;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_trans_validate_cb,
            EXT_API_FUN_DP_REGISTER_TRANS_VALIDATE_CB)
{
    static char *kwlist[] = {
        "dx",
        "vcbs",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *dx;
    PyObject *vcbs;
    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "OO", kwlist, &dx, &vcbs)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) dx)) {
       PyErr_Format(PyExc_TypeError,
            "dx argument must be a "
            CONFD_PY_MODULE ".dp.DaemonCtxRefRef instance");

        return NULL;
    }

    CHECK_CB_MTH(vcbs, "cb_init", 2);
    CHECK_CB_MTH(vcbs, "cb_stop", 2);

    py_dp_daemon_extra_t *extra = GET_DAEMON_EXTRA(dx);
    if (extra->trans_validate_cb != NULL) {
        PyErr_Format(PyExc_RuntimeError,
            CONFD_PY_MODULE ".dp.register_trans_validate_cb "
            "already called in this Daemon");

        return NULL;
    }

    struct confd_trans_validate_cbs cbs;
    cbs.init = _dp_register_trans_validate_cb_init;
    cbs.stop = _dp_register_trans_validate_cb_stop;

    CONFD_EXEC(confd_register_trans_validate_cb(dx->ctx, &cbs));

    Py_INCREF(vcbs);
    extra->trans_validate_cb = vcbs;

    Py_RETURN_NONE;
}

/* ************************************************************************* */
/* _dp_register_valpoint_cb                                                  */
/* ************************************************************************* */

static int _dp_valpoint_validate_cb(struct confd_trans_ctx *tctx,
                    confd_hkeypath_t *keypath,
                    confd_value_t *newval)
{
    int ret = CONFD_OK;

    // Enter Python environment

    PyGILState_STATE gstate = PyGILState_Ensure();

    PyObject *ctxRef = NULL;
    PyObject *kpref = newConfdHKeypathRefNoAutoFree(keypath);

    PyConfd_Value_Object *pyNewVal = PyConfd_Value_New_DupTo(newval);

    PyObject *pyret = NULL;
    PyObject *cbname = PyString_FromString("cb_validate");

    if ((ctxRef = newConfdTransCtxRef(tctx)) == NULL) {
        confd_trans_seterr(tctx,
                "_dp_valpoint_validate_cb : ctxRef == NULL");
        ret = CONFD_ERR;
        goto error;
    }


    PyObject *callback = (PyObject *) tctx->vcb_opaque;

    pyret = PyObject_CallMethodObjArgs(callback, cbname,
                ctxRef, kpref, pyNewVal, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_validate");
        ret = CONFD_ERR;
    } else if (pyret == Py_None) {
        ret = CONFD_OK;
    } else if (PyInt_Check(pyret)) {
        ret = (int) PyInt_AsLong(pyret);
    } else {
        confd_trans_seterr(tctx, "Python cb_validate invalid return type");
        ret = CONFD_ERR;
    }

error:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(cbname);
    Py_XDECREF(pyNewVal);
    Py_XDECREF(kpref);
    Py_XDECREF(ctxRef);

    // Exit Python environment
    PyGILState_Release(gstate);

    return ret;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_valpoint_cb, EXT_API_FUN_DP_REGISTER_VALPOINT_CB)
{
    static char *kwlist[] = {
        "dx",
        "valpoint",
        "vcb",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *dx;
    const char *valpoint;
    PyObject *callback;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "OsO", kwlist, &dx, &valpoint, &callback)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) dx)) {
       PyErr_Format(PyExc_TypeError,
            "dx argument must be a "
            CONFD_PY_MODULE ".dp.DaemonCtxRefRef instance");

        return NULL;
    }

    if (strlen(valpoint) > (MAX_CALLPOINT_LEN - 1)) {
       PyErr_Format(PyExc_TypeError,
            "valpoint length > (MAX_CALLPOINT_LEN - 1)");

        return NULL;
    }

    CHECK_CB_MTH(callback, "cb_validate", 4);

    struct confd_valpoint_cb vcb;
    int result;

    memcpy(vcb.valpoint, valpoint, strlen(valpoint) + 1);
    vcb.validate = _dp_valpoint_validate_cb;
    vcb.cb_opaque = (void *) callback;

    CHECK_CONFD_ERR(result = confd_register_valpoint_cb(dx->ctx, &vcb));

    Py_INCREF(callback);

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_range_valpoint_cb,
            EXT_API_FUN_DP_REGISTER_RANGE_VALPOINT_CB)
{
    static char *kwlist[] = {
        "dx",
        "valpoint",
        "vcb",
        "lower",
        "upper",
        "path",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *dx;
    const char *valpoint;
    PyObject *callback;
    PyObject *lower;
    PyObject *upper;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OsOOOO&", kwlist,
                &dx, &valpoint, &callback, &lower, &upper, path_arg, &path)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) dx)) {
       PyErr_Format(PyExc_TypeError,
            "dx argument must be a "
            CONFD_PY_MODULE ".dp.DaemonCtxRefRef instance");

        return NULL;
    }

    if (strlen(valpoint) > (MAX_CALLPOINT_LEN - 1)) {
       PyErr_Format(PyExc_TypeError,
            "valpoint length > (MAX_CALLPOINT_LEN - 1)");

        return NULL;
    }

    py_confd_value_t_list_t lower_ = {0};
    py_confd_value_t_list_t upper_ = {0};
    if (PyList_Check(lower) && PyList_Check(upper)) {
        if (PyList_Size(lower) != PyList_Size(upper)) {
            PyErr_Format(PyExc_TypeError,
                         "lower and upper lists must be of the same length");
            return NULL;
        }

        alloc_py_confd_value_t_list(lower, &lower_, "lower");
        alloc_py_confd_value_t_list(upper, &upper_, "upper");
    }
    else if (lower != Py_None && upper != Py_None) {
        PyErr_Format(PyExc_TypeError,
                        "lower and upper arguments must either both be a list "
                        "of " CONFD_PY_MODULE ".Value or None");
        return NULL;
    }

    CHECK_CB_MTH(callback, "cb_validate", 4);

    struct confd_valpoint_cb vcb;

    memcpy(vcb.valpoint, valpoint, strlen(valpoint) + 1);
    vcb.validate = _dp_valpoint_validate_cb;
    vcb.cb_opaque = (void *) callback;

    int ret;
    CONFD_EXEC(ret = confd_register_range_valpoint_cb(
                dx->ctx, &vcb, lower_.list, upper_.list, lower_.size, path));

    free((void *) path);
    free_py_confd_value_t_list(&lower_);
    free_py_confd_value_t_list(&upper_);

    CHECK_CONFD_ERR(ret);

    Py_INCREF(callback);

    Py_RETURN_NONE;
}


/* ************************************************************************* */
/*
  struct confd_action_cbs {
      char actionpoint[MAX_CALLPOINT_LEN];
      int (*init)(struct confd_user_info *uinfo);
      int (*abort)(struct confd_user_info *uinfo);
      int (*action)(struct confd_user_info *uinfo,
                    struct xml_tag *name,
                    confd_hkeypath_t *kp,
                    confd_tag_value_t *params,
                    int nparams);
      int (*command)(struct confd_user_info *uinfo,
                     char *path, int argc, char **argv);
      int (*completion)(struct confd_user_info *uinfo,
                        int cli_style, char *token, int completion_char,
                        confd_hkeypath_t *kp,
                        char *cmdpath, char *cmdparam_id,
                        struct confd_qname *simpleType, char *extra);
      void *cb_opaque;
  };
*/
/* ************************************************************************* */

static int _cbs_init_cb(struct confd_user_info *uinfo)
{
    PyObject* cbs = (PyObject *) uinfo->actx.cb_opaque;
    PyObject *uiref = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((uiref = newConfdUserInfo(uinfo)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_init")) == NULL) goto decref;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, uiref, NULL);

    if (pyret == NULL) {
        _confd_py_action_seterr_fetch(uinfo, "cb_init");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_action_seterr(uinfo,
                    "Python cb_init invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:

    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(uiref);

    PyGILState_Release(gstate);

    return ret;
}


static int _cbs_abort_cb(struct confd_user_info *uinfo)
{
    PyObject* cbs = (PyObject *) uinfo->actx.cb_opaque;
    PyObject *uiref = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((uiref = newConfdUserInfo(uinfo)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_abort")) == NULL) goto decref;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, uiref, NULL);

    if (pyret == NULL) {
        _confd_py_action_seterr_fetch(uinfo, "cb_abort");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_action_seterr(uinfo,
                    "Python cb_abort invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:

    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(uiref);

    PyGILState_Release(gstate);

    return ret;
}


static int _cbs_action_cb(struct confd_user_info *uinfo,
                     struct xml_tag *name,
                     confd_hkeypath_t *kp,
                     confd_tag_value_t *params,
                     int n)
{
    PyObject* cbs = (PyObject *) uinfo->actx.cb_opaque;
    PyObject *uiref = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;
    PyObject *pyname = NULL;
    PyObject *kpref = NULL;
    PyObject *pyparams = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((uiref = newConfdUserInfo(uinfo)) == NULL) goto decref;
    if ((pyname = PyConfd_XmlTag_New(name)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_action")) == NULL) goto decref;
    if ((pyparams = PyList_New(n)) == NULL) goto decref;

    int c;
    for (c = 0; c < n; c++) {
        confd_tag_value_t *tv = &params[c];
        PyObject* item = PyConfd_TagValue_New(tv);

        if (item) {
            PyList_SetItem(pyparams, c , item);
        }
    }

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, uiref, pyname, kpref,
                pyparams, NULL);

    if (pyret == NULL) {
        _confd_py_action_seterr_fetch(uinfo, "cb_action");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_action_seterr(uinfo,
                    "Python cb_action invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(pyparams);
    Py_XDECREF(kpref);
    Py_XDECREF(pyname);
    Py_XDECREF(uiref);

    PyGILState_Release(gstate);

    return ret;
}


static int _cbs_command_cb(struct confd_user_info *uinfo,
                   char *path, int argc, char **argv)
{
    PyObject* cbs = (PyObject *) uinfo->actx.cb_opaque;
    PyObject *uiref = NULL;
    PyObject *pypath = NULL;
    PyObject *pyargv = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((uiref = newConfdUserInfo(uinfo)) == NULL) goto decref;
    if ((pypath = PyString_FromString(path)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_command")) == NULL) goto decref;
    if ((pyargv = PyList_New(argc)) == NULL) goto decref;

    int c;
    for (c = 0; c < argc; c++) {
        PyList_SetItem(pyargv, c, PyString_FromString(argv[c]));
    }

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, uiref, pypath, pyargv, NULL);

    if (pyret == NULL) {
        _confd_py_action_seterr_fetch(uinfo, "cb_command");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_action_seterr(uinfo,
                    "Python cb_command invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:

    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(pyargv);
    Py_XDECREF(pypath);
    Py_XDECREF(uiref);

    PyGILState_Release(gstate);

    return ret;
}

int _cbs_completion_cb(struct confd_user_info *uinfo,
                       int cli_style,
                       char *token,
                       int completion_char,
                       confd_hkeypath_t *kp,
                       char *cmdpath,
                       char *cmdparam_id,
                       struct confd_qname *simpleType,
                       char *extra)
{
    PyObject* cbs = (PyObject *) uinfo->actx.cb_opaque;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;
    PyObject *uiref = NULL;
    PyObject *pycli_style = NULL;
    PyObject *pytoken = NULL;
    PyObject *pycompletion_char = NULL;
    PyObject *kpref = NULL;
    PyObject *pycmdpath = NULL;
    PyObject *pycmdparam_id = NULL;
    PyObject *pysimpleType = NULL;
    PyObject *pyextra = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    int ret = CONFD_ERR;

    if ((cbname = PyString_FromString("cb_completion")) == NULL) goto decref;
    if ((uiref = newConfdUserInfo(uinfo)) == NULL) goto decref;
    if ((pycli_style = PyInt_FromLong(cli_style)) == NULL) goto decref;
    if ((pytoken = PyString_FromString(token)) == NULL) goto decref;
    if ((pycompletion_char = PyInt_FromLong(completion_char)) == NULL)
        goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((pycmdpath = PyString_FromString(cmdpath)) == NULL) goto decref;

    if (cmdparam_id != NULL) {
        if ((pycmdparam_id = PyString_FromString(cmdparam_id)) == NULL)
            goto decref;
    } else {
        Py_INCREF(Py_None);
        pycmdparam_id = Py_None;
    }

    if (simpleType != NULL) {
        pysimpleType = PyTuple_New(2);
        PyTuple_SetItem(pysimpleType, 0,
                        PyString_FromStringAndSize(
                            (const char *)simpleType->prefix.ptr,
                            simpleType->prefix.size));
        PyTuple_SetItem(pysimpleType, 1,
                        PyString_FromStringAndSize(
                            (const char *)simpleType->name.ptr,
                            simpleType->name.size));

    } else {
        Py_INCREF(Py_None);
        pysimpleType = Py_None;
    }

    if (pyextra != NULL) {
        if ((pyextra = PyString_FromString(extra)) == NULL) goto decref;
    } else {
        Py_INCREF(Py_None);
        pyextra = Py_None;
    }


    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, uiref, pycli_style, pytoken, pycompletion_char,
            kpref, pycmdpath, pycmdparam_id, pysimpleType, pyextra, NULL);

    if (pyret == NULL) {
        _confd_py_action_seterr_fetch(uinfo, "cb_completion");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_action_seterr(uinfo,
                    "Python cb_completion invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(cbname);
    Py_XDECREF(pyret);
    Py_XDECREF(uiref);
    Py_XDECREF(pycli_style);
    Py_XDECREF(pytoken);
    Py_XDECREF(kpref);
    Py_XDECREF(pycmdpath);
    Py_XDECREF(pycmdparam_id);
    Py_XDECREF(pysimpleType);
    Py_XDECREF(pyextra);

    PyGILState_Release(gstate);

    return ret;
}


#ifdef CONFD_PY_PRODUCT_NCS
/* ************************************************************************** */
/*
enum ncs_service_operation {
    NCS_SERVICE_CREATE = 0,
    NCS_SERVICE_UPDATE = 1,
    NCS_SERVICE_DELETE = 2
};

struct ncs_service_cbs {
    char servicepoint[MAX_CALLPOINT_LEN];

    int (*pre_modification)(struct confd_trans_ctx *tctx,
                            enum ncs_service_operation op,
                            confd_hkeypath_t *kp,
                            struct ncs_name_value *proplist,
                            int num_props);
    int (*post_modification)(struct confd_trans_ctx *tctx,
                             enum ncs_service_operation op,
                             confd_hkeypath_t *kp,
                             struct ncs_name_value *proplist,
                             int num_props);
    int (*create)(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp,
                  struct ncs_name_value *proplist, int num_props,
                  int fastmap_thandle);
    void *cb_opaque;
};
*/
/* ************************************************************************** */

static int _scb_pre_modification_cb(struct confd_trans_ctx *tctx,
                             enum ncs_service_operation op,
                             confd_hkeypath_t *kp,
                             struct ncs_name_value *proplist,
                             int num_props)
{
    int ret = CONFD_OK;
    confdTransCtxRef *tctxref = NULL;
    PyObject *cbs = NULL;
    PyObject *ncs_service_operation_ref = NULL;
    PyObject *kpref = NULL;
    PyObject *pyprops = NULL;
    PyObject *pyret = NULL;
    PyObject *cbname = NULL;

    if (tctx->cb_opaque == NULL) {
        /* Should never happen */
        confd_trans_seterr(tctx, "Internal, cb_opaque == NULL");
        return CONFD_ERR;
    }

    PyGILState_STATE gstate = PyGILState_Ensure();

    ret = CONFD_ERR;

    if ((tctxref = (confdTransCtxRef *)
         newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((ncs_service_operation_ref = PyInt_FromLong(op)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((pyprops = PyList_New(num_props)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_pre_modification")) == NULL)
        goto decref;

    int c;
    for (c = 0; c < num_props; c++) {
        PyObject *item =
            Py_BuildValue("(ss)", proplist[c].name, proplist[c].value);
        if (item  == NULL)
            goto decref;
        PyList_SetItem(pyprops, c , item);
    }

    /* Don't have to incref the cbs pointer */
    cbs = tctx->cb_opaque;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname,
                                       tctxref, ncs_service_operation_ref,
                                       kpref, pyprops, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_pre_modification");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx,
                    "Python cb_pre_modification invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(tctxref);
    Py_XDECREF(kpref);
    Py_XDECREF(pyprops);
    Py_XDECREF(ncs_service_operation_ref);

    PyGILState_Release(gstate);

    return ret;
}


static int _scb_post_modification_cb(struct confd_trans_ctx *tctx,
                                     enum ncs_service_operation op,
                                     confd_hkeypath_t *kp,
                                     struct ncs_name_value *proplist,
                                     int num_props)
{
    int ret = CONFD_OK;
    confdTransCtxRef *tctxref = NULL;
    PyObject *cbs = NULL;
    PyObject *ncs_service_operation_ref = NULL;
    PyObject *kpref = NULL;
    PyObject *pyprops = NULL;
    PyObject *pyret = NULL;
    PyObject *cbname = NULL;

    if (tctx->cb_opaque == NULL) {
        /* Should never happen */
        confd_trans_seterr(tctx, "Internal, cb_opaque == NULL");
        return CONFD_ERR;
    }

    PyGILState_STATE gstate = PyGILState_Ensure();

    ret = CONFD_ERR;

    if ((tctxref = (confdTransCtxRef *)
         newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((ncs_service_operation_ref = PyInt_FromLong(op)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((pyprops = PyList_New(num_props)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_post_modification")) == NULL)
        goto decref;

    int c;
    for (c = 0; c < num_props; c++) {
        PyObject *item =
            Py_BuildValue("(ss)", proplist[c].name, proplist[c].value);
        if (item  == NULL)
            goto decref;
        PyList_SetItem(pyprops, c , item);
    }

    /* Don't have to incref the cbs pointer */
    cbs = tctx->cb_opaque;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname,
                                       tctxref, ncs_service_operation_ref,
                                       kpref, pyprops, NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_post_modification");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx,
                    "Python cb_post_modification invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(tctxref);
    Py_XDECREF(pyprops);
    Py_XDECREF(kpref);
    Py_XDECREF(ncs_service_operation_ref);

    PyGILState_Release(gstate);

    return ret;
}


static int _scb_create_cb(struct confd_trans_ctx *tctx,
                          confd_hkeypath_t *kp,
                          struct ncs_name_value *proplist,
                          int num_props,
                          int fastmap_thandle)
{
    int ret = CONFD_OK;
    confdTransCtxRef *tctxref = NULL;
    PyObject *cbs = NULL;
    PyObject *kpref = NULL;
    PyObject *pyprops = NULL;
    PyObject *pyfastmap_handle = NULL;
    PyObject *pyret = NULL;
    PyObject *cbname = NULL;

    if (tctx->cb_opaque == NULL) {
        /* Should never happen */
        confd_trans_seterr(tctx, "Internal, cb_opaque == NULL");
        return CONFD_ERR;
    }

    PyGILState_STATE gstate = PyGILState_Ensure();

    ret = CONFD_ERR;

    if ((tctxref = (confdTransCtxRef *)
         newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((pyprops = PyList_New(num_props)) == NULL) goto decref;
    if ((pyfastmap_handle = PyInt_FromLong(fastmap_thandle)) == NULL)
        goto decref;
    if ((cbname = PyString_FromString("cb_create")) == NULL) goto decref;

    int c;
    for (c = 0; c < num_props; c++) {
        PyObject *item =
            Py_BuildValue("(ss)", proplist[c].name, proplist[c].value);
        if (item  == NULL)
            goto decref;
        PyList_SetItem(pyprops, c , item);
    }

    /* Don't have to incref the cbs pointer */
    cbs = tctx->cb_opaque;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname,
                                       tctxref, kpref,
                                       pyprops, pyfastmap_handle,
                                       NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_create");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx,
                    "Python cb_create invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(tctxref);
    Py_XDECREF(kpref);
    Py_XDECREF(pyprops);
    Py_XDECREF(pyfastmap_handle);

    PyGILState_Release(gstate);

    return ret;
}


/* ************************************************************************** */
/*
struct ncs_nano_service_cbs {
    char servicepoint[MAX_CALLPOINT_LEN];

    int (*nano_create)(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp,
                       const confd_value_t *component_type,
                       const confd_value_t *component_name,
                       const confd_value_t *state,
                       struct ncs_name_value *proplist, int num_props,
                       struct ncs_name_value *comp_proplist, int num_comp_props,
                       confd_hkeypath_t *skp,
                       int fastmap_thandle);

    int (*nano_delete)(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp,
                       const confd_value_t *component_type,
                       const confd_value_t *component_name,
                       const confd_value_t *state,
                       struct ncs_name_value *proplist, int num_props,
                       struct ncs_name_value *comp_proplist, int num_comp_props,
                       confd_hkeypath_t *skp,
                       int fastmap_thandle);

    void *cb_opaque;
};
*/
/* ************************************************************************** */

static int _nscb_nano_create_cb(struct confd_trans_ctx *tctx,
                                confd_hkeypath_t *kp,
                                const confd_value_t *comptype,
                                const confd_value_t *compname,
                                const confd_value_t *state,
                                struct ncs_name_value *proplist,
                                int num_props,
                                struct ncs_name_value *comp_proplist,
                                int num_comp_props,
                                confd_hkeypath_t *skp,
                                int fastmap_thandle)
{
    int ret = CONFD_OK;
    confdTransCtxRef *tctxref = NULL;
    PyObject *cbs = NULL;
    PyObject *kpref = NULL;
    PyObject *skpref = NULL;
    PyObject *pycomp = NULL;
    PyObject *pycomptype = NULL;
    PyObject *pycompname = NULL;
    PyObject *pystate = NULL;
    PyObject *pyprops = NULL;
    PyObject *pycomp_props = NULL;
    PyObject *pyfastmap_handle = NULL;
    PyObject *pyret = NULL;
    PyObject *cbname = NULL;

    if (tctx->cb_opaque == NULL) {
        /* Should never happen */
        confd_trans_seterr(tctx, "Internal, cb_opaque == NULL");
        return CONFD_ERR;
    }

    PyGILState_STATE gstate = PyGILState_Ensure();

    ret = CONFD_ERR;

    if ((tctxref = (confdTransCtxRef *)
         newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((skpref = newConfdHKeypathRefNoAutoFree(skp)) == NULL) goto decref;
    if ((pyprops = PyList_New(num_props)) == NULL) goto decref;
    if ((pycomp_props = PyList_New(num_comp_props)) == NULL) goto decref;
    if ((pyfastmap_handle = PyInt_FromLong(fastmap_thandle)) == NULL)
        goto decref;
    if ((cbname = PyString_FromString("cb_nano_create")) == NULL) goto decref;

    int c;
    for (c = 0; c < num_props; c++) {
        PyObject *item =
            Py_BuildValue("(ss)", proplist[c].name, proplist[c].value);
        if (item  == NULL)
            goto decref;
        PyList_SetItem(pyprops, c , item);
    }

    for (c = 0; c < num_comp_props; c++) {
        PyObject *item =
            Py_BuildValue("(ss)", comp_proplist[c].name,
                          comp_proplist[c].value);
        if (item  == NULL)
            goto decref;
        PyList_SetItem(pycomp_props, c , item);
    }

    /* Don't have to incref the cbs pointer */
    cbs = tctx->cb_opaque;

    if (comptype && compname) {
        if ((pycomp = PyTuple_New(2)) == NULL) {
            goto decref;
        }
        if ((pycomptype = PyConfd_Value_New_DupTo_Py(comptype)) == NULL) {
            goto decref;
        }
        if (PyTuple_SetItem(pycomp, 0, pycomptype)) {
            Py_XDECREF(pycomptype);
            goto decref;
        }
        if ((pycompname = PyConfd_Value_New_DupTo_Py(compname)) == NULL) {
            goto decref;
        }
        if (PyTuple_SetItem(pycomp, 1, pycompname)) {
            Py_XDECREF(pycompname);
            goto decref;
        }
    } else {
        Py_INCREF(Py_None);
        pycomp = Py_None;
    }
    if (state) {
        if ((pystate = PyConfd_Value_New_DupTo_Py(state)) == NULL) goto decref;
    } else {
        Py_INCREF(Py_None);
        pystate = Py_None;
    }

    pyret = PyObject_CallMethodObjArgs(cbs, cbname,
                                       tctxref, kpref,
                                       pycomp, pystate,
                                       pyprops, pycomp_props,
                                       skpref, pyfastmap_handle,
                                       NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_nano_create");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx,
                    "Python cb_nano_create invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    unrefConfdHKeypathRef(skpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(tctxref);
    Py_XDECREF(kpref);
    Py_XDECREF(skpref);
    Py_XDECREF(pycomp);
    Py_XDECREF(pystate);
    Py_XDECREF(pyprops);
    Py_XDECREF(pyfastmap_handle);

    PyGILState_Release(gstate);

    return ret;
}


static int _nscb_nano_delete_cb(struct confd_trans_ctx *tctx,
                                confd_hkeypath_t *kp,
                                const confd_value_t *comptype,
                                const confd_value_t *compname,
                                const confd_value_t *state,
                                struct ncs_name_value *proplist,
                                int num_props,
                                struct ncs_name_value *comp_proplist,
                                int num_comp_props,
                                confd_hkeypath_t *skp,
                                int fastmap_thandle)
{
    int ret = CONFD_OK;
    confdTransCtxRef *tctxref = NULL;
    PyObject *cbs = NULL;
    PyObject *kpref = NULL;
    PyObject *skpref = NULL;
    PyObject *pycomp = NULL;
    PyObject *pycomptype = NULL;
    PyObject *pycompname = NULL;
    PyObject *pystate = NULL;
    PyObject *pyprops = NULL;
    PyObject *pycomp_props = NULL;
    PyObject *pyfastmap_handle = NULL;
    PyObject *pyret = NULL;
    PyObject *cbname = NULL;

    if (tctx->cb_opaque == NULL) {
        /* Should never happen */
        confd_trans_seterr(tctx, "Internal, cb_opaque == NULL");
        return CONFD_ERR;
    }

    PyGILState_STATE gstate = PyGILState_Ensure();

    ret = CONFD_ERR;

    if ((tctxref = (confdTransCtxRef *)
         newConfdTransCtxRef(tctx)) == NULL) goto decref;
    if ((kpref = newConfdHKeypathRefNoAutoFree(kp)) == NULL) goto decref;
    if ((skpref = newConfdHKeypathRefNoAutoFree(skp)) == NULL) goto decref;
    if ((pyprops = PyList_New(num_props)) == NULL) goto decref;
    if ((pycomp_props = PyList_New(num_comp_props)) == NULL) goto decref;
    if ((pyfastmap_handle = PyInt_FromLong(fastmap_thandle)) == NULL)
        goto decref;
    if ((cbname = PyString_FromString("cb_nano_delete")) == NULL) goto decref;

    int c;
    for (c = 0; c < num_props; c++) {
        PyObject *item =
            Py_BuildValue("(ss)", proplist[c].name, proplist[c].value);
        if (item  == NULL)
            goto decref;
        PyList_SetItem(pyprops, c , item);
    }

    for (c = 0; c < num_comp_props; c++) {
        PyObject *item = Py_BuildValue("(ss)",
                                       comp_proplist[c].name,
                                       comp_proplist[c].value);
        if (item  == NULL)
            goto decref;
        PyList_SetItem(pycomp_props, c , item);
    }

    /* Don't have to incref the cbs pointer */
    cbs = tctx->cb_opaque;

    if (compname && comptype) {
        if ((pycomp = PyTuple_New(2)) == NULL) {
            goto decref;
        }
        if ((pycomptype = PyConfd_Value_New_DupTo_Py(comptype)) == NULL) {
            goto decref;
        }
        if (PyTuple_SetItem(pycomp, 0, pycomptype)) {
            Py_XDECREF(pycomptype);
            goto decref;
        }
        if ((pycompname = PyConfd_Value_New_DupTo_Py(compname)) == NULL) {
            goto decref;
        }
        if (PyTuple_SetItem(pycomp, 1, pycompname)) {
            Py_XDECREF(pycompname);
            goto decref;
        }
    } else {
        Py_INCREF(Py_None);
        pycomp = Py_None;
    }
    if (state) {
        if ((pystate = PyConfd_Value_New_DupTo_Py(state)) == NULL) goto decref;
    } else {
        Py_INCREF(Py_None);
        pystate = Py_None;
    }

    pyret = PyObject_CallMethodObjArgs(cbs, cbname,
                                       tctxref, kpref,
                                       pycomp, pystate,
                                       pyprops, pycomp_props,
                                       skpref, pyfastmap_handle,
                                       NULL);

    if (pyret == NULL) {
        _confd_py_trans_seterr_fetch(tctx, "cb_nano_delete");
        ret = CONFD_ERR;
    } else {
        if (pyret == Py_None) {
            ret = CONFD_OK;
        } else if (PyInt_Check(pyret)) {
            ret = PyInt_AsLong(pyret);
        } else {
            confd_trans_seterr(tctx,
                    "Python cb_nano_delete invalid return type");
            ret = CONFD_ERR;
        }
    }

decref:
    unrefConfdHKeypathRef(kpref);
    unrefConfdHKeypathRef(skpref);
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(tctxref);
    Py_XDECREF(kpref);
    Py_XDECREF(skpref);
    Py_XDECREF(pycomp);
    Py_XDECREF(pystate);
    Py_XDECREF(pyprops);
    Py_XDECREF(pyfastmap_handle);

    PyGILState_Release(gstate);

    return ret;
}



#endif /* CONFD_PY_PRODUCT_NCS */

/* ------------------------------------------------------------------------- */

static void *setup_confd_action_cbs(
        struct confd_action_cbs *acb,
        const char *actionpoint,
        PyObject *cbs)
{
    if (strlen(actionpoint) > MAX_CALLPOINT_LEN-1) {
        PyErr_Format(PyExc_Exception,
            "actionpoint argument can be at most %d characters in length",
            MAX_CALLPOINT_LEN-1);
        return NULL;
    }

    memset(acb, 0, sizeof(struct confd_action_cbs));
    memcpy(acb->actionpoint, actionpoint, strlen(actionpoint) + 1);

    CHECK_CB_MTH(cbs, "cb_init", 2);
    acb->init = _cbs_init_cb;

    if (PyObject_HasAttrString(cbs, "cb_action")) {
        CHECK_CB_MTH(cbs, "cb_action", 5);
        acb->action = _cbs_action_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_abort")) {
        CHECK_CB_MTH(cbs, "cb_abort", 2);
        acb->abort = _cbs_abort_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_command")) {
        CHECK_CB_MTH(cbs, "cb_command", 4);
        acb->command = _cbs_command_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_completion")) {
        CHECK_CB_MTH(cbs, "cb_completion", 10);
        acb->completion = _cbs_completion_cb;
    }

    if (!(acb->action || acb->command || acb->completion)) {
        PyErr_Format(PyExc_TypeError,
            "Callback object must implement at least one of the methods "
            "cb_action, cb_command or cb_completion");
        return NULL;
    }

    acb->cb_opaque = (void*) cbs;

    return (void*)1;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_action_cbs, EXT_API_FUN_DP_REGISTER_ACTION_CBS)
{
    static char *kwlist[] = {
        "dx",
        "actionpoint",
        "acb",
        NULL
    };
    PyConfd_DaemonCtxRef_Object *ctx;
    char *actionpoint;
    PyObject *cbs;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OsO", kwlist,
                &ctx, &actionpoint, &cbs)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    struct confd_action_cbs acb;

    if (setup_confd_action_cbs(&acb, actionpoint, cbs) == NULL) {
        return NULL;
    }

    CHECK_CONFD_ERR(confd_register_action_cbs(ctx->ctx, &acb));

    Py_INCREF(cbs);

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_range_action_cbs,
            EXT_API_FUN_DP_REGISTER_RANGE_ACTION_CBS)
{
    static char *kwlist[] = {
        "dx",
        "actionpoint",
        "acb",
        "lower",
        "upper",
        "path",
        NULL
    };
    PyConfd_DaemonCtxRef_Object *ctx;
    char *actionpoint;
    PyObject *cbs;
    PyObject *lower;
    PyObject *upper;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OsOOOO&", kwlist,
                &ctx, &actionpoint, &cbs, &lower, &upper, path_arg, &path)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    py_confd_value_t_list_t lower_ = {0};
    py_confd_value_t_list_t upper_ = {0};
    if (PyList_Check(lower) && PyList_Check(upper)) {
        if (PyList_Size(lower) != PyList_Size(upper)) {
            PyErr_Format(PyExc_TypeError,
                         "lower and upper lists must be of the same length");
            return NULL;
        }

        alloc_py_confd_value_t_list(lower, &lower_, "lower");
        alloc_py_confd_value_t_list(upper, &upper_, "upper");
    }
    else if (lower != Py_None && upper != Py_None) {
        PyErr_Format(PyExc_TypeError,
                        "lower and upper arguments must either both be a list "
                        "of " CONFD_PY_MODULE ".Value or None");
        return NULL;
    }

    struct confd_action_cbs acb;

    if (setup_confd_action_cbs(&acb, actionpoint, cbs) == NULL) {
        return NULL;
    }

    int ret;

    CONFD_EXEC(ret = confd_register_range_action_cbs(
                ctx->ctx, &acb, lower_.list, upper_.list, lower_.size, path));

    free((void *) path);
    free_py_confd_value_t_list(&lower_);
    free_py_confd_value_t_list(&upper_);

    CHECK_CONFD_ERR(ret);

    Py_INCREF(cbs);

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_set_fd, EXT_API_FUN_DP_ACTION_SET_FD)
{
    static char *kwlist[] = {
        "uinfo",
        "sock",
        NULL
    };
    confdUserInfo *uinfo;
    int s;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO&", kwlist,
                &uinfo, sock_arg, &s)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    CONFD_EXEC(confd_action_set_fd(uinfo->uinfo, s));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_reply_values, EXT_API_FUN_DP_ACTION_REPLY_VALUES)
{
    static char *kwlist[] = {
        "uinfo",
        "values",
        NULL
    };

    confdUserInfo *uinfo;
    PyObject *values;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                &uinfo, &values)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    if (!(values == Py_None || PyList_Check(values))) {
        PyErr_Format(PyExc_TypeError,
            "values argument must be None of a list of "
            CONFD_PY_MODULE ".TagValue instances");
        return NULL;
    }

    py_confd_tag_value_t_list_t tv = {0};
    if (!alloc_py_confd_tag_value_t_list(values, &tv, "values")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_action_reply_values(uinfo->uinfo, tv.list, tv.size),
            free_py_confd_tag_value_t_list(&tv));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_reply_command, EXT_API_FUN_DP_ACTION_REPLY_COMMAND)
{
    static char *kwlist[] = {
        "uinfo",
        "values",
        NULL
    };

    confdUserInfo *uinfo;
    PyObject *values;
    py_string_list_t values_sl = {0};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                &uinfo, &values)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    if (PyList_Check(values)) {
        if (! confd_py_alloc_py_string_list(values, &values_sl, "values")) {
            return NULL;
        }
    } else if (values != Py_None) {
        PyErr_Format(PyExc_TypeError,
            "values argument must be a list of strings or None");
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(confd_action_reply_command(uinfo->uinfo,
                                                    values_sl.list,
                                                    values_sl.size),
                         confd_py_free_py_string_list(&values_sl));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_reply_rewrite, EXT_API_FUN_DP_ACTION_REPLY_REWRITE)
{
    static char *kwlist[] = {
        "uinfo",
        "values",
        "unhides",
        NULL
    };

    confdUserInfo *uinfo;
    PyObject *values;
    PyObject *unhides;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOO", kwlist,
                &uinfo, &values, &unhides)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
                     "uinfo argument must be a "
                     CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    if (! PyList_Check(values) && values != Py_None) {
        PyErr_Format(PyExc_TypeError,
                     "values argument must be a list of strings or None");
    }

    if (! PyList_Check(unhides) && unhides != Py_None) {
        PyErr_Format(PyExc_TypeError,
                     "unhides argument must be a list of strings or None");
        return NULL;
    }

    py_string_list_t values_sl = {0};
    if (PyList_Check(values)
        && ! confd_py_alloc_py_string_list(values, &values_sl, "values")) {
        return NULL;
    }

    py_string_list_t unhides_sl = {0};
    if (PyList_Check(unhides)
        && ! confd_py_alloc_py_string_list(unhides, &unhides_sl, "unhides")) {
        confd_py_free_py_string_list(&values_sl);
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(confd_action_reply_rewrite(uinfo->uinfo,
                                                    values_sl.list,
                                                    values_sl.size,
                                                    unhides_sl.list,
                                                    unhides_sl.size),
                         {
                             confd_py_free_py_string_list(&values_sl);
                             confd_py_free_py_string_list(&unhides_sl);
                         });

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_reply_rewrite2, EXT_API_FUN_DP_ACTION_REPLY_REWRITE2)
{
    static char *kwlist[] = {
        "uinfo",
        "values",
        "unhides",
        "selects",
        NULL
    };

    confdUserInfo *uinfo;
    PyObject *values;
    PyObject *unhides;
    PyObject *selects;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOOO", kwlist,
                &uinfo, &values, &unhides, &selects)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
                     "uinfo argument must be a "
                     CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }
    if (! PyList_Check(values) && values != Py_None) {
        PyErr_Format(PyExc_TypeError,
                     "values argument must be a list of strings or None");
        return NULL;
    }
    if (! PyList_Check(unhides) && unhides != Py_None) {
        PyErr_Format(PyExc_TypeError,
                     "unhides argument must be a list of strings or None");
        return NULL;
    }
    if (! PyList_Check(selects) && selects != Py_None) {
        PyErr_Format(PyExc_TypeError,
                     "selects argument must be a list of strings or None");
        return NULL;
    }

    py_string_list_t values_sl = {0};
    if (PyList_Check(values)
        && ! confd_py_alloc_py_string_list(values, &values_sl, "values")) {
        return NULL;
    }
    py_string_list_t unhides_sl = {0};
    if (PyList_Check(unhides)
        && ! confd_py_alloc_py_string_list(unhides, &unhides_sl, "unhides")) {
        confd_py_free_py_string_list(&values_sl);
        return NULL;
    }
    py_string_list_t selects_sl = {0};
    if (PyList_Check(selects)
        && ! confd_py_alloc_py_string_list(selects, &selects_sl, "selects")) {
        confd_py_free_py_string_list(&values_sl);
        confd_py_free_py_string_list(&unhides_sl);
        return NULL;
    }

    struct confd_rewrite_select confd_sel, *confd_sel_p;
    confd_sel.tokens = selects_sl.list;
    confd_sel.n = selects_sl.size;
    confd_sel_p = &confd_sel;

    CHECK_CONFD_ERR_EXEC(
                         confd_action_reply_rewrite2(uinfo->uinfo,
                                                     values_sl.list,
                                                     values_sl.size,
                                                     unhides_sl.list,
                                                     unhides_sl.size,
                                                     &confd_sel_p, 1),
                         {
                             confd_py_free_py_string_list(&selects_sl);
                             confd_py_free_py_string_list(&unhides_sl);
                             confd_py_free_py_string_list(&values_sl);
                         });

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

static void _free_confd_completion_values(struct confd_completion_value *ccvs,
                                          int size)
{
    for (int i = 0; i < size; i++) {
        if (ccvs[i].value == NULL) {
            break;
        }
        free(ccvs[i].value);
        free(ccvs[i].extra);
    }
    free(ccvs);
}

EXT_API_FUN(_dp_action_reply_completion, EXT_API_FUN_DP_ACTION_REPLY_COMPLETION)
{
    static char *kwlist[] = {
        "uinfo",
        "values",
        NULL
    };

    confdUserInfo *uinfo;
    PyObject *values;
    int size = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                &uinfo, &values)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    struct confd_completion_value *confd_cv = NULL;

    if (values == Py_None ||
            (PyList_Check(values) && PyList_Size(values) == 0)) {
        goto docall;
    }

    if (!PyList_Check(values)) {
        PyErr_Format(PyExc_TypeError,
            "values argument must be a list of 3-tuples or None");
        return NULL;
    }

    size = (int)PyList_Size(values);

    confd_cv = (struct confd_completion_value*)
        calloc(size, sizeof(struct confd_completion_value));

    PyObject *po;
    for (int c = 0; c < size; c++) {
        PyObject *s = PyList_GetItem(values, c);

        if (!PyTuple_Check(s)) {
            PyErr_Format(PyExc_TypeError,
                "Item %d in values is not a 3-tuple", c);
            _free_confd_completion_values(confd_cv, size);
            return NULL;
        }
        if (PyTuple_Size(s) != 3) {
            PyErr_Format(PyExc_TypeError,
                "Item %d in values is not a 3-tuple", c);
            _free_confd_completion_values(confd_cv, size);
            return NULL;
        }

        po = PyTuple_GetItem(s, 0);
        if (!PyInt_Check(po)) {
            PyErr_Format(PyExc_TypeError,
                "First item of tuple %d in values must be an integer", c);
            _free_confd_completion_values(confd_cv, size);
            return NULL;
        }
        confd_cv[c].type = PyInt_AsLong(po);

        po = PyTuple_GetItem(s, 1);
        if (!PyString_Check(po)) {
            PyErr_Format(PyExc_TypeError,
                "Second item of tuple %d in values must be a string", c);
            _free_confd_completion_values(confd_cv, size);
            return NULL;
        }
        confd_cv[c].value = confd_py_string_strdup(po);

        po = PyTuple_GetItem(s, 2);
        if (po == Py_None) {
            confd_cv[c].extra = NULL;
        } else {
            if (!PyString_Check(po)) {
                PyErr_Format(PyExc_TypeError,
                    "Third item of tuple %d in values must be a string "
                    "or None", c);
                _free_confd_completion_values(confd_cv, size);
                return NULL;
            }
            confd_cv[c].extra = confd_py_string_strdup(po);
        }
    }

docall:

    CHECK_CONFD_ERR_EXEC(confd_action_reply_completion(uinfo->uinfo,
                                                       confd_cv, size),
                         _free_confd_completion_values(confd_cv, size));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_reply_range_enum, EXT_API_FUN_DP_ACTION_REPLY_RANGE_ENUM)
{
    static char *kwlist[] = {
        "uinfo",
        "values",
        "keysize",
        NULL
    };

    confdUserInfo *uinfo;
    PyObject *values;
    int keysize = 1;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOi", kwlist,
                &uinfo, &values, &keysize)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    py_string_list_t values_sl = {0};
    if (PyList_Check(values)) {
        int num_values = (int)PyList_Size(values);
        if (num_values > 0) {
            if (keysize < 1) {
                PyErr_Format(PyExc_TypeError,
                             "keysize argument must be at least 1");
                return NULL;
            }
            if (num_values % keysize != 0) {
                PyErr_Format(PyExc_TypeError,
                             "Number of values must be a multiple of keysize");
                return NULL;
            }
        }

        if (! confd_py_alloc_py_string_list(values, &values_sl, "values")) {
            return NULL;
        }
    }  else if (values != Py_None) {
        PyErr_Format(PyExc_TypeError,
                     "values argument must be a list of strings or None");
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(confd_action_reply_range_enum(uinfo->uinfo,
                                                       values_sl.list,
                                                       keysize,
                                                       values_sl.size),
            confd_py_free_py_string_list(&values_sl));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_delayed_reply_ok, EXT_API_FUN_DP_ACTION_DELAYED_REPLY_OK)
{
    static char *kwlist[] = {
        "uinfo",
        NULL
    };

    confdUserInfo *uinfo;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &uinfo)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_action_delayed_reply_ok(uinfo->uinfo));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_delayed_reply_error,
            EXT_API_FUN_DP_ACTION_DELAYED_REPLY_ERROR)
{
    static char *kwlist[] = {
        "uinfo",
        "errstr",
        NULL
    };

    confdUserInfo *uinfo;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Os", kwlist,
                &uinfo, &errstr)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_action_delayed_reply_error(uinfo->uinfo, errstr));

    Py_RETURN_NONE;
}


/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_seterr, EXT_API_FUN_DP_ACTION_SETERR)
{
    static char *kwlist[] = {
        "uinfo",
        "errstr",
        NULL
    };

    confdUserInfo *uinfo;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Os", kwlist,
                &uinfo, &errstr)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    CONFD_EXEC(confd_action_seterr(uinfo->uinfo, "%s", errstr));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_seterr_extended, EXT_API_FUN_DP_ACTION_SETERR_EXTENDED)
{
    static char *kwlist[] = {
        "uinfo",
        "code",
        "apptag_ns",
        "apptag_tag",
        "errstr",
        NULL
    };

    confdUserInfo *uinfo;
    int code;
    u_int32_t apptag_ns;
    u_int32_t apptag_tag;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OiIIs", kwlist,
                &uinfo, &code, &apptag_ns, &apptag_tag, &errstr)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    CONFD_EXEC(confd_action_seterr_extended(
                uinfo->uinfo, code, apptag_ns, apptag_tag, "%s", errstr));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_seterr_extended_info,
            EXT_API_FUN_DP_ACTION_SETERR_EXTENDED_INFO)
{
    static char *kwlist[] = {
        "uinfo",
        "code",
        "apptag_ns",
        "apptag_tag",
        "error_info",
        "errstr",
        NULL
    };

    confdUserInfo *uinfo;
    int code;
    u_int32_t apptag_ns;
    u_int32_t apptag_tag;
    PyObject *error_info;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OiIIOs", kwlist,
                &uinfo, &code, &apptag_ns, &apptag_tag, &error_info, &errstr)){
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    if (!PyList_Check(error_info)) {
        PyErr_Format(PyExc_TypeError,
            "error_info argument must be a list of "
            CONFD_PY_MODULE ".TagValue instances");
        return NULL;
    }

    if (PyList_Size(error_info) < 1) {
        PyErr_Format(PyExc_TypeError,
            "Number of error_info must be at least 1");
        return NULL;
    }

    py_confd_tag_value_t_list_t tv = {0};
    if (!alloc_py_confd_tag_value_t_list(error_info, &tv, "error_info")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_action_seterr_extended_info(
                uinfo->uinfo, code, apptag_ns, apptag_tag,
                tv.list, tv.size, "%s", errstr),
            free_py_confd_tag_value_t_list(&tv));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_action_set_timeout, EXT_API_FUN_DP_ACTION_SET_TIMEOUT)
{
    static char *kwlist[] = {
        "uinfo",
        "timeout_secs",
        NULL
    };

    confdUserInfo *uinfo;
    int timeout;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oi", kwlist,
                &uinfo, &timeout)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    CONFD_EXEC(confd_action_set_timeout(uinfo->uinfo, timeout));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_data_reply_value, EXT_API_FUN_DP_DATA_REPLY_VALUE)
{
    static char *kwlist[] = {
        "tctx",
        "v",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    PyConfd_Value_Object *value;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                &ctx, &value)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    if (!PyConfd_Value_CheckExact((PyObject*)value)) {
        PyErr_Format(PyExc_TypeError,
                     "v argument must be a "
                     CONFD_PY_MODULE ".Value instance");
        return NULL;
    }
    CHECK_CONFD_ERR(confd_data_reply_value(ctx->tc, PyConfd_Value_PTR(value)));
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_data_reply_value_array, EXT_API_FUN_DP_DATA_REPLY_VALUE_ARRAY)
{
    static char *kwlist[] = {
        "tctx",
        "vs",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    PyObject *vlist = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                &ctx, &vlist)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    if (!PyList_Check(vlist)) {
        PyErr_Format(PyExc_TypeError,
            "vs argument must be a list of "
            CONFD_PY_MODULE ".Value instances");
        return NULL;
    }

    py_confd_value_t_list_t pv = {0};
    if (!alloc_py_confd_value_t_list(vlist, &pv, "vs")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_data_reply_value_array(ctx->tc, pv.list, pv.size),
            free_py_confd_value_t_list(&pv));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_data_reply_tag_value_array,
            EXT_API_FUN_DP_DATA_REPLY_TAG_VALUE_ARRAY)
{
    static char *kwlist[] = {
        "tctx",
        "tvs",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    PyObject *tvs = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                &ctx, &tvs)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    if (!(tvs == Py_None || PyList_Check(tvs))) {
        PyErr_Format(PyExc_TypeError,
            "tvs argument must be None or a list of "
            CONFD_PY_MODULE ".TagValue instances");
        return NULL;
    }

    py_confd_tag_value_t_list_t tv = {0};
    if (!alloc_py_confd_tag_value_t_list(tvs, &tv, "tvs")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_data_reply_tag_value_array(ctx->tc, tv.list, tv.size),
            free_py_confd_tag_value_t_list(&tv));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_data_reply_found, EXT_API_FUN_DP_DATA_REPLY_FOUND)
{
    static char *kwlist[] = { "tctx", NULL };
    confdTransCtxRef *ctx = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &ctx)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_data_reply_found(ctx->tc));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_data_reply_not_found, EXT_API_FUN_DP_DATA_REPLY_NOT_FOUND)
{
    static char *kwlist[] = { "tctx", NULL };
    confdTransCtxRef *ctx = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &ctx)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_data_reply_not_found(ctx->tc));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_data_reply_next_key, EXT_API_FUN_DP_DATA_REPLY_NEXT_KEY)
{
    static char *kwlist[] = {
        "tctx",
        "keys",
        "next",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    PyObject *keys = NULL;
    long next;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOl", kwlist,
                &ctx, &keys, &next)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    py_confd_value_t_list_t cl = {0};
    if (PyList_Check(keys)) {
        Py_ssize_t len = PyList_Size(keys);
        if (len > 0) {
            if (!alloc_py_confd_value_t_list(keys, &cl, "keys")) {
                return NULL;
            }
        }
    } else if (keys != Py_None) {
        PyErr_Format(PyExc_TypeError,
            "keys argument must be a list of "
            CONFD_PY_MODULE ".Value instances or None");
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_data_reply_next_key(ctx->tc,
                                      cl.list,
                                      cl.size,
                                      next),
            free_py_confd_value_t_list(&cl));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_data_reply_next_object_array,
            EXT_API_FUN_DP_DATA_REPLY_NEXT_OBJECT_ARRAY)
{
    static char *kwlist[] = {
        "tctx",
        "v",
        "next",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    PyObject *values = NULL;
    long next;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOl", kwlist,
                &ctx, &values, &next)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    py_confd_value_t_list_t cl = {0};
    if (PyList_Check(values)) {
        Py_ssize_t len = PyList_Size(values);
        if (len > 0) {
            if (!alloc_py_confd_value_t_list(values, &cl, "v")) {
                return NULL;
            }
        }
    } else if (values != Py_None) {
        PyErr_Format(PyExc_TypeError,
            "v argument must be a list of "
            CONFD_PY_MODULE ".Value instances or None");
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_data_reply_next_object_array(
                ctx->tc,
                cl.list,
                cl.size,
                next),
            free_py_confd_value_t_list(&cl));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

static void free_next_object_arr(struct confd_next_object *obj, int nobjs)
{
    if (obj) {
        int i;
        for (i = 0; i < nobjs; i++) {
            if (obj[i].v) {
                free(obj[i].v);
            }
        }
        free(obj);
    }
}

EXT_API_FUN(_dp_data_reply_next_object_arrays,
            EXT_API_FUN_DP_DATA_REPLY_NEXT_OBJECT_ARRAYS)
{
    static char *kwlist[] = {
        "tctx",
        "objs",
        "timeout_millisecs",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    PyObject *obj = NULL;
    long timeout;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOl", kwlist,
                &ctx, &obj, &timeout)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    if (obj != Py_None && !PyList_Check(obj)) {
        PyErr_Format(PyExc_TypeError,
                "objs argument must be a list of tuples or None");
        return NULL;
    }

    /* Python format of objs is list(tuple(list(_lib.Value), long)).
     * objs may also be None to indicate end of list.
     * Another way to indicate end of list is to include None as the
     * first item in the 2-tuple last in the list.
     *
     * objs = [
     *         ( [ V(1), V(2) ], next1 ),
     *         ( [ V(3), V(4) ], next2 ),
     *         ( None, -1 )
     *       ]
     */

    int nobjs = 0;
    struct confd_next_object *no = NULL;

    if (obj != Py_None) {
        nobjs = (int)PyList_Size(obj);
        if (nobjs <= 0) {
            PyErr_Format(PyExc_TypeError, "Number of objs must be at least 1");
            return NULL;
        }
        no = (struct confd_next_object*)malloc(
                sizeof(struct confd_next_object) * nobjs);
        memset(no, 0, sizeof(struct confd_next_object) * nobjs);

        int i, j;
        PyObject *pot;
        PyObject *polist;
        PyObject *polong;

        for (i = 0; i < nobjs; i++) {
            pot = PyList_GetItem(obj, i);
            if (pot == Py_None) {
                no[i].v = NULL;
                no[i].next = -1;
            } else {
                if ((!PyTuple_Check(pot)) || PyTuple_Size(pot) != 2) {
                    PyErr_Format(PyExc_TypeError,
                            "Item %d in objs must be a 2-tuple or None", i);
                    free_next_object_arr(no, nobjs);
                    return NULL;
                }

                polist = PyTuple_GetItem(pot, 0);

                if (polist == Py_None) {
                    if (i != nobjs - 1) {
                        PyErr_Format(PyExc_TypeError,
                                "First item of 2-tuple at position %d in objs "
                                "is None and must be last in list", i);
                        free_next_object_arr(no, nobjs);
                        return NULL;
                    }
                    no[i].v = NULL;
                    no[i].next = -1;
                    break;
                }

                if (!PyList_Check(polist)) {
                    PyErr_Format(PyExc_TypeError,
                            "Item %d in objs must be None or a list of "
                            CONFD_PY_MODULE ".Value", i);
                    free_next_object_arr(no, nobjs);
                    return NULL;
                }

                int vlistsize = PyList_Size(polist);
                if (vlistsize <= 0) {
                    PyErr_Format(PyExc_TypeError,
                            "List at first item of 2-tuple at item %d in objs "
                            " must contain at least 1 entry", i);
                    free_next_object_arr(no, nobjs);
                    return NULL;
                }

                no[i].v = (confd_value_t*)malloc(
                        sizeof(confd_value_t) * vlistsize);
                no[i].n = vlistsize;

                PyObject *value;
                for (j = 0; j < vlistsize; j++) {
                    value = PyList_GetItem(polist, j);
                    if (!PyConfd_Value_CheckExact(value)) {
                        PyErr_Format(PyExc_TypeError,
                            "List at first item of 2-tuple at item %d in objs "
                            " must only contain "
                            CONFD_PY_MODULE ".type.Value instances", i);
                        free_next_object_arr(no, nobjs);
                        return NULL;
                    }
                    memcpy(no[i].v + j,
                           PyConfd_Value_PTR((PyConfd_Value_Object*)value),
                           sizeof(confd_value_t));
                }

                polong = PyTuple_GetItem(pot, 1);
                if (!PyLong_Check(polong)) {
                    PyErr_Format(PyExc_TypeError,
                            "Long at second item of 2-tuple at item %d in objs "
                            "must be of type long", i);
                    free_next_object_arr(no, nobjs);
                    return NULL;
                }

                no[i].next = PyLong_AsLong(polong);
            }
        }
    }

    CHECK_CONFD_ERR_EXEC(
            confd_data_reply_next_object_arrays(
                ctx->tc, no, nobjs, timeout),
            free_next_object_arr(no, nobjs));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_data_reply_next_object_tag_value_array,
            EXT_API_FUN_DP_DATA_REPLY_NEXT_OBJECT_TAG_VALUE_ARRAY)
{
    static char *kwlist[] = {
        "tctx",
        "tvs",
        "next",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    PyObject *tvs = NULL;
    long next;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOl", kwlist,
                &ctx, &tvs, &next)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    if (tvs != Py_None && !PyList_Check(tvs)) {
        PyErr_Format(PyExc_TypeError,
            "tvs argument must be a list of "
            CONFD_PY_MODULE ".TagValue instances or None");
        return NULL;
    }

    py_confd_tag_value_t_list_t tv = {0};
    if (!alloc_py_confd_tag_value_t_list(tvs, &tv, "tvs")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_data_reply_next_object_tag_value_array(
                ctx->tc, tv.list, tv.size, next),
            free_py_confd_tag_value_t_list(&tv));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

static void free_tag_next_object_arr(
        struct confd_tag_next_object *obj, int nobjs)
{
    if (obj) {
        int i;
        for (i = 0; i < nobjs; i++) {
            if (obj[i].tv) {
                free(obj[i].tv);
            }
        }
        free(obj);
    }
}


EXT_API_FUN(_dp_data_reply_next_object_tag_value_arrays,
            EXT_API_FUN_DP_DATA_REPLY_NEXT_OBJECT_TAG_VALUE_ARRAYS)
{
    static char *kwlist[] = {
        "tctx",
        "objs",
        "timeout_millisecs",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    PyObject *obj = NULL;
    long timeout;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOl", kwlist,
                &ctx, &obj, &timeout)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    if (obj != Py_None && !PyList_Check(obj)) {
        PyErr_Format(PyExc_TypeError,
                "objs argument must be a list of tuples or None");
        return NULL;
    }

    /* Python format of objs is list(tuple(list(_lib.TagValue), long)).
     * objs may also be None to indicate end of list.
     * Another way to indicate end of list if to include None as the
     * first item in the 2-tuple last in the list.
     *
     * objs = [
     *          ( [ tagval1, tagval2 ], next1 ),
     *          ( [ tagval3, tagval4, tagval5 ], next2 ),
     *          ( None, -1 )
     *        ]
     */

    int nobjs = 0;
    struct confd_tag_next_object *no = NULL;

    if (obj != Py_None) {
        nobjs = (int)PyList_Size(obj);
        if (nobjs <= 0) {
            PyErr_Format(PyExc_TypeError, "Number of objs must be at least 1");
            return NULL;
        }
        no = (struct confd_tag_next_object*)malloc(
                sizeof(struct confd_tag_next_object) * nobjs);
        memset(no, 0, sizeof(struct confd_tag_next_object) * nobjs);

        int i, j;
        PyObject *pot;
        PyObject *polist;
        PyObject *polong;

        for (i = 0; i < nobjs; i++) {
            pot = PyList_GetItem(obj, i);
            if (pot == Py_None) {
                no[i].tv = NULL;
                no[i].next = -1;
            } else {
                if ((!PyTuple_Check(pot)) || PyTuple_Size(pot) != 2) {
                    PyErr_Format(PyExc_TypeError,
                            "Item %d in objs must be a 2-tuple or None", i);
                    free_tag_next_object_arr(no, nobjs);
                    return NULL;
                }

                polist = PyTuple_GetItem(pot, 0);

                if (polist == Py_None) {
                    if (i != nobjs - 1) {
                        PyErr_Format(PyExc_TypeError,
                                "First item of 2-tuple at position %d in objs "
                                "is None and must be last in list", i);
                        free_tag_next_object_arr(no, nobjs);
                        return NULL;
                    }
                    no[i].tv = NULL;
                    no[i].next = -1;
                    break;
                }

                if (!PyList_Check(polist)) {
                    PyErr_Format(PyExc_TypeError,
                            "Item %d in objs must be None or a list of "
                            CONFD_PY_MODULE ".TagValue", i);
                    free_tag_next_object_arr(no, nobjs);
                    return NULL;
                }

                int vlistsize = PyList_Size(polist);
                if (vlistsize <= 0) {
                    PyErr_Format(PyExc_TypeError,
                            "List at first item of 2-tuple at item %d in objs "
                            " must contain at least 1 entry", i);
                    free_tag_next_object_arr(no, nobjs);
                    return NULL;
                }

                no[i].tv = (confd_tag_value_t*)malloc(
                        sizeof(confd_tag_value_t) * vlistsize);
                no[i].n = vlistsize;

                PyObject *value;
                for (j = 0; j < vlistsize; j++) {
                    value = PyList_GetItem(polist, j);
                    if (!PyConfd_TagValue_CheckExact(value)) {
                        PyErr_Format(PyExc_TypeError,
                            "List at first item of 2-tuple at item %d in objs "
                            " must only contain "
                            CONFD_PY_MODULE ".type.TagValue instances", i);
                        free_tag_next_object_arr(no, nobjs);
                        return NULL;
                    }
                    memcpy(no[i].tv + j,
                           PyConfd_TagValue_PTR(value),
                           sizeof(confd_tag_value_t));
                }

                polong = PyTuple_GetItem(pot, 1);
                if (!PyLong_Check(polong)) {
                    PyErr_Format(PyExc_TypeError,
                            "Long at second item of 2-tuple at item %d in objs "
                            "must be of type long", i);
                    free_tag_next_object_arr(no, nobjs);
                    return NULL;
                }

                no[i].next = PyLong_AsLong(polong);
            }
        }
    }

    CHECK_CONFD_ERR_EXEC(
            confd_data_reply_next_object_tag_value_arrays(
                ctx->tc, no, nobjs, timeout),
            free_tag_next_object_arr(no, nobjs));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_data_reply_attrs, EXT_API_FUN_DP_DATA_REPLY_ATTRS)
{
    static char *kwlist[] = {
        "tctx",
        "attrs",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    PyObject *attrs = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                &ctx, &attrs)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    if (!PyList_Check(attrs)) {
        PyErr_Format(PyExc_TypeError,
                "attrs argument must be a list of "
                CONFD_PY_MODULE ".AttrValue instances");
        return NULL;
    }

    confd_attr_value_t *cattrs = NULL;
    int numattrs = PyList_Size(attrs);

    if (numattrs > 0) {
        cattrs = (confd_attr_value_t*)malloc(
                sizeof(confd_attr_value_t) * numattrs);
        int i;
        PyObject *a;
        for (i = 0; i < numattrs; i++) {
            a = PyList_GetItem(attrs, i);
            if (!PyConfd_AttrValue_CheckExact(a)) {
                PyErr_Format(PyExc_TypeError,
                        "Item %d in attrs must be a "
                        CONFD_PY_MODULE ".AttrValue instance", i);
                free(cattrs);
                return NULL;
            }
            cattrs[i].attr =
                (u_int32_t)PyLong_AsLong(((PyConfd_AttrValue_Object*)a)->attr);
            cattrs[i].v =
                *(PyConfd_Value_PTR(((PyConfd_AttrValue_Object*)a)->v));
        }
    }

    CHECK_CONFD_ERR_EXEC(
            confd_data_reply_attrs(ctx->tc, cattrs, numattrs),
            free(cattrs));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_data_set_timeout, EXT_API_FUN_DP_DATA_SET_TIMEOUT)
{
    static char *kwlist[] = {
        "tctx",
        "timeout_secs",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    int timeout;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oi", kwlist,
                &ctx, &timeout)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_data_set_timeout(ctx->tc, timeout));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_data_get_list_filter, EXT_API_FUN_DP_DATA_GET_LIST_FILTER)
{
    static char *kwlist[] = {
        "tctx",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    struct confd_list_filter *filter = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &ctx)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_data_get_list_filter(ctx->tc, &filter));

    if (filter == NULL) {
        Py_RETURN_NONE;
    }
    return newConfdListFilter(filter, NULL);
}


/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_delayed_reply_ok, EXT_API_FUN_DP_DELAYED_REPLY_OK)
{
    static char *kwlist[] = {
        "tctx",
        NULL
    };
    confdTransCtxRef *ctx = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &ctx)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_delayed_reply_ok(ctx->tc));

    Py_RETURN_NONE;
}


/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_delayed_reply_error, EXT_API_FUN_DP_DELAYED_REPLY_ERROR)
{
    static char *kwlist[] = {
        "tctx",
        "errstr",
        NULL
    };
    confdTransCtxRef *ctx = NULL;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Os", kwlist,
                &ctx, &errstr)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_delayed_reply_error(ctx->tc, errstr));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_delayed_reply_validation_warn,
            EXT_API_FUN_DP_DELAYED_REPLY_VALIDATION_WARN)
{
    static char *kwlist[] = {
        "tctx",
        NULL
    };
    confdTransCtxRef *ctx = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &ctx)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
                     "tctx argument must be a "
                      CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_delayed_reply_validation_warn(ctx->tc));

    Py_RETURN_NONE;
}

/* ************************************************************************* */
/* _dp_register_db_cb                                                        */
/* ************************************************************************* */
/*
    struct confd_db_cbs {
        int (*candidate_commit)(struct confd_db_ctx *dbx, int timeout);
        int (*candidate_confirming_commit)(struct confd_db_ctx *dbx);
        int (*candidate_reset)(struct confd_db_ctx *dbx);
        int (*candidate_chk_not_modified)(struct confd_db_ctx *dbx);
        int (*candidate_rollback_running)(struct confd_db_ctx *dbx);
        int (*candidate_validate)(struct confd_db_ctx *dbx);
        int (*add_checkpoint_running)(struct confd_db_ctx *dbx);
        int (*del_checkpoint_running)(struct confd_db_ctx *dbx);
        int (*activate_checkpoint_running)(struct confd_db_ctx *dbx);
        int (*copy_running_to_startup)(struct confd_db_ctx *dbx);
        int (*running_chk_not_modified)(struct confd_db_ctx *dbx);
        int (*lock)(struct confd_db_ctx *dbx, enum confd_dbname dbname);
        int (*unlock)(struct confd_db_ctx *dbx, enum confd_dbname dbname);
        int (*lock_partial)(struct confd_db_ctx *dbx,
                            enum confd_dbname dbname, int lockid,
                            confd_hkeypath_t paths[], int npaths);
        int (*unlock_partial)(struct confd_db_ctx *dbx,
                                enum confd_dbname dbname, int lockid);
        int (*delete_config)(struct confd_db_ctx *dbx,
                            enum confd_dbname dbname);
    };
*/

/* ------------------------------------------------------------------------- */
static int _db_candidate_commit_cb(struct confd_db_ctx *dbx, int timeout)
{
    py_dp_daemon_extra_t *extra = GET_DB_DAEMON_EXTRA(dbx);

    if (extra == NULL) {
        /* Should never happen */
        confd_db_seterr(dbx, "Internal, extra == NULL");
        return CONFD_ERR;
    }

    if (extra->db_cb_ctx == NULL) {
        /* Should never happen */
        confd_db_seterr(dbx,
            "Internal, extra->db_cb_ctx == NULL");
        return CONFD_ERR;
    }

    int ret = CONFD_ERR;

    confdDbCtxRef *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pytimeout = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    if ((ctxRef = (confdDbCtxRef*)newConfdDbCtxRef(dbx)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_candidate_commit")) == NULL)
        goto decref;
    if ((pytimeout = PyInt_FromLong(timeout)) == NULL) goto decref;

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = extra->db_cb_ctx;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, ctxRef, pytimeout, NULL);

    if (pyret == NULL) {
        _confd_py_db_seterr_fetch(dbx, "cb_candidate_commit");
        ret = CONFD_ERR;
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_db_seterr(dbx, "Python cb_candidate_commit error. "
                             "Invalid return type.");
        ret = CONFD_ERR;
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(pytimeout);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);

    return ret;
}

/* ------------------------------------------------------------------------- */
static int _db_generic_cb(struct confd_db_ctx *dbx, const char *py_mth_name)
{
    py_dp_daemon_extra_t *extra = GET_DB_DAEMON_EXTRA(dbx);

    if (extra == NULL) {
        /* Should never happen */
        confd_db_seterr(dbx, "Internal, extra == NULL");
        return CONFD_ERR;
    }

    if (extra->db_cb_ctx == NULL) {
        /* Should never happen */
        confd_db_seterr(dbx,
            "Internal, extra->db_cb_ctx == NULL");
        return CONFD_ERR;
    }

    int ret = CONFD_ERR;

    confdDbCtxRef *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    if ((ctxRef = (confdDbCtxRef*)newConfdDbCtxRef(dbx)) == NULL) goto decref;
    if ((cbname = PyString_FromString(py_mth_name)) == NULL)
        goto decref;

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = extra->db_cb_ctx;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, ctxRef, NULL);

    if (pyret == NULL) {
        _confd_py_db_seterr_fetch(dbx, py_mth_name);
        ret = CONFD_ERR;
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_db_seterr(dbx, "Python %s error. Invalid return type.",
                            py_mth_name);
        ret = CONFD_ERR;
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);

    return ret;
}

static int _db_candidate_confirming_commit_cb(struct confd_db_ctx *dbx)
{
    return _db_generic_cb(dbx, "cb_candidate_confirming_commit");
}

static int _db_candidate_reset_cb(struct confd_db_ctx *dbx)
{
    return _db_generic_cb(dbx, "cb_candidate_reset");
}

static int _db_candidate_chk_not_modified_cb(struct confd_db_ctx *dbx)
{
    return _db_generic_cb(dbx, "cb_candidate_chk_not_modified");
}

static int _db_candidate_rollback_running_cb(struct confd_db_ctx *dbx)
{
    return _db_generic_cb(dbx, "cb_candidate_rollback_running");
}

static int _db_candidate_validate_cb(struct confd_db_ctx *dbx)
{
    return _db_generic_cb(dbx, "cb_candidate_validate");
}

static int _db_add_checkpoint_running_cb(struct confd_db_ctx *dbx)
{
    return _db_generic_cb(dbx, "cb_add_checkpoint_running");
}

static int _db_del_checkpoint_running_cb(struct confd_db_ctx *dbx)
{
    return _db_generic_cb(dbx, "cb_del_checkpoint_running");
}

static int _db_activate_checkpoint_running_cb(struct confd_db_ctx *dbx)
{
    return _db_generic_cb(dbx, "cb_activate_checkpoint_running");
}

static int _db_copy_running_to_startup_cb(struct confd_db_ctx *dbx)
{
    return _db_generic_cb(dbx, "cb_copy_running_to_startup");
}

static int _db_running_chk_not_modified_cb(struct confd_db_ctx *dbx)
{
    return _db_generic_cb(dbx, "cb_running_chk_not_modified");
}

static int _db_generic2_cb(
        struct confd_db_ctx *dbx,
        enum confd_dbname dbname,
        const char *py_mth_name)
{
    py_dp_daemon_extra_t *extra = GET_DB_DAEMON_EXTRA(dbx);

    if (extra == NULL) {
        /* Should never happen */
        confd_db_seterr(dbx, "Internal, extra == NULL");
        return CONFD_ERR;
    }

    if (extra->db_cb_ctx == NULL) {
        /* Should never happen */
        confd_db_seterr(dbx,
            "Internal, extra->db_cb_ctx == NULL");
        return CONFD_ERR;
    }

    int ret = CONFD_ERR;

    confdDbCtxRef *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pydbname = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    if ((ctxRef = (confdDbCtxRef*)newConfdDbCtxRef(dbx)) == NULL) goto decref;
    if ((cbname = PyString_FromString(py_mth_name)) == NULL) goto decref;
    if ((pydbname = PyInt_FromLong(dbname)) == NULL) goto decref;

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = extra->db_cb_ctx;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, ctxRef, pydbname, NULL);

    if (pyret == NULL) {
        _confd_py_db_seterr_fetch(dbx, py_mth_name);
        ret = CONFD_ERR;
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_db_seterr(dbx, "Python %s error. Invalid return type.",
                            py_mth_name);
        ret = CONFD_ERR;
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(pydbname);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);

    return ret;
}

static int _db_lock_cb(struct confd_db_ctx *dbx, enum confd_dbname dbname)
{
    return _db_generic2_cb(dbx, dbname, "cb_lock");
}

static int _db_unlock_cb(struct confd_db_ctx *dbx, enum confd_dbname dbname)
{
    return _db_generic2_cb(dbx, dbname, "cb_unlock");
}

static int _db_delete_config_cb(
        struct confd_db_ctx *dbx, enum confd_dbname dbname)
{
    return _db_generic2_cb(dbx, dbname, "cb_delete_config");
}

static int _db_lock_partial_cb(
        struct confd_db_ctx *dbx, enum confd_dbname dbname, int lockid,
        confd_hkeypath_t paths[], int npaths)
{
    py_dp_daemon_extra_t *extra = GET_DB_DAEMON_EXTRA(dbx);

    if (extra == NULL) {
        /* Should never happen */
        confd_db_seterr(dbx, "Internal, extra == NULL");
        return CONFD_ERR;
    }

    if (extra->db_cb_ctx == NULL) {
        /* Should never happen */
        confd_db_seterr(dbx,
            "Internal, extra->db_cb_ctx == NULL");
        return CONFD_ERR;
    }

    int ret = CONFD_ERR;

    confdDbCtxRef *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pydbname = NULL;
    PyObject *pyret = NULL;
    PyObject *kprefs = NULL;
    PyObject *pylockid = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    if ((ctxRef = (confdDbCtxRef*)newConfdDbCtxRef(dbx)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_lock_partial")) == NULL) goto decref;
    if ((pydbname = PyInt_FromLong(dbname)) == NULL) goto decref;
    if ((pylockid = PyInt_FromLong(lockid)) == NULL) goto decref;

    kprefs = PyList_New(npaths);

    PyObject *kpref;
    int i;
    for (i = 0; i < npaths; ++i) {
        if ((kpref = newConfdHKeypathRefNoAutoFree(&paths[i])) == NULL)
            goto decref;
        PyList_SetItem(kprefs, i, kpref);
    }

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = extra->db_cb_ctx;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxRef, pydbname, pylockid, kprefs, NULL);

    if (pyret == NULL) {
        _confd_py_db_seterr_fetch(dbx, "cb_lock_partial");
        ret = CONFD_ERR;
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_db_seterr(
                dbx, "Python cb_lock_partial error. Invalid return type.");
        ret = CONFD_ERR;
    }

decref:
    if (kprefs) {
        for (--i; i >= 0; --i) {
            PyObject *kp = PyList_GetItem(kprefs, i);
            unrefConfdHKeypathRef(kp);
        }
    }

    Py_XDECREF(pyret);
    Py_XDECREF(pydbname);
    Py_XDECREF(kprefs);
    Py_XDECREF(pylockid);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);

    return ret;
}

static int _db_unlock_partial_cb(
        struct confd_db_ctx *dbx, enum confd_dbname dbname, int lockid)
{
    py_dp_daemon_extra_t *extra = GET_DB_DAEMON_EXTRA(dbx);

    if (extra == NULL) {
        /* Should never happen */
        confd_db_seterr(dbx, "Internal, extra == NULL");
        return CONFD_ERR;
    }

    if (extra->db_cb_ctx == NULL) {
        /* Should never happen */
        confd_db_seterr(dbx,
            "Internal, extra->db_cb_ctx == NULL");
        return CONFD_ERR;
    }

    int ret = CONFD_ERR;

    confdDbCtxRef *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pydbname = NULL;
    PyObject *pyret = NULL;
    PyObject *pylockid = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    if ((ctxRef = (confdDbCtxRef*)newConfdDbCtxRef(dbx)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_unlock_partial")) == NULL)
        goto decref;
    if ((pydbname = PyInt_FromLong(dbname)) == NULL) goto decref;
    if ((pylockid = PyInt_FromLong(lockid)) == NULL) goto decref;

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = extra->db_cb_ctx;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxRef, pydbname, pylockid, NULL);

    if (pyret == NULL) {
        _confd_py_db_seterr_fetch(dbx, "cb_unlock_partial");
        ret = CONFD_ERR;
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_db_seterr(
                dbx, "Python cb_unlock_partial error. Invalid return type.");
        ret = CONFD_ERR;
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(pydbname);
    Py_XDECREF(pylockid);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);

    return ret;
}

EXT_API_FUN(_dp_register_db_cb, EXT_API_FUN_DP_REGISTER_DB_CB)
{
    static char *kwlist[] = {
        "dx",
        "dbcbs",
        NULL
    };
    PyConfd_DaemonCtxRef_Object *ctx;
    PyObject *cbs;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                &ctx, &cbs)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *) ctx)) {
        PyErr_Format(PyExc_TypeError,
            "dx argument must be a " CONFD_PY_MODULE ".dp.DaemonCtxRef");
        return NULL;
    }

    py_dp_daemon_extra_t *extra = GET_DAEMON_EXTRA(ctx);

    if (extra->db_cb_ctx != NULL) {
        PyErr_Format(PyExc_Exception,
            "Can only handle one db callback");
        return NULL;
    }

    struct confd_db_cbs dbcb;
    memset(&dbcb, 0, sizeof(dbcb));

    if (PyObject_HasAttrString(cbs, "cb_candidate_commit")) {
        CHECK_CB_MTH(cbs, "cb_candidate_commit", 3);
        dbcb.candidate_commit = _db_candidate_commit_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_candidate_confirming_commit")) {
        CHECK_CB_MTH(cbs, "cb_candidate_confirming_commit", 2);
        dbcb.candidate_confirming_commit = _db_candidate_confirming_commit_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_candidate_reset")) {
        CHECK_CB_MTH(cbs, "cb_candidate_reset", 2);
        dbcb.candidate_reset = _db_candidate_reset_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_candidate_chk_not_modified")) {
        CHECK_CB_MTH(cbs, "cb_candidate_chk_not_modified", 2);
        dbcb.candidate_chk_not_modified = _db_candidate_chk_not_modified_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_candidate_rollback_running")) {
        CHECK_CB_MTH(cbs, "cb_candidate_rollback_running", 2);
        dbcb.candidate_rollback_running = _db_candidate_rollback_running_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_candidate_validate")) {
        CHECK_CB_MTH(cbs, "cb_candidate_validate", 2);
        dbcb.candidate_validate = _db_candidate_validate_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_add_checkpoint_running")) {
        CHECK_CB_MTH(cbs, "cb_add_checkpoint_running", 2);
        dbcb.add_checkpoint_running = _db_add_checkpoint_running_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_del_checkpoint_running")) {
        CHECK_CB_MTH(cbs, "cb_del_checkpoint_running", 2);
        dbcb.del_checkpoint_running = _db_del_checkpoint_running_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_activate_checkpoint_running")) {
        CHECK_CB_MTH(cbs, "cb_activate_checkpoint_running", 2);
        dbcb.activate_checkpoint_running = _db_activate_checkpoint_running_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_copy_running_to_startup")) {
        CHECK_CB_MTH(cbs, "cb_copy_running_to_startup", 2);
        dbcb.copy_running_to_startup = _db_copy_running_to_startup_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_running_chk_not_modified")) {
        CHECK_CB_MTH(cbs, "cb_running_chk_not_modified", 2);
        dbcb.running_chk_not_modified = _db_running_chk_not_modified_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_lock")) {
        CHECK_CB_MTH(cbs, "cb_lock", 3);
        dbcb.lock = _db_lock_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_unlock")) {
        CHECK_CB_MTH(cbs, "cb_unlock", 3);
        dbcb.unlock = _db_unlock_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_lock_partial")) {
        CHECK_CB_MTH(cbs, "cb_lock_partial", 5);
        dbcb.lock_partial = _db_lock_partial_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_unlock_partial")) {
        CHECK_CB_MTH(cbs, "cb_unlock_partial", 4);
        dbcb.unlock_partial = _db_unlock_partial_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_delete_config")) {
        CHECK_CB_MTH(cbs, "cb_delete_config", 3);
        dbcb.delete_config = _db_delete_config_cb;
    }

    CHECK_CONFD_ERR(confd_register_db_cb(ctx->ctx, &dbcb) );

    Py_INCREF(cbs);
    extra->db_cb_ctx = cbs;

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_db_set_timeout, EXT_API_FUN_DP_DB_SET_TIMEOUT)
{
    static char *kwlist[] = {
        "dbx",
        "timeout_secs",
        NULL
    };
    confdDbCtxRef *dbx = NULL;
    int timeout;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oi", kwlist,
                &dbx, &timeout)) {
        return NULL;
    }

    if (!isConfdDbCtxRef((PyObject *)dbx)) {
        PyErr_Format(PyExc_TypeError,
                     "dbx argument must be a "
                      CONFD_PY_MODULE ".dp.DbCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_db_set_timeout(dbx->dbx, timeout));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_db_seterr, EXT_API_FUN_DP_DB_SETERR)
{
    static char *kwlist[] = {
        "dbx",
        "errstr",
        NULL
    };
    confdDbCtxRef *dbx;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Os", kwlist,
                &dbx, &errstr)) {
        return NULL;
    }

    if (!isConfdDbCtxRef((PyObject *)dbx)) {
        PyErr_Format(PyExc_TypeError,
                     "dbx argument must be a "
                      CONFD_PY_MODULE ".dp.DbCtxRef instance");
        return NULL;
    }

    CONFD_EXEC(confd_db_seterr(dbx->dbx, "%s", errstr));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_db_seterr_extended, EXT_API_FUN_DP_DB_SETERR_EXTENDED)
{
    static char *kwlist[] = {
        "dbx",
        "code",
        "apptag_ns",
        "apptag_tag",
        "errstr",
        NULL
    };
    confdDbCtxRef *dbx;
    int code;
    u_int32_t apptag_ns;
    u_int32_t apptag_tag;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OiIIs", kwlist,
                &dbx, &code, &apptag_ns, &apptag_tag, &errstr)) {
        return NULL;
    }

    if (!isConfdDbCtxRef((PyObject *)dbx)) {
        PyErr_Format(PyExc_TypeError,
                     "dbx argument must be a "
                      CONFD_PY_MODULE ".dp.DbCtxRef instance");
        return NULL;
    }

    CONFD_EXEC(confd_db_seterr_extended(
                dbx->dbx, code, apptag_ns, apptag_tag, "%s", errstr));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_db_seterr_extended_info, EXT_API_FUN_DP_DB_SETERR_EXTENDED_INFO)
{
    static char *kwlist[] = {
        "dbx",
        "code",
        "apptag_ns",
        "apptag_tag",
        "error_info",
        "errstr",
        NULL
    };

    confdDbCtxRef *dbx;
    int code;
    u_int32_t apptag_ns;
    u_int32_t apptag_tag;
    PyObject *error_info;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OiIIOs", kwlist,
                &dbx, &code, &apptag_ns, &apptag_tag, &error_info, &errstr)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)dbx)) {
        PyErr_Format(PyExc_TypeError,
            "tctx argument must be a "
            CONFD_PY_MODULE ".dp.DbCtxRef instance");
        return NULL;
    }

    if (!PyList_Check(error_info)) {
        PyErr_Format(PyExc_TypeError,
            "error_info argument must be a list of "
            CONFD_PY_MODULE ".TagValue instances");
        return NULL;
    }

    if (PyList_Size(error_info) < 1) {
        PyErr_Format(PyExc_TypeError,
            "Number of error_info must be at least 1");
        return NULL;
    }

    py_confd_tag_value_t_list_t tv = {0};
    if (!alloc_py_confd_tag_value_t_list(error_info, &tv, "error_info")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_db_seterr_extended_info(
                dbx->dbx, code, apptag_ns, apptag_tag,
                tv.list, tv.size, "%s", errstr),
            free_py_confd_tag_value_t_list(&tv));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_aaa_reload, EXT_API_FUN_DP_AAA_RELOAD)
{
    static char *kwlist[] = {
        "tctx",
        NULL
    };

    confdTransCtxRef *ctx;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &ctx)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError,
            "tctx argument must be a "
            CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CONFD_EXEC(confd_aaa_reload(ctx->tc));

    Py_RETURN_NONE;
}

/* ************************************************************************* */
/* confd_register_auth_cb                                                    */
/*
    struct confd_auth_cb {
        int (*auth)(struct confd_auth_ctx *actx);
    };
*/
/* ************************************************************************* */

/* ------------------------------------------------------------------------- */

int _db_abc_auth_cb(struct confd_auth_ctx *actx)
{
    if (g_db_auth_cb == NULL) {
        /* Should never happen */
        confd_auth_seterr(actx, "Internal, g_db_auth_cb == NULL");
        return CONFD_ERR;
    }

    int ret = CONFD_ERR;

    confdAuthCtxRef *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    ctxRef = (confdAuthCtxRef*)newConfdAuthCtxRef(actx);
    if (ctxRef == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_auth")) == NULL) goto decref;

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = g_db_auth_cb;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, ctxRef, NULL);

    if (pyret == NULL) {
        _confd_py_auth_seterr_fetch(actx, "cb_auth");
        ret = CONFD_ERR;
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_auth_seterr(
                actx, "Python cb_auth error. Invalid return type.");
        ret = CONFD_ERR;
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);

    return ret;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_auth_cb, EXT_API_FUN_DP_REGISTER_AUTH_CB)
{
    static char *kwlist[] = {
        "dx",
        "acb",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;
    PyObject *cbs;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist, &ctx, &cbs)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    CHECK_CB_MTH(cbs, "cb_auth", 2);

    pthread_mutex_lock(&g_db_auth_cb_lock);

    if (g_db_auth_cb != NULL) {
        PyErr_Format(PyExc_Exception,
            "Can only handle one auth callback per VM");
        pthread_mutex_unlock(&g_db_auth_cb_lock);
        return NULL;
    }

    pthread_mutex_unlock(&g_db_auth_cb_lock);

    struct confd_auth_cb acb;
    memset(&acb, 0, sizeof(acb));

    acb.auth = _db_abc_auth_cb;

    CHECK_CONFD_ERR(confd_register_auth_cb(ctx->ctx, &acb));

    Py_INCREF(cbs);
    g_db_auth_cb = cbs;

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_auth_seterr, EXT_API_FUN_DP_AUTH_SETERR)
{
    static char *kwlist[] = {
        "actx",
        "errstr",
        NULL
    };

    confdAuthCtxRef *actx;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Os", kwlist,
                &actx, &errstr)) {
        return NULL;
    }

    if (!isConfdAuthCtxRef((PyObject *)actx)) {
        PyErr_Format(PyExc_TypeError, "actx argument must be a "
                     CONFD_PY_MODULE ".dp.AuthCtxRef instance");
        return NULL;
    }

    CONFD_EXEC(confd_auth_seterr(actx->actx, "%s", errstr));

    Py_RETURN_NONE;
}

/* ************************************************************************* */
/* confd_register_authorization_cb                                           */
/*
  struct confd_authorization_cbs {
        int cmd_filter;
        int data_filter;
        int (*chk_cmd_access)(struct confd_authorization_ctx *actx,
                              char **cmdtokens, int ntokens, int cmdop);
        int (*chk_data_access)(struct confd_authorization_ctx *actx,
                               u_int32_t hashed_ns, confd_hkeypath_t *hkp,
                               int dataop, int how);
  };
*/
/* ************************************************************************* */

/* ------------------------------------------------------------------------- */

static int _dp_chk_cmd_access_cb(struct confd_authorization_ctx *actx,
                                 char **cmdtokens, int ntokens, int cmdop)
{
    py_dp_daemon_extra_t *extra = GET_AUTHORIZATION_DAEMON_EXTRA(actx);

    if (extra == NULL) {
        /* Should never happen */
        confd_error_seterr(actx->uinfo, "Internal, extra == NULL");
        return CONFD_ERR;
    }

    if (extra->authorization_ctx == NULL) {
        /* Should never happen */
        confd_error_seterr(actx->uinfo,
            "Internal, extra->authorization_ctx == NULL");
        return CONFD_ERR;
    }

    int ret = CONFD_ERR;

    confdAuthorizationCtxRef *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pytokens = NULL;
    PyObject *pycmdop = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    ctxRef = (confdAuthorizationCtxRef*)newConfdAuthorizationCtxRef(actx);
    if (ctxRef == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_chk_cmd_access")) == NULL)
        goto decref;
    if ((pycmdop = PyInt_FromLong(cmdop)) == NULL) goto decref;

    pytokens = PyList_New(ntokens);
    int i;
    for (i = 0; i < ntokens; i++) {
        PyList_SetItem(pytokens, i, PyString_FromString(cmdtokens[i]));
    }

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = extra->authorization_ctx;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxRef, pytokens, pycmdop, NULL);

    if (pyret == NULL) {
        _confd_py_error_seterr_fetch(actx->uinfo, "cb_chk_cmd_access");
        ret = CONFD_ERR;
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_error_seterr(actx->uinfo,
                "Python cb_chk_cmd_access error. Invalid return type.");
        ret = CONFD_ERR;
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(pycmdop);
    Py_XDECREF(pytokens);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);

    return ret;
}

/* ------------------------------------------------------------------------- */

static int _dp_chk_data_access_cb(struct confd_authorization_ctx *actx,
                                  u_int32_t hashed_ns, confd_hkeypath_t *hkp,
                                  int dataop, int how)
{
    py_dp_daemon_extra_t *extra = GET_AUTHORIZATION_DAEMON_EXTRA(actx);

    if (extra == NULL) {
        /* Should never happen */
        confd_error_seterr(actx->uinfo, "Internal, extra == NULL");
        return CONFD_ERR;
    }

    if (extra->authorization_ctx == NULL) {
        /* Should never happen */
        confd_error_seterr(actx->uinfo,
            "Internal, extra->authorization_ctx == NULL");
        return CONFD_ERR;
    }

    int ret = CONFD_ERR;

    confdAuthorizationCtxRef *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pyhns = NULL;
    PyObject *pykpref = NULL;
    PyObject *pydataop = NULL;
    PyObject *pyhow = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    ctxRef = (confdAuthorizationCtxRef*)newConfdAuthorizationCtxRef(actx);
    if (ctxRef == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_chk_data_access")) == NULL)
        goto decref;
    if (hkp) {
        if ((pykpref = newConfdHKeypathRefNoAutoFree(hkp)) == NULL) goto decref;
    }
    else {
        Py_INCREF(Py_None);
        pykpref = Py_None;
    }
    if ((pyhns = PyInt_FromLong(hashed_ns)) == NULL) goto decref;
    if ((pydataop = PyInt_FromLong(dataop)) == NULL) goto decref;
    if ((pyhow = PyInt_FromLong(how)) == NULL) goto decref;

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = extra->authorization_ctx;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxRef, pyhns, pykpref, pydataop, pyhow, NULL);

    if (pyret == NULL) {
        _confd_py_error_seterr_fetch(actx->uinfo, "cb_chk_data_access");
        ret = CONFD_ERR;
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_error_seterr(actx->uinfo,
                "Python cb_chk_data_access error. Invalid return type.");
        ret = CONFD_ERR;
    }

decref:

    unrefConfdHKeypathRef(pykpref);
    Py_XDECREF(pyret);
    Py_XDECREF(pyhns);
    Py_XDECREF(pykpref);
    Py_XDECREF(pydataop);
    Py_XDECREF(pyhow);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);

    return ret;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_authorization_cb,
            EXT_API_FUN_DP_REGISTER_AUTHORIZATION_CB)
{
    static char *kwlist[] = {
        "dx",
        "acb",
        "cmd_filter",
        "data_filter",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;
    PyObject *cbs;
    int cmd_filter = 0;
    int data_filter = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO|ii", kwlist,
                &ctx, &cbs, &cmd_filter, &data_filter)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    py_dp_daemon_extra_t *extra = GET_DAEMON_EXTRA(ctx);

    if (extra->authorization_ctx != NULL) {
        PyErr_Format(PyExc_Exception,
            "Can only handle one authorization callback");
        return NULL;
    }

    struct confd_authorization_cbs acb;
    memset(&acb, 0, sizeof(acb));

    acb.cmd_filter = cmd_filter;
    acb.data_filter = data_filter;

    if (PyObject_HasAttrString(cbs, "cb_chk_cmd_access")) {
        CHECK_CB_MTH(cbs, "cb_chk_cmd_access", 4);
        acb.chk_cmd_access = _dp_chk_cmd_access_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_chk_data_access")) {
        CHECK_CB_MTH(cbs, "cb_chk_data_access", 6);
        acb.chk_data_access = _dp_chk_data_access_cb;
    }

    CHECK_CONFD_ERR(confd_register_authorization_cb(ctx->ctx, &acb));

    Py_INCREF(cbs);
    extra->authorization_ctx = cbs;

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_access_reply_result, EXT_API_FUN_DP_ACCESS_REPLY_RESULT)
{
    static char *kwlist[] = {
        "actx",
        "result",
        NULL
    };
    confdAuthorizationCtxRef *actx = NULL;
    int result;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oi", kwlist,
                &actx, &result)) {
        return NULL;
    }

    if (!isConfdAuthorizationCtxRef((PyObject *)actx)) {
        PyErr_Format(PyExc_TypeError,
                     "actx argument must be a "
                      CONFD_PY_MODULE ".dp.AuthorizationCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_access_reply_result(actx->actx, result));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_authorization_set_timeout,
            EXT_API_FUN_DP_AUTHORIZATION_SET_TIMEOUT)
{
    static char *kwlist[] = {
        "actx",
        "timeout_secs",
        NULL
    };
    confdAuthorizationCtxRef *actx = NULL;
    int timeout;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oi", kwlist,
                &actx, &timeout)) {
        return NULL;
    }

    if (!isConfdAuthorizationCtxRef((PyObject *)actx)) {
        PyErr_Format(PyExc_TypeError,
                     "actx argument must be a "
                      CONFD_PY_MODULE ".dp.AuthorizationCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_authorization_set_timeout(actx->actx, timeout));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */
/*
   struct confd_error_cb {
       int error_types;
       void (*format_error)(struct confd_user_info *uinfo,
                            struct confd_errinfo *errinfo,
                            char *default_msg);
   };

 where error_types is

      CONFD_ERRTYPE_VALIDATION
      CONFD_ERRTYPE_BAD_VALUE
      CONFD_ERRTYPE_CLI
      CONFD_ERRTYPE_MISC
      CONFD_ERRTYPE_OPERATION
      CONFD_ERRTYPE_NCS

      OR:ed together

      The callback then takes the confd_errinfo
      struct confd_errinfo {
          int type;  : CONFD_ERRTYPE_XXX
          union {
              struct confd_errinfo_validation validation;
              struct confd_errinfo_bad_value bad_value;
              struct confd_errinfo_cli cli;
              struct confd_errinfo_misc misc;
              struct confd_errinfo_ncs ncs;
          } info;
     };

     Depending on the type, there are different structs to be used:

     enum confd_errinfo_ptype {
        CONFD_ERRINFO_KEYPATH,
     CONFD_ERRINFO_STRING
     };

     struct confd_errinfo_param {
         enum confd_errinfo_ptype type;
             union {
             confd_hkeypath_t *kp;
             char *str;
             } val;
     };

        struct confd_errinfo_bad_value {
            int code;
            int n_params;
            struct confd_errinfo_param *params;
        };

        struct confd_errinfo_cli {
            int code;
            int n_params;
            struct confd_errinfo_param *params;
        };

        struct confd_errinfo_misc {
            int code;
            int n_params;
            struct confd_errinfo_param *params;
        };

        struct confd_errinfo_ncs {
            int code;
            int n_params;
            struct confd_errinfo_param *params;
        };

*/


#define MAKE_ERRINFO_GENERAL_IMPL(FNAME, SNAME)                                \
static void FNAME(PyObject *d, struct SNAME *sp)                               \
{                                                                              \
    PyObject *l = PyList_New(sp->n_params);                                    \
    PYDICT_SET_ITEM(d, "code", PyInt_FromLong(sp->code));                      \
    for (int i = 0; i < sp->n_params; i++) {                                   \
        PyObject *p = PyDict_New();                                            \
        int param_type = sp->params[i].type;                                   \
        PYDICT_SET_ITEM(p, "ptype", PyInt_FromLong(param_type));               \
        if (param_type == CONFD_ERRINFO_STRING) {                              \
            PYDICT_SET_ITEM(p, "string",                                       \
                            PyString_FromString(sp->params[i].val.str));       \
        } else {                                                               \
            confd_hkeypath_t *hkp = sp->params[i].val.kp;                      \
            PYDICT_SET_ITEM(p, "kp", _confd_hkeypath2PyString(hkp, hkp->len)); \
        }                                                                      \
        PyList_SetItem(l, i, p);                                               \
    }                                                                          \
    PYDICT_SET_ITEM(d, "params", l);                                           \
}

MAKE_ERRINFO_GENERAL_IMPL(build_bad_value_errinfo, confd_errinfo_bad_value);
MAKE_ERRINFO_GENERAL_IMPL(build_cli_errinfo, confd_errinfo_cli);
MAKE_ERRINFO_GENERAL_IMPL(build_misc_errinfo, confd_errinfo_misc);
#ifdef CONFD_PY_PRODUCT_NCS
MAKE_ERRINFO_GENERAL_IMPL(build_ncs_errinfo, confd_errinfo_ncs);
#endif
#undef MAKE_ERRINFO_GENERAL_IMPL


static void build_validation_errinfo(
    PyObject *d, struct confd_errinfo_validation *validation)
{
    confd_hkeypath_t *hkp;

    PyObject *p = PyDict_New();
    switch (validation->code) {
    case CONFD_ERR_NOTSET:
        /* The element given by kp is not set */
        hkp = validation->info.notset.kp;
        PYDICT_SET_ITEM(p, "kp", _confd_hkeypath2PyString(hkp, hkp->len));
        break;
    case CONFD_ERR_TOO_FEW_ELEMS:
        /* kp has n instances, must be at least min */
        hkp = validation->info.too_few_elems.kp;
        PYDICT_SET_ITEM(p, "kp", _confd_hkeypath2PyString(hkp, hkp->len));
        PYDICT_SET_ITEM(p, "n",
                        PyInt_FromLong(validation->info.too_few_elems.n));
        PYDICT_SET_ITEM(p, "min",
                        PyInt_FromLong(validation->info.too_few_elems.min));
        break;
    case CONFD_ERR_TOO_MANY_ELEMS:
        /* kp has n instances, must be at most max */
        hkp = validation->info.too_many_elems.kp;
        PYDICT_SET_ITEM(p, "kp", _confd_hkeypath2PyString(hkp, hkp->len));
        PYDICT_SET_ITEM(p, "n",
                        PyInt_FromLong(validation->info.too_many_elems.n));
        PYDICT_SET_ITEM(p, "max",
                        PyInt_FromLong(validation->info.too_many_elems.max));
        break;
    case CONFD_ERR_NON_UNIQUE:
        /* the elements given by kps1 have the same set
           of values vals as the elements given by kps2
           (kps1, kps2, and vals point to n_elems long arrays) */
        /* n_values is skipped */
        hkp = validation->info.non_unique.kps1;
        PYDICT_SET_ITEM(p, "kps1", _confd_hkeypath2PyString(hkp, hkp->len));
        hkp = validation->info.non_unique.kps2;
        PYDICT_SET_ITEM(p, "kps2", _confd_hkeypath2PyString(hkp, hkp->len));
        int i, n_elems;
        n_elems = validation->info.non_unique.n_elems;
        PyObject *el = PyList_New(n_elems);
        for(i = 0; i < n_elems; i++) {
            PyList_SetItem(el, i, newConfdValue(
                               &(validation->info.non_unique.vals[i])));
        }
        PYDICT_SET_ITEM(p, "vals", el);
        break;
    case CONFD_ERR_BAD_KEYREF:
        /* the element given by kp references
           the non-existing element given by ref
           Note: 'ref' may be NULL or have key elements without values
           (ref->v[n][0].type == C_NOEXISTS) if it cannot be instantiated */
        hkp = validation->info.bad_keyref.kp;
        PYDICT_SET_ITEM(p, "kp", _confd_hkeypath2PyString(hkp, hkp->len));
        hkp = validation->info.bad_keyref.ref;
        PYDICT_SET_ITEM(p, "ref", _confd_hkeypath2PyString(hkp, hkp->len));
        break;
    case CONFD_ERR_UNSET_CHOICE:
        /* the mandatory 'choice' statement choice in the
           container kp does not have a selected 'case' */
        hkp = validation->info.unset_choice.kp;
        PYDICT_SET_ITEM(p, "kp", _confd_hkeypath2PyString(hkp, hkp->len));
        PYDICT_SET_ITEM(p, "choice",
                        newConfdValue(validation->info.unset_choice.choice));
        break;
    case CONFD_ERR_MUST_FAILED:
        /* the 'must' expression expr for element kp is not satisfied
           - error_message and and error_app_tag are NULL if not given
           in the 'must'; val points to the value of the element if it
           has one, otherwise it is NULL */
        hkp = validation->info.must_failed.kp;
        PYDICT_SET_ITEM(p, "kp", _confd_hkeypath2PyString(hkp, hkp->len));
        PYDICT_SET_ITEM(p, "expr",
                        PyString_FromString(
                            validation->info.must_failed.expr));
        if (validation->info.must_failed.error_message != NULL) {
            PYDICT_SET_ITEM(p, "error_message",
                            PyString_FromString(
                                validation-> info.must_failed.error_message));
        } else {
            PyDict_SetItemString(p, "error_message", Py_None);
        }
        if (validation->info.must_failed.error_app_tag != NULL) {
            PYDICT_SET_ITEM(p, "error_app_tag",
                            PyString_FromString(
                                validation->info.must_failed.error_app_tag));
        } else {
            PyDict_SetItemString(p, "error_app_tag", Py_None);
        }
        if (validation->info.must_failed.val != NULL) {
            PYDICT_SET_ITEM(p, "val",
                            newConfdValue(validation->info.must_failed.val));
        } else {
            PyDict_SetItemString(p, "val", Py_None);
        }
        break;
    case  CONFD_ERR_MISSING_INSTANCE:
        /* the element kp has the instance-identifier value instance,
           which doesn't exist, but require-instance is 'true' */
        hkp = validation->info.missing_instance.kp;
        PYDICT_SET_ITEM(p, "kp", _confd_hkeypath2PyString(hkp, hkp->len));
        hkp = validation->info.missing_instance.instance;
        PYDICT_SET_ITEM(p, "instance", _confd_hkeypath2PyString(hkp, hkp->len));
        break;
    case CONFD_ERR_INVALID_INSTANCE:
        /* the element kp has the instance-identifier value instance,
           which doesn't conform to the specified path filters */
        hkp = validation->info.invalid_instance.kp;
        PYDICT_SET_ITEM(p, "kp", _confd_hkeypath2PyString(hkp, hkp->len));
        hkp = validation->info.invalid_instance.instance;
        PYDICT_SET_ITEM(p, "instance", _confd_hkeypath2PyString(hkp, hkp->len));
        break;
    case CONFD_ERR_STALE_INSTANCE:
        /* the element kp has the instance-identifier value instance,
           which has stale data after upgrading, and require-instance is
           'true' */
        hkp = validation->info.stale_instance.kp;
        PYDICT_SET_ITEM(p, "kp", _confd_hkeypath2PyString(hkp, hkp->len));
        hkp = validation->info.stale_instance.instance;
        PYDICT_SET_ITEM(p, "instance", _confd_hkeypath2PyString(hkp, hkp->len));
        break;
    case CONFD_ERR_POLICY_FAILED:
        /* the expression for a configuration policy rule evaluated to
           'false' - error_message is the associated error message */
        PYDICT_SET_ITEM(p, "error_message",
                        PyString_FromString(
                            validation->info.policy_failed.error_message));
        break;

    case CONFD_ERR_POLICY_COMPILATION_FAILED:
        /* the XPath expression expr, for the configuration policy
           rule with key name, could not be compiled due to msg */
        PYDICT_SET_ITEM(p, "name",
                        PyString_FromString(
                            validation->info.policy_compilation_failed.name));
        PYDICT_SET_ITEM(p, "expr",
                        PyString_FromString(
                            validation->info.policy_compilation_failed.expr));
        PYDICT_SET_ITEM(p, "msg",
                        PyString_FromString(
                            validation->info.policy_compilation_failed.msg));
        break;
    case CONFD_ERR_POLICY_EVALUATION_FAILED:
        /* the expression expr, for the configuration policy rule
           with key name, failed XPath evaluation due to msg */
        PYDICT_SET_ITEM(p, "name",
                        PyString_FromString(
                            validation->info.policy_compilation_failed.name));
        PYDICT_SET_ITEM(p, "expr",
                        PyString_FromString(
                            validation->info.policy_compilation_failed.expr));
        PYDICT_SET_ITEM(p, "msg",
                        PyString_FromString(
                            validation->info.policy_compilation_failed.msg));
        break;
    }

    PYDICT_SET_ITEM(d, "param", p);
    PYDICT_SET_ITEM(d, "code", PyInt_FromLong(validation->code));
    /* CONFD_ERRTYPE_OPERATION has no test and tctx is NULL */
    if (validation->tctx != NULL) {
        PYDICT_SET_ITEM(d, "test", PyInt_FromLong(validation->test));
        PYDICT_SET_ITEM(d, "ctx", newConfdTransCtxRef(validation->tctx));
    }
}

static void _cbs_format_error_cb(struct confd_user_info *uinfo,
                                struct confd_errinfo *errinfo,
                                char *default_msg)
{
    PyObject* cbs = NULL;
    PyObject *uiref = NULL;
    PyObject *dmref = NULL;
    PyObject *cbname = NULL;


    if (g_error_cb == NULL) {
        /* Should never happen */
        confd_error_seterr(uinfo, "Internal, g_error_cb == NULL");
    }

    PyGILState_STATE gstate = PyGILState_Ensure();

    if ((uiref = newConfdUserInfo(uinfo)) == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_format_error")) == NULL) goto decref;
    if ((dmref = PyString_FromString(default_msg)) == NULL) goto decref;

    // Depending on the type of the errinfo, we build different types of dicts
    PyObject *eidict = PyDict_New();
    PYDICT_SET_ITEM(eidict, "type", PyInt_FromLong(errinfo->type));

    if (errinfo->type == CONFD_ERRTYPE_BAD_VALUE) {
        build_bad_value_errinfo(eidict, &(errinfo->info.bad_value));
    }

    if (errinfo->type == CONFD_ERRTYPE_CLI) {
        build_cli_errinfo(eidict, &(errinfo->info.cli));
    }

    if (errinfo->type == CONFD_ERRTYPE_MISC) {
        build_misc_errinfo(eidict, &(errinfo->info.misc));
    }

#ifdef CONFD_PY_PRODUCT_NCS
    if (errinfo->type == CONFD_ERRTYPE_NCS) {
        build_ncs_errinfo(eidict, &(errinfo->info.ncs));
    }
#endif /* CONFD_PY_PRODUCT_NCS */

    if (errinfo->type == CONFD_ERRTYPE_VALIDATION ||
        errinfo->type == CONFD_ERRTYPE_OPERATION) {
        build_validation_errinfo(eidict, &(errinfo->info.validation));
    }

    /* Get the callback function */
    cbs = g_error_cb;

    PyObject_CallMethodObjArgs(cbs, cbname, uiref, eidict, dmref, NULL);

decref:

    Py_XDECREF(cbname);
    Py_XDECREF(uiref);
    Py_XDECREF(dmref);

    PyGILState_Release(gstate);

}


EXT_API_FUN(_dp_register_error_cb, EXT_API_FUN_DP_REGISTER_ERROR_CB)
{
    static char *kwlist[] = {
        "dx",
        "errortypes",
        "ecbs",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;
    PyObject *cbs;
    int error_types = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OiO", kwlist,
                                     &ctx, &error_types, &cbs)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    pthread_mutex_lock(&g_error_cb_lock);

    if (g_error_cb != NULL) {
        PyErr_Format(PyExc_Exception,
            "Can only handle one error format callback per VM");
        pthread_mutex_unlock(&g_error_cb_lock);

        return NULL;
    }

    pthread_mutex_unlock(&g_error_cb_lock);

    struct confd_error_cb ecb;
    memset(&ecb, 0, sizeof(ecb));
    if (PyObject_HasAttrString(cbs, "cb_format_error")) {
        CHECK_CB_MTH(cbs, "cb_format_error", 4); // 3 + self
        ecb.error_types = error_types;
        ecb.format_error = _cbs_format_error_cb;
    } else {
        PyErr_Format(PyExc_TypeError,
                     "Callback object must implement the method "
                     "cb_format_error");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_register_error_cb(ctx->ctx, &ecb));

    Py_INCREF(cbs);
    g_error_cb = cbs;

    Py_RETURN_NONE;
}


EXT_API_FUN(_dp_error_seterr, EXT_API_FUN_DP_ERROR_SETERR)
{
    static char *kwlist[] = {
        "uinfo",
        "errstr",
        NULL
    };

    confdUserInfo *uinfo;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Os", kwlist,
                &uinfo, &errstr)) {
        return NULL;
    }

    if (!isConfdUserInfo((PyObject *) uinfo)) {
        PyErr_Format(PyExc_TypeError,
            "uinfo argument must be a "
            CONFD_PY_MODULE ".UserInfo instance");
        return NULL;
    }

    CONFD_EXEC(confd_error_seterr(uinfo->uinfo, "%s", errstr));

    Py_RETURN_NONE;
}


/* ************************************************************************* */
/* confd_register_usess_cb                                                   */
/*
    struct confd_usess_cbs {
               void (*start)(struct confd_daemon_ctx *dx,
                             struct confd_user_info *uinfo);
               void (*stop)(struct confd_daemon_ctx *dx,
                            struct confd_user_info *uinfo);
    };
*/
/* ************************************************************************* */

static void _dp_usess_generic_cb(struct confd_daemon_ctx *dx,
                              struct confd_user_info *uinfo,
                              const char *py_mth_name)
{
    py_dp_daemon_extra_t *extra = (py_dp_daemon_extra_t*)dx->d_opaque;

    if (extra == NULL) {
        /* Should never happen */
        confd_error_seterr(uinfo, "Internal, extra == NULL");
        return;
    }

    if (extra->usess_ctx == NULL) {
        /* Should never happen */
        confd_error_seterr(uinfo, "Internal, extra->usess_ctx == NULL");
        return;
    }

    PyObject *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pyuinfo = NULL;
    PyObject *pyret = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    ctxRef = (PyObject*)PyConfd_DaemonCtxRef_New_NoAutoFree(dx);
    if (ctxRef == NULL) goto decref;
    if ((cbname = PyString_FromString(py_mth_name)) == NULL) goto decref;
    if ((pyuinfo = newConfdUserInfo(uinfo)) == NULL) goto decref;

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = extra->usess_ctx;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, ctxRef, pyuinfo, NULL);

    if (pyret == NULL) {
        _confd_py_error_seterr_fetch(uinfo, py_mth_name);
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(pyuinfo);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);
}

/* ------------------------------------------------------------------------- */

static void _dp_usess_start_cb(struct confd_daemon_ctx *dx,
                               struct confd_user_info *uinfo)
{
    _dp_usess_generic_cb(dx, uinfo, "cb_start");
}
/* ------------------------------------------------------------------------- */

static void _dp_usess_stop_cb(struct confd_daemon_ctx *dx,
                               struct confd_user_info *uinfo)
{
    _dp_usess_generic_cb(dx, uinfo, "cb_stop");
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_usess_cb, EXT_API_FUN_DP_REGISTER_USESS_CB)
{
    static char *kwlist[] = {
        "dx",
        "ucb",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;
    PyObject *cbs;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist, &ctx, &cbs)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    py_dp_daemon_extra_t *extra = GET_DAEMON_EXTRA(ctx);

    if (extra->usess_ctx != NULL) {
        PyErr_Format(PyExc_Exception,
            "Can only handle one usess callback");
        return NULL;
    }

    struct confd_usess_cbs ucb;
    memset(&ucb, 0, sizeof(ucb));

    if (PyObject_HasAttrString(cbs, "cb_start")) {
        CHECK_CB_MTH(cbs, "cb_start", 3);
        ucb.start = _dp_usess_start_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_stop")) {
        CHECK_CB_MTH(cbs, "cb_stop", 3);
        ucb.stop = _dp_usess_stop_cb;
    }

    CHECK_CONFD_ERR(confd_register_usess_cb(ctx->ctx, &ucb));

    Py_INCREF(cbs);
    extra->usess_ctx = cbs;

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_install_crypto_keys, EXT_API_FUN_DP_INSTALL_CRYPTO_KEYS)
{
    static char *kwlist[] = {
        "dtx",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &ctx)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dtx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_install_crypto_keys(ctx->ctx));

    Py_RETURN_NONE;
}

/* ************************************************************************* */
/* confd_register_notification_stream                                        */
/*
   struct confd_notification_stream_cbs {
               char streamname[MAX_STREAMNAME_LEN];
               int fd;
               int (*get_log_times)(
                   struct confd_notification_ctx *nctx);
               int (*replay)(struct confd_notification_ctx *nctx,
                             struct confd_datetime *start,
                             struct confd_datetime *stop);
               void *cb_opaque;
           };
*/
/* ************************************************************************* */

/* ------------------------------------------------------------------------- */

static int _dp_notification_get_log_times_cb(
        struct confd_notification_ctx *nctx)
{
    if (nctx->cb_opaque == NULL) {
        /* Should never happen */
        confd_notification_seterr(nctx, "Internal, cb_opaque == NULL");
        return CONFD_ERR;
    }

    PyObject *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;

    int ret = CONFD_ERR;

    PyGILState_STATE gstate = PyGILState_Ensure();

    ctxRef = (PyObject*)newConfdNotificationCtxRef(nctx);
    if (ctxRef == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_get_log_times")) == NULL)
        goto decref;

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = nctx->cb_opaque;

    pyret = PyObject_CallMethodObjArgs(cbs, cbname, ctxRef, NULL);

    if (pyret == NULL) {
        _confd_py_notification_seterr_fetch(nctx, "cb_get_log_times");
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_notification_seterr(
                nctx, "Python cb_get_log_times error. Invalid return type.");
        ret = CONFD_ERR;
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);

    PyGILState_Release(gstate);

    return ret;
}

/* ------------------------------------------------------------------------- */
static int _dp_notification_replay_cb(
        struct confd_notification_ctx *nctx,
        struct confd_datetime *start,
        struct confd_datetime *stop)
{
    if (nctx->cb_opaque == NULL) {
        /* Should never happen */
        confd_notification_seterr(nctx, "Internal, cb_opaque == NULL");
        return CONFD_ERR;
    }

    PyObject *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;
    PyObject *pystart = NULL;
    PyObject *pystop = NULL;

    int ret = CONFD_ERR;

    PyGILState_STATE gstate = PyGILState_Ensure();

    ctxRef = (PyObject*)newConfdNotificationCtxRef(nctx);
    if (ctxRef == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_replay")) == NULL)
        goto decref;
    if ((pystart = newConfdDateTime(start)) == NULL) goto decref;
    if (stop) {
        if ((pystop = newConfdDateTime(stop)) == NULL) goto decref;
    }
    else {
        Py_INCREF(Py_None);
        pystop = Py_None;
    }

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = nctx->cb_opaque;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxRef, pystart, pystop, NULL);

    if (pyret == NULL) {
        _confd_py_notification_seterr_fetch(nctx, "cb_replay");
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_notification_seterr(
                nctx, "Python cb_replay error. Invalid return type.");
        ret = CONFD_ERR;
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);
    Py_XDECREF(pystart);
    Py_XDECREF(pystop);

    PyGILState_Release(gstate);

    return ret;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_notification_stream,
            EXT_API_FUN_DP_REGISTER_NOTIFICATION_STREAM)
{
    static char *kwlist[] = {
        "dx",
        "ncbs",
        "sock",
        "streamname",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;
    PyObject *cbs;
    int fd;
    char *streamname;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOO&s", kwlist,
                &ctx, &cbs, sock_arg, &fd, &streamname)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    if (strlen(streamname) > MAX_STREAMNAME_LEN-1) {
        PyErr_Format(PyExc_Exception,
            "streamname argument can be at most %d characters in length",
            MAX_STREAMNAME_LEN-1);
        return NULL;
    }

    struct confd_notification_stream_cbs ncbs;
    memset(&ncbs, 0, sizeof(ncbs));

    if (PyObject_HasAttrString(cbs, "cb_get_log_times")) {
        CHECK_CB_MTH(cbs, "cb_get_log_times", 2);
        ncbs.get_log_times = _dp_notification_get_log_times_cb;
    }
    if (PyObject_HasAttrString(cbs, "cb_replay")) {
        CHECK_CB_MTH(cbs, "cb_replay", 4);
        ncbs.replay = _dp_notification_replay_cb;
    }

    ncbs.fd = fd;
    ncbs.cb_opaque = cbs;
    memcpy(ncbs.streamname, streamname, strlen(streamname) + 1);

    struct confd_notification_ctx *not_ctx;

    CHECK_CONFD_ERR(
            confd_register_notification_stream(ctx->ctx, &ncbs, &not_ctx));

    Py_INCREF(cbs);

    return newConfdNotificationCtxRef(not_ctx);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_send, EXT_API_FUN_DP_NOTIFICATION_SEND)
{
    static char *kwlist[] = {
        "nctx",
        "time",
        "values",
        NULL
    };

    confdNotificationCtxRef *nctx;
    confdDateTime *pytime;
    PyObject *values;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOO", kwlist,
                &nctx, &pytime, &values)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError, "nctx argument must be a "
                     CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    if (!isConfdDateTime((PyObject *)pytime)) {
        PyErr_Format(PyExc_TypeError, "time argument must be a "
                     CONFD_PY_MODULE ".DateTime instance");
        return NULL;
    }

    if (!(values == Py_None || PyList_Check(values))) {
        PyErr_Format(PyExc_TypeError,
            "values argument must be None or a list of "
            CONFD_PY_MODULE ".TagValue instances");
        return NULL;
    }

    py_confd_tag_value_t_list_t tv = {0};
    if (!alloc_py_confd_tag_value_t_list(values, &tv, "values")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_notification_send(
                nctx->nctx, &pytime->dt, tv.list, tv.size),
            free_py_confd_tag_value_t_list(&tv));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_send_path, EXT_API_FUN_DP_NOTIFICATION_SEND_PATH)
{
    static char *kwlist[] = {
        "nctx",
        "time",
        "values",
        "path",
        NULL
    };

    confdNotificationCtxRef *nctx;
    confdDateTime *pytime;
    PyObject *values;
    char *path;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOOO&", kwlist,
                                     &nctx, &pytime, &values,
                                     path_arg, &path)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError, "nctx argument must be a "
                     CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    if (!isConfdDateTime((PyObject *)pytime)) {
        PyErr_Format(PyExc_TypeError, "time argument must be a "
                     CONFD_PY_MODULE ".DateTime instance");
        return NULL;
    }

    if (!(values == Py_None || PyList_Check(values))) {
        PyErr_Format(PyExc_TypeError,
            "values argument must be None or a list of "
            CONFD_PY_MODULE ".TagValue instances");
        return NULL;
    }

    py_confd_tag_value_t_list_t tv = {0};
    if (!alloc_py_confd_tag_value_t_list(values, &tv, "values")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_notification_send_path(
                nctx->nctx, &pytime->dt, tv.list, tv.size, path),
            {
                free_py_confd_tag_value_t_list(&tv);
                free(path);
            });

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_reply_log_times,
            EXT_API_FUN_DP_NOTIFICATION_REPLY_LOG_TIMES)
{
    static char *kwlist[] = {
        "nctx",
        "creation",
        "aged",
        NULL
    };

    confdNotificationCtxRef *nctx;
    confdDateTime *creation;
    confdDateTime *aged;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOO", kwlist,
                &nctx, &creation, &aged)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError, "nctx argument must be a "
                     CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    if (!isConfdDateTime((PyObject *)creation)) {
        PyErr_Format(PyExc_TypeError, "creation argument must be a "
                     CONFD_PY_MODULE ".DateTime instance");
        return NULL;
    }

    struct confd_datetime *caged = NULL;

    if ((PyObject*)aged != Py_None) {
        if (!isConfdDateTime((PyObject *)aged)) {
            PyErr_Format(PyExc_TypeError, "aged argument must be a "
                        CONFD_PY_MODULE ".DateTime instance or None");
            return NULL;
        }
        caged = &aged->dt;
    }

    CHECK_CONFD_ERR(
            confd_notification_reply_log_times(
                nctx->nctx, &creation->dt, caged));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_replay_complete,
            EXT_API_FUN_DP_NOTIFICATION_REPLAY_COMPLETE)
{
    static char *kwlist[] = {
        "nctx",
        NULL
    };

    confdNotificationCtxRef *nctx;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &nctx)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError, "nctx argument must be a "
                     CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_notification_replay_complete(nctx->nctx));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_replay_failed,
            EXT_API_FUN_DP_NOTIFICATION_REPLAY_FAILED)
{
    static char *kwlist[] = {
        "nctx",
        NULL
    };

    confdNotificationCtxRef *nctx;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &nctx)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError, "nctx argument must be a "
                     CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_notification_replay_failed(nctx->nctx));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_set_fd, EXT_API_FUN_DP_NOTIFICATION_SET_FD)
{
    static char *kwlist[] = {
        "nctx",
        "sock",
        NULL
    };

    confdNotificationCtxRef *nctx;
    int sock;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO&", kwlist,
                &nctx, sock_arg, &sock)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError, "nctx argument must be a "
                     CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    CONFD_EXEC(confd_notification_set_fd(nctx->nctx, sock));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_seterr, EXT_API_FUN_DP_NOTIFICATION_SETERR)
{
    static char *kwlist[] = {
        "nctx",
        "errstr",
        NULL
    };
    confdNotificationCtxRef *nctx;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Os", kwlist,
                &nctx, &errstr)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError,
            "nctx argument must be a "
            CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    CONFD_EXEC(confd_notification_seterr(nctx->nctx, "%s", errstr));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_seterr_extended,
            EXT_API_FUN_DP_NOTIFICATION_SETERR_EXTENDED)
{
    static char *kwlist[] = {
        "nctx",
        "code",
        "apptag_ns",
        "apptag_tag",
        "errstr",
        NULL
    };
    confdNotificationCtxRef *nctx;
    int code;
    u_int32_t apptag_ns;
    u_int32_t apptag_tag;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OiIIs", kwlist,
                &nctx, &code, &apptag_ns, &apptag_tag, &errstr)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError,
            "nctx argument must be a "
            CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    CONFD_EXEC(confd_notification_seterr_extended(
                nctx->nctx, code, apptag_ns, apptag_tag, "%s", errstr));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_seterr_extended_info,
            EXT_API_FUN_DP_NOTIFICATION_SETERR_EXTENDED_INFO)
{
    static char *kwlist[] = {
        "nctx",
        "code",
        "apptag_ns",
        "apptag_tag",
        "error_info",
        "errstr",
        NULL
    };
    confdNotificationCtxRef *nctx;
    int code;
    u_int32_t apptag_ns;
    u_int32_t apptag_tag;
    PyObject *error_info;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OiIIOs", kwlist,
                &nctx, &code, &apptag_ns, &apptag_tag, &error_info, &errstr)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError,
            "nctx argument must be a "
            CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    if (!PyList_Check(error_info)) {
        PyErr_Format(PyExc_TypeError,
            "error_info argument must be a list of "
            CONFD_PY_MODULE ".TagValue instances");
        return NULL;
    }

    if (PyList_Size(error_info) < 1) {
        PyErr_Format(PyExc_TypeError,
            "Number of error_info must be at least 1");
        return NULL;
    }

    py_confd_tag_value_t_list_t tv = {0};
    if (!alloc_py_confd_tag_value_t_list(error_info, &tv, "error_info")) {
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_notification_seterr_extended_info(
                nctx->nctx, code, apptag_ns, apptag_tag,
                tv.list, tv.size, "%s", errstr),
            free_py_confd_tag_value_t_list(&tv));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_snmp_notification,
            EXT_API_FUN_DP_REGISTER_SNMP_NOTIFICATION)
{
    static char *kwlist[] = {
        "dx",
        "sock",
        "notify_name",
        "ctx_name",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;
    int s;
    char *notify_name;
    char *ctx_name;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO&ss", kwlist,
                &ctx, sock_arg, &s, &notify_name, &ctx_name)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    struct confd_notification_ctx *not_ctx;

    CHECK_CONFD_ERR(
            confd_register_snmp_notification(
                ctx->ctx, s, notify_name, ctx_name, &not_ctx));

    return newConfdNotificationCtxRef(not_ctx);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_send_snmp, EXT_API_FUN_DP_NOTIFICATION_SEND_SNMP)
{
    static char *kwlist[] = {
        "nctx",
        "notification",
        "varbinds",
        NULL
    };

    confdNotificationCtxRef *nctx;
    char *notification;
    PyObject *varbinds;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OsO", kwlist,
                &nctx, &notification, &varbinds)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError, "nctx argument must be a "
                     CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    struct confd_snmp_varbind *vbs = NULL;
    int vbc = 0;

    if (PyList_Check(varbinds) && PyList_Size(varbinds) > 0) {
        vbc = (int)PyList_Size(varbinds);
        vbs = (struct confd_snmp_varbind*)
                malloc(sizeof(struct confd_snmp_varbind) * vbc);

        int i;
        PyObject *o;
        for (i = 0; i < vbc; i++) {
            o = PyList_GetItem(varbinds, i);
            if (!isConfdSnmpVarbind((PyObject*)o)) {
                PyErr_Format(PyExc_TypeError,
                        "item %d of varbinds must be a "
                        CONFD_PY_MODULE ".SnmpVarbind instance", i);
                free(vbs);
                return NULL;
            }
            memcpy(&vbs[i], &((confdSnmpVarbind*)o)->vb,
                    sizeof(struct confd_snmp_varbind));
        }
    }
    else if (varbinds != Py_None) {
        PyErr_Format(PyExc_TypeError,
            "varbinds argument must be None or a list of "
            CONFD_PY_MODULE ".SnmpVarbind instances");
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(
            confd_notification_send_snmp(
                nctx->nctx, notification, vbs, vbc),
            free(vbs));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_send_snmp_inform,
            EXT_API_FUN_DP_NOTIFICATION_SEND_SNMP_INFORM)
{
    static char *kwlist[] = {
        "nctx",
        "notification",
        "varbinds",
        "cb_id",
        "ref",
        NULL
    };

    confdNotificationCtxRef *nctx;
    char *notification;
    PyObject *varbinds;
    PyObject *pycb_id;
    char *cb_id = NULL;
    int ref;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OsOOi", kwlist,
                &nctx, &notification, &varbinds, &pycb_id, &ref)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError, "nctx argument must be a "
                     CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    if (PyString_Check(pycb_id)) {
        cb_id = confd_py_string_strdup(pycb_id);
    } else if (pycb_id != Py_None) {
       PyErr_Format(PyExc_TypeError, "cb_id argument must be None or a string");
       return NULL;
    }

    struct confd_snmp_varbind *vbs = NULL;
    int vbc = 0;

    if (PyList_Check(varbinds) && PyList_Size(varbinds) > 0) {
        vbc = (int)PyList_Size(varbinds);
        vbs = (struct confd_snmp_varbind*)
                malloc(sizeof(struct confd_snmp_varbind) * vbc);

        int i;
        PyObject *o;
        for (i = 0; i < vbc; i++) {
            o = PyList_GetItem(varbinds, i);
            if (!isConfdSnmpVarbind((PyObject*)o)) {
                PyErr_Format(PyExc_TypeError,
                        "item %d of varbinds must be a "
                        CONFD_PY_MODULE ".SnmpVarbind instance", i);
                free(cb_id);
                free(vbs);
                return NULL;
            }
            memcpy(&vbs[i], &((confdSnmpVarbind*)o)->vb,
                    sizeof(struct confd_snmp_varbind));
        }
    }
    else if (varbinds != Py_None) {
        PyErr_Format(PyExc_TypeError,
            "varbinds argument must be None or a list of "
            CONFD_PY_MODULE ".SnmpVarbind instances");
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(confd_notification_send_snmp_inform(nctx->nctx,
                                                             notification,
                                                             vbs, vbc,
                                                             cb_id, ref),
                         {
                             free(cb_id);
                             free(vbs);
                         });

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_set_snmp_src_addr,
            EXT_API_FUN_DP_NOTIFICATION_SET_SNMP_SRC_ADDR)
{
    static char *kwlist[] = {
        "nctx",
        "family",
        "src_addr",
        NULL
    };

    confdNotificationCtxRef *nctx;
    int family;
    char *src_addr;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Ois", kwlist,
                &nctx, &family, &src_addr)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError, "nctx argument must be a "
                     CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    struct confd_ip ip;
    memset(&ip, 0, sizeof(ip));

    ip.af = family;

    if (family == AF_INET) {
        if (inet_pton(AF_INET, src_addr, &ip.ip.v4) != 1) {
            PyErr_Format(PyExc_ValueError, "invalid IP address: %s", src_addr);
            return NULL;
        }
    }
    else if (family == AF_INET6) {
        if (inet_pton(AF_INET6, src_addr, &ip.ip.v6) != 1) {
            PyErr_Format(PyExc_ValueError, "invalid IP address: %s", src_addr);
            return NULL;
        }
    }
    else if (family != AF_UNSPEC) {
        PyErr_Format(PyExc_TypeError, "family argument must be "
                     CONFD_PY_MODULE "AF_INET, AF_INET6 or AF_UNSPEC");
        return NULL;
    }

    CONFD_EXEC(confd_notification_set_snmp_src_addr(nctx->nctx, &ip));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_set_snmp_notify_name,
            EXT_API_FUN_DP_NOTIFICATION_SET_SNMP_NOTIFY_NAME)
{
    static char *kwlist[] = {
        "nctx",
        "notify_name",
        NULL
    };

    confdNotificationCtxRef *nctx;
    char *name;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Os", kwlist, &nctx, &name)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError, "nctx argument must be a "
                     CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_notification_set_snmp_notify_name(nctx->nctx, name));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_notification_flush, EXT_API_FUN_DP_NOTIFICATION_FLUSH)
{
    static char *kwlist[] = {
        "nctx",
        NULL
    };

    confdNotificationCtxRef *nctx;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Os", kwlist, &nctx)) {
        return NULL;
    }

    if (!isConfdNotificationCtxRef((PyObject *)nctx)) {
        PyErr_Format(PyExc_TypeError, "nctx argument must be a "
                     CONFD_PY_MODULE ".dp.NotificationCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_notification_flush(nctx->nctx));

    Py_RETURN_NONE;
}

/* ************************************************************************* */
/* register_notification_snmp_inform_cb

  struct confd_notification_snmp_inform_cbs {
        char cb_id[MAX_CALLPOINT_LEN];
        void (*targets)(struct confd_notification_ctx *nctx,
                        int ref, struct confd_snmp_target *targets,
                        int num_targets);
        void (*result)(struct confd_notification_ctx *nctx,
                        int ref, struct confd_snmp_target *target,
                        int got_response);
        void *cb_opaque;
  };
*/
/* ************************************************************************* */

/* ------------------------------------------------------------------------- */

static void _dp_notification_snmp_inform_targets_cb(
        struct confd_notification_ctx *nctx,
        int ref, struct confd_snmp_target *targets,
        int num_targets)
{
    if (nctx->cb_opaque == NULL) {
        /* Should never happen */
        confd_notification_seterr(nctx, "Internal, cb_opaque == NULL");
        return;
    }

    PyObject *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pyref = NULL;
    PyObject *pyret = NULL;
    PyObject *pytargets = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    ctxRef = (PyObject*)newConfdNotificationCtxRef(nctx);
    if (ctxRef == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_targets")) == NULL)
        goto decref;
    if ((pyref = PyInt_FromLong(ref)) == NULL) goto decref;

    pytargets = PyList_New(num_targets);
    PyObject *tup;
    int i;
    for (i = 0; i < num_targets; i++) {
        tup = PyTuple_New(2);
        PyTuple_SetItem(tup, 0, newConfdValue(&targets[i].address));
        PyTuple_SetItem(tup, 0, PyInt_FromLong(targets[i].port));
        PyList_SetItem(pytargets, i, tup);
    }

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = nctx->cb_opaque;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxRef, pyref, pytargets, NULL);

    if (pyret == NULL) {
        _confd_py_notification_seterr_fetch(nctx, "cb_targets");
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);
    Py_XDECREF(pyref);
    Py_XDECREF(pytargets);

    PyGILState_Release(gstate);
}

/* ------------------------------------------------------------------------- */

static void _dp_notification_snmp_inform_result_cb(
        struct confd_notification_ctx *nctx,
        int ref, struct confd_snmp_target *target,
        int got_response)
{
    if (nctx->cb_opaque == NULL) {
        /* Should never happen */
        confd_notification_seterr(nctx, "Internal, cb_opaque == NULL");
        return;
    }

    PyObject *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;
    PyObject *pyref = NULL;
    PyObject *pytarget = NULL;
    PyObject *pygot_response = NULL;

    PyGILState_STATE gstate = PyGILState_Ensure();

    ctxRef = (PyObject*)newConfdNotificationCtxRef(nctx);
    if (ctxRef == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_result")) == NULL)
        goto decref;
    if ((pyref = PyInt_FromLong(ref)) == NULL) goto decref;
    if ((pygot_response = PyInt_FromLong(got_response)) == NULL) goto decref;

    pytarget = PyTuple_New(2);
    PyTuple_SetItem(pytarget, 0, newConfdValue(&target->address));
    PyTuple_SetItem(pytarget, 0, PyInt_FromLong(target->port));

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = nctx->cb_opaque;

    pyret = PyObject_CallMethodObjArgs(
            cbs, cbname, ctxRef, pyref, pytarget, pygot_response, NULL);

    if (pyret == NULL) {
        _confd_py_notification_seterr_fetch(nctx, "cb_result");
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);
    Py_XDECREF(pyref);
    Py_XDECREF(pytarget);
    Py_XDECREF(pygot_response);

    PyGILState_Release(gstate);
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_notification_snmp_inform_cb,
            EXT_API_FUN_DP_REGISTER_NOTIFICATION_SNMP_INFORM_CB)
{
    static char *kwlist[] = {
        "dx",
        "cb_id",
        "cbs",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;
    char *cb_id;
    PyObject *cbs;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OsO", kwlist,
                &ctx, &cb_id, &cbs)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    CHECK_CB_MTH(cbs, "cb_targets", 4);
    CHECK_CB_MTH(cbs, "cb_result", 5);

    struct confd_notification_snmp_inform_cbs x;
    memset(&x, 0, sizeof(x));

    strncpy(x.cb_id, cb_id, sizeof(x.cb_id)-1);

    x.targets = _dp_notification_snmp_inform_targets_cb;
    x.result = _dp_notification_snmp_inform_result_cb;
    x.cb_opaque = cbs;

    CHECK_CONFD_ERR(confd_register_notification_snmp_inform_cb(ctx->ctx, &x));

    Py_INCREF(cbs);

    Py_RETURN_NONE;
}

/* ************************************************************************* */
/* register_notification_sub_snmp_cb
 *
    struct confd_notification_sub_snmp_cb {
        char sub_id[MAX_CALLPOINT_LEN];
        int (*recv)(struct confd_notification_ctx *nctx,
                    char *notification,
                    struct confd_snmp_varbind *varbinds, int num_vars,
                    confd_value_t *src_addr, u_int16_t src_port);
        void *cb_opaque;
    };
*/
/* ************************************************************************* */

static int _dp_notification_sub_snmp_recv_cb(
        struct confd_notification_ctx *nctx,
        char *notification,
        struct confd_snmp_varbind *varbinds, int num_vars,
        confd_value_t *src_addr, u_int16_t src_port)
{
    if (nctx->cb_opaque == NULL) {
        /* Should never happen */
        confd_notification_seterr(nctx, "Internal, cb_opaque == NULL");
        return CONFD_ERR;
    }

    PyObject *ctxRef = NULL;
    PyObject *cbname = NULL;
    PyObject *pyret = NULL;
    PyObject *pynotification = NULL;
    PyObject *pyvarbinds = NULL;
    PyObject *pysrc_addr = NULL;
    PyObject *pysrc_port = NULL;

    int ret = CONFD_ERR;

    PyGILState_STATE gstate = PyGILState_Ensure();

    ctxRef = (PyObject*)newConfdNotificationCtxRef(nctx);
    if (ctxRef == NULL) goto decref;
    if ((cbname = PyString_FromString("cb_recv")) == NULL)
        goto decref;
    if ((pynotification = PyString_FromString(notification)) == NULL)
        goto decref;
    if ((pysrc_addr = newConfdValue(src_addr)) == NULL) goto decref;
    if ((pysrc_port = PyInt_FromLong(src_port)) == NULL) goto decref;

    int i;
    pyvarbinds = PyList_New(num_vars);
    for (i = 0; i < num_vars; i++) {
        PyList_SetItem(pyvarbinds, i, newConfdSnmpVarbind(&varbinds[i]));
    }

    /* Don't have to incref the cbs pointer */
    PyObject *cbs = nctx->cb_opaque;

    pyret = PyObject_CallMethodObjArgs(
                cbs, cbname, ctxRef, pynotification,
                pyvarbinds, pysrc_addr, pysrc_port, NULL);

    if (pyret == NULL) {
        _confd_py_notification_seterr_fetch(nctx, "cb_recv");
    }
    else if (pyret == Py_None) {
        ret = CONFD_OK;
    }
    else if (PyInt_Check(pyret)) {
        ret = (int)PyInt_AsLong(pyret);
    }
    else {
        confd_notification_seterr(
                nctx, "Python cb_recv error. Invalid return type.");
        ret = CONFD_ERR;
    }

decref:
    Py_XDECREF(pyret);
    Py_XDECREF(cbname);
    Py_XDECREF(ctxRef);
    Py_XDECREF(pynotification);
    Py_XDECREF(pyvarbinds);
    Py_XDECREF(pysrc_addr);
    Py_XDECREF(pysrc_port);

    PyGILState_Release(gstate);

    return ret;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_dp_register_notification_sub_snmp_cb,
            EXT_API_FUN_DP_REGISTER_NOTIFICATION_SUB_SNMP_CB)
{
    static char *kwlist[] = {
        "dx",
        "sub_id",
        "cbs",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;
    char *sub_id;
    PyObject *cbs;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OsO", kwlist,
                &ctx, &sub_id, &cbs)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    CHECK_CB_MTH(cbs, "cb_recv", 6);

    struct confd_notification_sub_snmp_cb x;
    memset(&x, 0, sizeof(x));

    strncpy(x.sub_id, sub_id, sizeof(x.sub_id)-1);

    x.recv = _dp_notification_sub_snmp_recv_cb;
    x.cb_opaque = cbs;

    CHECK_CONFD_ERR(confd_register_notification_sub_snmp_cb(ctx->ctx, &x));

    Py_INCREF(cbs);

    Py_RETURN_NONE;
}


/* Services API */
#ifdef CONFD_PY_PRODUCT_NCS

EXT_API_FUN(_dp_register_service_cb, EXT_API_FUN_DP_REGISTER_SERVICE_CB)
{
    static char *kwlist[] = {
        "dx",
        "servicepoint",
        "scb",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;
    PyObject *cbs;
    char *servicepoint;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OsO", kwlist,
                &ctx, &servicepoint, &cbs)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    struct ncs_service_cbs nscb;
    memset(&nscb, 0, sizeof(nscb));

    if (PyObject_HasAttrString(cbs, "cb_create")) {
        CHECK_CB_MTH(cbs, "cb_create", 5);
        nscb.create = _scb_create_cb;
    }

    if (PyObject_HasAttrString(cbs, "cb_pre_modification")) {
        CHECK_CB_MTH(cbs, "cb_pre_modification", 5);
        nscb.pre_modification = _scb_pre_modification_cb;
    }

    if (PyObject_HasAttrString(cbs, "cb_post_modification")) {
        CHECK_CB_MTH(cbs, "cb_post_modification", 5);
        nscb.post_modification = _scb_post_modification_cb;
    }

    if (!(nscb.create ||
          nscb.pre_modification || nscb.post_modification)) {
        PyErr_Format(PyExc_TypeError,
                        "Callback object must implement at least one of the "
                        "methods cb_create(), "
                        "cb_pre_modification() or cb_post_modification()");
        return NULL;
    }

    if (strlen(servicepoint) > MAX_CALLPOINT_LEN-1) {
        PyErr_Format(PyExc_Exception,
            "servicepoint argument can be at most %d characters in length",
            MAX_CALLPOINT_LEN-1);
        return NULL;
    }

    nscb.cb_opaque = cbs;

    memcpy(nscb.servicepoint, servicepoint, strlen(servicepoint) + 1);

    CHECK_CONFD_ERR(ncs_register_service_cb(ctx->ctx, &nscb));

    Py_INCREF(cbs);

    Py_RETURN_NONE;
}


EXT_API_FUN(_dp_service_reply_proplist, EXT_API_FUN_DP_SERVICE_REPLY_PROPLIST)
{
    static char *kwlist[] = {
        "tctx",
        "proplist",
        NULL
    };

    confdTransCtxRef *tctx;
    PyObject *pyproplist;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                                     &tctx, &pyproplist)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)tctx)) {
        PyErr_Format(PyExc_TypeError,
            "tctx argument must be a "
            CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    py_prop_list_t proplist_pl = {0};
    if (PyList_Check(pyproplist)) {
        if (! confd_py_alloc_py_prop_list(pyproplist, &proplist_pl,
                                          "proplist")) {
            return NULL;
        }
    } else if (pyproplist != Py_None) {
        PyErr_Format(PyExc_TypeError,
                     "proplist argument must be a list of 2-tuples or None");
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(ncs_service_reply_proplist(tctx->tc,
                                                    proplist_pl.list,
                                                    proplist_pl.size),
                         confd_py_free_py_prop_list(&proplist_pl));

    Py_RETURN_NONE;
}


EXT_API_FUN(_dp_register_nano_service_cb,
            EXT_API_FUN_DP_REGISTER_NANO_SERVICE_CB)
{
    static char *kwlist[] = {
        "dx",
        "servicepoint",
        "componenttype",
        "state",
        "cbs",
        NULL
    };

    PyConfd_DaemonCtxRef_Object *ctx;
    PyObject *cbs;
    char *servicepoint;
    char *componenttype;
    char *state;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OsssO", kwlist,
                                     &ctx, &servicepoint, &componenttype,
                                     &state, &cbs)) {
        return NULL;
    }

    if (!PyConfd_DaemonCtxRef_CheckExact((PyObject *)ctx)) {
        PyErr_Format(PyExc_TypeError, "dx argument must be a "
                     CONFD_PY_MODULE ".dp.DaemonCtxRef instance");
        return NULL;
    }

    struct ncs_nano_service_cbs nscb;
    memset(&nscb, 0, sizeof(nscb));

    if (PyObject_HasAttrString(cbs, "cb_nano_create")) {
        CHECK_CB_MTH(cbs, "cb_nano_create", 9);
        nscb.nano_create = _nscb_nano_create_cb;
    }

    if (PyObject_HasAttrString(cbs, "cb_nano_delete")) {
        CHECK_CB_MTH(cbs, "cb_nano_delete", 9);
        nscb.nano_delete = _nscb_nano_delete_cb;
    }

    if (strlen(servicepoint) > MAX_CALLPOINT_LEN-1) {
        PyErr_Format(PyExc_Exception,
            "servicepoint argument can be at most %d characters in length",
            MAX_CALLPOINT_LEN-1);
        return NULL;
    }

    nscb.cb_opaque = cbs;

    memcpy(nscb.servicepoint, servicepoint, strlen(servicepoint) + 1);

    CHECK_CONFD_ERR(ncs_register_nano_service_cb(ctx->ctx,
                                                 componenttype,
                                                 state,
                                                 &nscb));
    Py_INCREF(cbs);

    Py_RETURN_NONE;
}

EXT_API_FUN(_dp_nano_service_reply_proplist,
            EXT_API_FUN_DP_NANO_SERVICE_REPLY_PROPLIST)
{
    static char *kwlist[] = {
        "tctx",
        "proplist",
        NULL
    };

    confdTransCtxRef *tctx;
    PyObject *pyproplist;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                                     &tctx, &pyproplist)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)tctx)) {
        PyErr_Format(PyExc_TypeError,
            "tctx argument must be a "
            CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    py_prop_list_t proplist_pl = {0};
    if (PyList_Check(pyproplist)) {
        if (! confd_py_alloc_py_prop_list(pyproplist, &proplist_pl,
                                          "proplist")) {
            return NULL;
        }
    } else if (pyproplist != Py_None) {
        PyErr_Format(PyExc_TypeError,
                     "proplist argument must be a list of 2-tuples or None");
        return NULL;
    }

    CHECK_CONFD_ERR_EXEC(ncs_service_reply_proplist(tctx->tc,
                                                    proplist_pl.list,
                                                    proplist_pl.size),
                         confd_py_free_py_prop_list(&proplist_pl));

    Py_RETURN_NONE;
}


#endif /* CONFD_PY_PRODUCT_NCS */


#include "../doc/src/dp_doc.c"

#define PYMOD_ENTRY(NAME) {# NAME, (PyCFunction)_dp_ ## NAME, \
                           METH_VARARGS | METH_KEYWORDS, \
                           _dp_ ## NAME ## __doc__}

static PyMethodDef confd_dp_Methods[] = {

    PYMOD_ENTRY(init_daemon),
    PYMOD_ENTRY(set_daemon_flags),
    PYMOD_ENTRY(release_daemon),
    PYMOD_ENTRY(connect),

    PYMOD_ENTRY(register_trans_cb),
    PYMOD_ENTRY(register_db_cb),
    PYMOD_ENTRY(register_range_data_cb),
    PYMOD_ENTRY(register_data_cb),
    PYMOD_ENTRY(register_usess_cb),
    PYMOD_ENTRY(register_done),

    PYMOD_ENTRY(fd_ready),
    PYMOD_ENTRY(trans_set_fd),

    PYMOD_ENTRY(data_reply_value),

    PYMOD_ENTRY(data_reply_value_array),
    PYMOD_ENTRY(data_reply_tag_value_array),

    PYMOD_ENTRY(data_reply_next_key),
    PYMOD_ENTRY(data_reply_not_found),
    PYMOD_ENTRY(data_reply_found),

    PYMOD_ENTRY(data_reply_next_object_array),
    PYMOD_ENTRY(data_reply_next_object_tag_value_array),
    PYMOD_ENTRY(data_reply_next_object_arrays),
    PYMOD_ENTRY(data_reply_next_object_tag_value_arrays),
    PYMOD_ENTRY(data_reply_attrs),
    PYMOD_ENTRY(delayed_reply_ok),
    PYMOD_ENTRY(delayed_reply_error),
    PYMOD_ENTRY(data_set_timeout),
    PYMOD_ENTRY(data_get_list_filter),
    PYMOD_ENTRY(trans_seterr),
    PYMOD_ENTRY(trans_seterr_extended),
    PYMOD_ENTRY(trans_seterr_extended_info),
    PYMOD_ENTRY(db_set_timeout),
    PYMOD_ENTRY(db_seterr),
    PYMOD_ENTRY(db_seterr_extended),
    PYMOD_ENTRY(db_seterr_extended_info),
    PYMOD_ENTRY(aaa_reload),
    PYMOD_ENTRY(install_crypto_keys),

    PYMOD_ENTRY(register_trans_validate_cb),
    PYMOD_ENTRY(register_valpoint_cb),

    PYMOD_ENTRY(register_range_valpoint_cb),
    PYMOD_ENTRY(delayed_reply_validation_warn),

    PYMOD_ENTRY(register_action_cbs),

    PYMOD_ENTRY(register_range_action_cbs),
    PYMOD_ENTRY(action_set_fd),
    PYMOD_ENTRY(action_seterr),
    PYMOD_ENTRY(action_seterr_extended),
    PYMOD_ENTRY(action_seterr_extended_info),
    PYMOD_ENTRY(action_reply_values),
    PYMOD_ENTRY(action_reply_command),
    PYMOD_ENTRY(action_reply_rewrite),
    PYMOD_ENTRY(action_reply_rewrite2),
    PYMOD_ENTRY(action_reply_completion),
    PYMOD_ENTRY(action_reply_range_enum),
    PYMOD_ENTRY(action_delayed_reply_ok),
    PYMOD_ENTRY(action_delayed_reply_error),
    PYMOD_ENTRY(action_set_timeout),
    PYMOD_ENTRY(register_notification_stream),
    PYMOD_ENTRY(notification_send),
    PYMOD_ENTRY(notification_send_path),
    PYMOD_ENTRY(notification_replay_complete),
    PYMOD_ENTRY(notification_replay_failed),
    PYMOD_ENTRY(notification_reply_log_times),
    PYMOD_ENTRY(notification_set_fd),
    PYMOD_ENTRY(notification_set_snmp_src_addr),
    PYMOD_ENTRY(notification_set_snmp_notify_name),
    PYMOD_ENTRY(notification_seterr),
    PYMOD_ENTRY(notification_seterr_extended),
    PYMOD_ENTRY(notification_seterr_extended_info),
    PYMOD_ENTRY(register_snmp_notification),
    PYMOD_ENTRY(notification_send_snmp),
    PYMOD_ENTRY(register_notification_snmp_inform_cb),
    PYMOD_ENTRY(notification_send_snmp_inform),
    PYMOD_ENTRY(register_notification_sub_snmp_cb),
    PYMOD_ENTRY(notification_flush),
    PYMOD_ENTRY(register_auth_cb),
    PYMOD_ENTRY(auth_seterr),
    PYMOD_ENTRY(register_authorization_cb),
    PYMOD_ENTRY(access_reply_result),
    PYMOD_ENTRY(authorization_set_timeout),
    PYMOD_ENTRY(register_error_cb),
    PYMOD_ENTRY(error_seterr),

#ifdef CONFD_PY_PRODUCT_NCS

    PYMOD_ENTRY(register_service_cb),
    PYMOD_ENTRY(service_reply_proplist),
    PYMOD_ENTRY(register_nano_service_cb),
    PYMOD_ENTRY(nano_service_reply_proplist),

#endif /* CONFD_PY_PRODUCT_NCS */


    {NULL, NULL, 0, NULL}
};
#undef PYMOD_ENTRY

/* ************************************************************************ */
/* Module initialization                                                    */
/* ************************************************************************ */

#define MODULE CONFD_PY_MODULE ".dp"

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        MODULE,
        DP_MODULE_DOCSTR(CONFD_PY_PRODUCT),
        0,
        confd_dp_Methods,
        NULL,
        NULL,
        NULL,
        NULL
};

PyObject* init__dp_module(void)
{
    PyObject *m = NULL;

    if ((m = PyModule_Create(&moduledef)) == NULL) {
        goto error;
    }

    init_dp_types(m);

    /* Add constants */
#define ADD_CONST(C_NAME, PY_NAME) \
    (void)PyModule_AddIntConstant(m, PY_NAME, C_NAME);

#define ADD_CONST_STR(C_NAME, PY_NAME) \
    (void)PyModule_AddStringConstant(m, PY_NAME, C_NAME);


#include "gen_add_dp_const.c"
#include "gen_add_errcode_const.c"

#undef ADD_CONST
#undef ADD_CONST_STR


error:
    if (PyErr_Occurred()) {
        PyErr_SetString(PyExc_ImportError,
                        MODULE " : init failed");
        return NULL;
    } else {
        return m;
    }
}
