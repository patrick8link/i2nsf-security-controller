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
#include "confdpy_err.h"
#include "types.h"
#include "common.h"


#include <pthread.h>


#include "confdpy_config.h"


/* ------------------------------------------------------------------------- */

EXT_API_FUN(_events_notifications_connect,
            EXT_API_FUN_EVENTS_NOTIFICATIONS_CONNECT)
{
    static char *kwlist[] = {
        "sock", "mask", "ip", "port", "path", NULL };
    PyObject *sock, *tmp;
    int mask;

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
            args, kwds, "Oi|sis", kwlist,
            &sock, &mask, &ipstr, &port, &pstr)) {
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

    CHECK_CONFD_ERR(confd_notifications_connect(s, addr, addrlen, mask));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_events_notifications_connect2,
            EXT_API_FUN_EVENTS_NOTIFICATIONS_CONNECT2)
{
    static char *kwlist[] = {
        "sock", "mask", "data", "ip", "port", "path", NULL };
    PyObject *sock, *tmp;
    int mask;
    confdNotificationsData *data;

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
            args, kwds, "OiO|sis", kwlist,
            &sock, &mask, &data, &ipstr, &port, &pstr)) {
        return NULL;
    }

    if (!isConfdNotificationsData((PyObject*)data)) {
        PyErr_Format(PyExc_TypeError, "data argument must be a "
                     CONFD_PY_MODULE ".events.NotificationsData instance");
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

    CHECK_CONFD_ERR(
            confd_notifications_connect2(s, addr, addrlen, mask, &data->nd));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

/* event delivered from the CONFD_NOTIF_AUDIT flag */
/*
    struct confd_audit_notification {
        int logno;
        char user[MAXUSERNAMELEN];
        char msg[BUFSIZ];
        int usid;
    };
*/
static void build_audit_notification(
        PyObject *d, struct confd_audit_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "logno", PyInt_FromLong(n->logno));
    PYDICT_SET_ITEM(x, "user", PyString_FromString(n->user));
    PYDICT_SET_ITEM(x, "msg", PyString_FromString(n->msg));
    PYDICT_SET_ITEM(x, "usid", PyInt_FromLong(n->usid));

    PYDICT_SET_ITEM(d, "audit", x);
}

/* event delivered from the CONFD_NOTIF_DAEMON, CONFD_NOTIF_NETCONF,   */
/* CONFD_NOTIF_DEVEL, CONFD_NOTIF_JSONRPC, and CONFD_NOTIF_WEBUI flags */
/*
    struct confd_syslog_notification {
        int prio;
        int logno;
        char msg[BUFSIZ];
    };
*/
static void build_syslog_notification(
        PyObject *d, struct confd_syslog_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "prio", PyInt_FromLong(n->prio));
    PYDICT_SET_ITEM(x, "logno", PyInt_FromLong(n->logno));
    PYDICT_SET_ITEM(x, "msg", PyString_FromString(n->msg));

    PYDICT_SET_ITEM(d, "syslog", x);
}

/* event delivered from the CONFD_NOTIF_COMMIT_SIMPLE flag */
/*
    struct confd_commit_notification {
        enum confd_dbname database;
        int diff_available;
        struct confd_user_info uinfo;
        int flags;
    };
*/
static void build_commit_notification(
        PyObject *d, struct confd_commit_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "database", PyInt_FromLong(n->database));
    PYDICT_SET_ITEM(x, "diff_available", PyInt_FromLong(n->diff_available));
    PYDICT_SET_ITEM(x, "flags", PyInt_FromLong(n->flags));
    PYDICT_SET_ITEM(x, "uinfo", newConfdUserInfo(&n->uinfo));

    PYDICT_SET_ITEM(d, "commit", x);
}

/* event delivered from the CONFD_NOTIF_COMMIT_DIFF flag */
/*
    struct confd_commit_diff_notification {
        enum confd_dbname database;
        struct confd_user_info uinfo;
        struct confd_trans_ctx  *tctx;
        int flags;
        char comment[MAX_COMMENT_LEN];
        char label[MAX_LABEL_LEN];
    };
*/
static void build_commit_diff_notification(
        PyObject *d, struct confd_commit_diff_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "database", PyInt_FromLong(n->database));
    PYDICT_SET_ITEM(x, "flags", PyInt_FromLong(n->flags));
    PYDICT_SET_ITEM(x, "uinfo", newConfdUserInfo(&n->uinfo));
    PYDICT_SET_ITEM(x, "tctx", newConfdTransCtxRef(n->tctx));
    if (n->comment[0] != '\0') {
        PYDICT_SET_ITEM(x, "comment", PyString_FromString(n->comment));
    }
    if (n->label[0] != '\0') {
        PYDICT_SET_ITEM(x, "label", PyString_FromString(n->label));
    }

    PYDICT_SET_ITEM(d, "commit_diff", x);
}

/* event delivered from the CONFD_NOTIF_USER_SESSION flag */
/*
    struct confd_user_sess_notification {
        enum confd_user_sess_type type;
        struct confd_user_info uinfo;
        enum confd_dbname database;
    };
*/
static void build_user_sess_notification(
        PyObject *d, struct confd_user_sess_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "type", PyInt_FromLong(n->type));
    PYDICT_SET_ITEM(x, "uinfo", newConfdUserInfo(&n->uinfo));
    PYDICT_SET_ITEM(x, "database", PyInt_FromLong(n->database));

    PYDICT_SET_ITEM(d, "user_sess", x);
}

/* event delivered from the CONFD_NOTIF_HA_INFO flag */
/*
    struct confd_ha_notification {
        enum confd_ha_info_type type;
        * additional info for various info types *
        union {
            // CONFD_HA_INFO_NOPRIMARY
            int noprimary;
            // CONFD_HA_INFO_SECONDARY_DIED
            struct confd_ha_node secondary_died;
            // CONFD_HA_INFO_SECONDARY_ARRIVED
            struct confd_ha_node secondary_arrived;
            // CONFD_HA_INFO_SECONDARY_INITIALIZED
            int cdb_initialized_by_copy;
            // CONFD_HA_INFO_BESECONDARY_RESULT
            int besecondary_result;
        } data;
    };
*/
static void add_ha_node_info(
        PyObject *d, const char *name, struct confd_ha_node *n)
{
    PyObject *secondary = PyDict_New();

    PYDICT_SET_ITEM(secondary, "nodeid",
                    (PyObject*)PyConfd_Value_New_DupTo(&n->nodeid));
    PYDICT_SET_ITEM(secondary, "af", PyInt_FromLong(n->af));

    if (n->af == AF_INET) {
        char tmp[INET_ADDRSTRLEN + 1];
        if (inet_ntop(n->af, &n->addr.ip4, tmp, INET_ADDRSTRLEN)) {
            PYDICT_SET_ITEM(secondary, "ip4", PyString_FromString(tmp));
        }
        else {
            PYDICT_SET_ITEM(
                    secondary, "ip4",
                    PyString_FromString("ip address conversion failed"));
        }
    }
    else if (n->af == AF_INET6) {
        char tmp[INET6_ADDRSTRLEN + 1];
        if (inet_ntop(n->af, &n->addr.ip6, tmp, INET6_ADDRSTRLEN)) {
            PYDICT_SET_ITEM(secondary, "ip6", PyString_FromString(tmp));
        }
        else {
            PYDICT_SET_ITEM(
                    secondary, "ip6",
                    PyString_FromString("ip address conversion failed"));
        }
    }
    else if (n->af == AF_UNSPEC) {
        if (n->addr.str) {
            PYDICT_SET_ITEM(secondary, "str", PyString_FromString(n->addr.str));
        }
        else {
            PyDict_SetItemString(secondary, "str", Py_None);
        }
    }

    PYDICT_SET_ITEM(d, name, secondary);
}

static void build_ha_notification(
        PyObject *d, struct confd_ha_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "type", PyInt_FromLong(n->type));

    if (n->type == CONFD_HA_INFO_NOPRIMARY) {
        PYDICT_SET_ITEM(x, "noprimary", PyInt_FromLong(n->data.noprimary));
        // BIASED FREE: Backwards compatibility - remove later
        PYDICT_SET_ITEM(x, "nomaster", PyInt_FromLong(n->data.noprimary));
    }
    else if (n->type == CONFD_HA_INFO_SECONDARY_DIED) {
        add_ha_node_info(x, "secondary_died", &n->data.secondary_died);
        // BIASED FREE: Backwards compatibility - remove later
        add_ha_node_info(x, "slave_died", &n->data.secondary_died);
    }
    else if (n->type == CONFD_HA_INFO_SECONDARY_ARRIVED) {
        add_ha_node_info(x, "secondary_arrived", &n->data.secondary_arrived);
        // BIASED FREE: Backwards compatibility - remove later
        add_ha_node_info(x, "slave_arrived", &n->data.secondary_arrived);
    }
    else if (n->type == CONFD_HA_INFO_SECONDARY_INITIALIZED) {
        PYDICT_SET_ITEM(x, "cdb_initialized_by_copy",
                             PyInt_FromLong(n->data.cdb_initialized_by_copy));
    }
    else if (n->type == CONFD_HA_INFO_BESECONDARY_RESULT) {
        PYDICT_SET_ITEM(x, "besecondary_result",
                             PyInt_FromLong(n->data.besecondary_result));
        // BIASED FREE: Backwards compatibility - remove later
        PYDICT_SET_ITEM(x, "beslave_result",
                             PyInt_FromLong(n->data.besecondary_result));
    }

    PYDICT_SET_ITEM(d, "hnot", x);
}

/* event delivered from the CONFD_NOTIF_SUBAGENT_INFO flag */
/*
    struct confd_subagent_notification {
        enum confd_subagent_info_type type;
        char name[MAXAGENTNAMELEN];
    };
*/
static void build_subagent_notification(
        PyObject *d, struct confd_subagent_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "type", PyInt_FromLong(n->type));
    PYDICT_SET_ITEM(x, "name", PyString_FromString(n->name));

    PYDICT_SET_ITEM(d, "subagent", x);
}

/* event delivered from the CONFD_NOTIF_FORWARD_INFO flag */
/*
    struct confd_forward_notification {
        enum confd_forward_info_type type; * type of forward event
        char target[MAXTARGETNAMELEN];     * target name in confd.conf
        struct confd_user_info uinfo;      * on behalf of which user
    };
*/
static void build_forward_notification(
        PyObject *d, struct confd_forward_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "type", PyInt_FromLong(n->type));
    PYDICT_SET_ITEM(x, "type", PyString_FromString(n->target));
    PYDICT_SET_ITEM(x, "uinfo", newConfdUserInfo(&n->uinfo));

    PYDICT_SET_ITEM(d, "forward", x);
}

/* event delivered from the CONFD_NOTIF_COMMIT_FAILED flag */
/*
    struct confd_commit_failed_notification {
        enum confd_data_provider provider;
        enum confd_dbname dbname;
        union {
            struct confd_netconf_failed_commit nc;
            char daemon_name[MAX_DAEMON_NAME_LEN];
        } v;
    };
*/
static void build_commit_failed_notification(
        PyObject *d, struct confd_commit_failed_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "provider", PyInt_FromLong(n->provider));
    PYDICT_SET_ITEM(x, "dbname", PyInt_FromLong(n->dbname));

    if (n->provider == CONFD_DP_NETCONF) {
        PYDICT_SET_ITEM(x, "port", PyInt_FromLong(n->v.nc.port));
        PYDICT_SET_ITEM(x, "af", PyInt_FromLong(n->v.nc.ip.af));
        if (n->v.nc.ip.af == AF_INET) {
            char tmp[INET_ADDRSTRLEN + 1];
            if (inet_ntop(n->v.nc.ip.af,
                          &n->v.nc.ip.ip.v4,
                          tmp, INET_ADDRSTRLEN)) {
                PYDICT_SET_ITEM(x, "ip4", PyString_FromString(tmp));
            }
            else {
                PYDICT_SET_ITEM(
                        x, "ip4",
                        PyString_FromString("ip address conversion failed"));
            }
        }
        else if (n->v.nc.ip.af == AF_INET6) {
            char tmp[INET6_ADDRSTRLEN + 1];
            if (inet_ntop(n->v.nc.ip.af,
                          &n->v.nc.ip.ip.v6,
                          tmp, INET6_ADDRSTRLEN)) {
                PYDICT_SET_ITEM(x, "ip6", PyString_FromString(tmp));
            }
            else {
                PYDICT_SET_ITEM(
                        x, "ip6",
                        PyString_FromString("ip address conversion failed"));
            }
        }
    }
    else if (n->provider == CONFD_DP_EXTERNAL) {
        PYDICT_SET_ITEM(
                x, "daemon_name", PyString_FromString(n->v.daemon_name));
    }

    PYDICT_SET_ITEM(d, "cfail", x);
}

/* event delivered from the CONFD_NOTIF_SNMPA flag */
/*
    struct confd_snmpa_notification {
        enum confd_snmp_pdu_type pdu_type;
        int request_id;
        struct confd_ip ip;
        unsigned short port;
        int error_status;
        int error_index;
        int num_variables;                  * size of vbinds
        struct confd_snmp_varbind *vb;      * lib malloced array
        struct confd_v1_trap_info *v1_trap; * v1 traps pdus only
    };
*/
static void build_snmpa_notification(
        PyObject *d, struct confd_snmpa_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "pdu_type", PyInt_FromLong(n->pdu_type));
    PYDICT_SET_ITEM(x, "request_id", PyInt_FromLong(n->request_id));
    PYDICT_SET_ITEM(x, "error_status", PyInt_FromLong(n->error_status));
    PYDICT_SET_ITEM(x, "error_index", PyInt_FromLong(n->error_index));

    PYDICT_SET_ITEM(x, "port", PyInt_FromLong(n->port));
    PYDICT_SET_ITEM(x, "af", PyInt_FromLong(n->ip.af));

    if (n->ip.af == AF_INET) {
        char tmp[INET_ADDRSTRLEN + 1];
        if (inet_ntop(n->ip.af, &n->ip.ip.v4, tmp, INET_ADDRSTRLEN)) {
            PYDICT_SET_ITEM(x, "ip4", PyString_FromString(tmp));
        }
        else {
            PYDICT_SET_ITEM(
                    x, "ip4",
                    PyString_FromString("ip address conversion failed"));
        }
    }
    else if (n->ip.af == AF_INET6) {
        char tmp[INET6_ADDRSTRLEN + 1];
        if (inet_ntop(n->ip.af, &n->ip.ip.v6, tmp, INET6_ADDRSTRLEN)) {
            PYDICT_SET_ITEM(x, "ip6", PyString_FromString(tmp));
        }
        else {
            PYDICT_SET_ITEM(
                    x, "ip6",
                    PyString_FromString("ip address conversion failed"));
        }
    }

    if (n->vb != NULL && n->num_variables > 0) {
        PyObject *l = PyList_New(n->num_variables);
        int i;
        for (i = 0; i < n->num_variables; i++) {
            PyList_SetItem(l, i, (PyObject*)newConfdSnmpVarbind(&n->vb[i]));
        }
        PYDICT_SET_ITEM(x, "vb", l);
    }

    if (n->v1_trap != NULL) {
        PYDICT_SET_ITEM(
                x, "generic_trap", PyInt_FromLong(n->v1_trap->generic_trap));
        PYDICT_SET_ITEM(
                x, "specific_trap", PyInt_FromLong(n->v1_trap->specific_trap));
        PYDICT_SET_ITEM(
                x, "time_stamp", PyInt_FromLong(n->v1_trap->time_stamp));

        if (n->v1_trap->enterprise.len > 0) {
            PyObject *l = PyList_New(n->v1_trap->enterprise.len);
            int i;
            for (i = 0; i < n->v1_trap->enterprise.len; i++) {
                PyList_SetItem(
                        l, i, PyInt_FromLong(n->v1_trap->enterprise.oid[i]));
            }
            PYDICT_SET_ITEM(x, "enterprise", l);
        }
    }

    PYDICT_SET_ITEM(d, "snmpa", x);
}

/* event delivered from the CONFD_NOTIF_CONFIRMED_COMMIT flag */
/*
    struct confd_confirmed_commit_notification {
        enum confd_confirmed_commit_type type;
        unsigned int timeout; * in seconds
                                timeout is > 0 when type is
                                CONFD_CONFIRMED_COMMIT, otherwise it is 0 *
        struct confd_user_info uinfo;
    };
*/
static void build_confirmed_commit_notification(
        PyObject *d, struct confd_confirmed_commit_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "type", PyInt_FromLong(n->type));
    PYDICT_SET_ITEM(x, "timeout", PyInt_FromLong(n->timeout));
    PYDICT_SET_ITEM(x, "uinfo", newConfdUserInfo(&n->uinfo));

    PYDICT_SET_ITEM(d, "confirm", x);
}

/* event delivered from the CONFD_NOTIF_UPGRADE_EVENT flag */
/*
    struct confd_upgrade_notification {
        enum confd_upgrade_event_type event;
    };
*/
static void build_upgrade_notification(
        PyObject *d, struct confd_upgrade_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "event", PyInt_FromLong(n->event));

    PYDICT_SET_ITEM(d, "upgrade", x);
}

/* event delivered from the CONFD_NOTIF_COMMIT_PROGRESS and
   CONFD_NOTIF_PROGRESS flag
*/
/*
    struct confd_progress_notification {
        enum confd_progress_event_type type; * progress event type
        unsigned long long timestamp;        * microseconds since Epoch
        unsigned long long duration;         * when type is CONFD_PROGRESS_STOP
        int usid;                            * user session id
        int tid;                             * transaction id
        enum confd_dbname datastore;         * datastore name
        char* context;                       * session context
        char trace_id[MAX_TRACE_ID_LEN];     * per request unique trace id
        char* subsystem;                     * name of subsystem
        char* phase;                         * transaction phase
        char msg[BUFSIZ];                    * progress event message
        char* annotation;                    * metadata about event
        * NCS specific values (removed at compile time for ConfD)
        char* service;                       * invoked service instance
        char* service_phase;                 * callback phase of invoked service
        unsigned long long commit_queue_id;  * item id (0 means not applicable)
        char* node;                          * remote node name
        char* device;                        * device name
        char* device_phase;                  * device communication phase
        char* package;                       * package that generated event
    };
*/
static void build_progress_notification(
        PyObject *d, struct confd_progress_notification *n)
{
    PyObject *x = PyDict_New();
    PYDICT_SET_ITEM(x, "type", PyInt_FromLong(n->type));
    PYDICT_SET_ITEM(x, "timestamp", PyLong_FromUnsignedLong(n->timestamp));
    if (n->type == CONFD_PROGRESS_STOP) {
        PYDICT_SET_ITEM(x, "duration", PyLong_FromUnsignedLong(n->duration));
    }
    PYDICT_SET_ITEM(x, "usid", PyInt_FromLong(n->usid));
    PYDICT_SET_ITEM(x, "tid", PyInt_FromLong(n->tid));
    PYDICT_SET_ITEM(x, "datastore", PyInt_FromLong(n->datastore));
    if (n->context != NULL) {
        PYDICT_SET_ITEM(x, "context", PyString_FromString(n->context));
    }
    if (n->trace_id[0] != '\0') {
        PYDICT_SET_ITEM(x, "trace_id", PyString_FromString(n->trace_id));
    }
    if (n->subsystem != NULL) {
        PYDICT_SET_ITEM(x, "subsystem", PyString_FromString(n->subsystem));
    }
    if (n->phase != NULL) {
        PYDICT_SET_ITEM(x, "phase", PyString_FromString(n->phase));
    }
    if (n->msg[0] != '\0') {
        PYDICT_SET_ITEM(x, "msg", PyString_FromString(n->msg));
    }
    if (n->annotation != NULL) {
        PYDICT_SET_ITEM(x, "annotation",
                        PyString_FromString(n->annotation));
    }
#ifdef CONFD_PY_PRODUCT_NCS
    if (n->service != NULL) {
        PYDICT_SET_ITEM(x, "service", PyString_FromString(n->service));
    }
    if (n->service_phase != NULL) {
        PYDICT_SET_ITEM(x, "service_phase",
                        PyString_FromString(n->service_phase));
    }
    if (n->commit_queue_id != 0) {
        PYDICT_SET_ITEM(x, "commit_queue_id",
                        PyLong_FromUnsignedLong(n->commit_queue_id));
    }
    if (n->node != NULL) {
        PYDICT_SET_ITEM(x, "node", PyString_FromString(n->node));
    }
    if (n->device != NULL) {
        PYDICT_SET_ITEM(x, "device", PyString_FromString(n->device));
    }
    if (n->device_phase != NULL) {
        PYDICT_SET_ITEM(x, "device_phase",
                        PyString_FromString(n->device_phase));
    }
    if (n->package != NULL) {
        PYDICT_SET_ITEM(x, "package", PyString_FromString(n->package));
    }
#endif
    PYDICT_SET_ITEM(d, "progress", x);
}

/* event delivered from the CONFD_NOTIF_STREAM_EVENT flag */
/*
    struct confd_stream_notification {
        enum confd_stream_notif_type type;
        struct confd_datetime event_time;
        confd_tag_value_t *values;
        int nvalues;
        char *replay_error;
    };
*/
static void build_stream_notification(
        PyObject *d, struct confd_stream_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "type", PyInt_FromLong(n->type));

    if (n->type == CONFD_STREAM_REPLAY_FAILED && n->replay_error != NULL) {
        PYDICT_SET_ITEM(x, "error", PyString_FromString(n->replay_error));
    }
    else if (n->type == CONFD_STREAM_NOTIFICATION_EVENT) {
        PYDICT_SET_ITEM(x, "event_time", newConfdDateTime(&n->event_time));
        PyObject *l = PyList_New(n->nvalues);
        int i;
        for (i = 0; i < n->nvalues; i++) {
            PyList_SetItem(l, i, PyConfd_TagValue_New(&n->values[i]));
        }
        PYDICT_SET_ITEM(x, "values", l);
    }

    PYDICT_SET_ITEM(d, "stream", x);
}

#ifdef CONFD_PY_PRODUCT_NCS
/* event delivered from the NCS_NOTIF_CQ_PROGRESS flag */
/*
    struct ncs_cq_progress_notification {
        enum ncs_cq_progress_notif_type type;
        struct confd_datetime timestamp;
        char* cq_tag;
        u_int64_t cq_id;
        char **completed_devices;
        int  ncompleted_devices;
        char **transient_devices;
        int  ntransient_devices;
        char **failed_devices;
        char **failed_reasons;
        int  nfailed_devices;
        char **completed_services;
        confd_value_t **completed_services_completed_devices;
        int  ncompleted_services;
        char **failed_services;
        confd_value_t **failed_services_completed_devices;
        confd_value_t **failed_services_failed_devices;
        int  nfailed_services;
    };
*/
static void build_ncs_cq_progress_notification(
        PyObject *d, struct ncs_cq_progress_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "type", PyInt_FromLong(n->type));
    PYDICT_SET_ITEM(x, "timestamp", newConfdDateTime(&n->timestamp));
    if (n->cq_tag != NULL) {
        PYDICT_SET_ITEM(x, "cq_tag", PyString_FromString(n->cq_tag));
    }
    PYDICT_SET_ITEM(x, "cq_id", PyLong_FromUnsignedLong(n->cq_id));

    if (n->ncompleted_devices > 0) {
        PyObject *l = PyList_New(n->ncompleted_devices);
        int i;
        for (i = 0; i < n->ncompleted_devices; i++) {
            PyList_SetItem(l, i, PyString_FromString(n->completed_devices[i]));
        }
        PYDICT_SET_ITEM(x, "completed_devices", l);
    }

    if (n->ntransient_devices > 0) {
        PyObject *l = PyList_New(n->ntransient_devices);
        int i;
        for (i = 0; i < n->ntransient_devices; i++) {
            PyList_SetItem(l, i, PyString_FromString(n->transient_devices[i]));
        }
        PYDICT_SET_ITEM(x, "transient_devices", l);
    }

    if (n->nfailed_devices > 0) {
        PyObject *ld = PyList_New(n->nfailed_devices);
        PyObject *lr = PyList_New(n->nfailed_devices);
        int i;
        for (i = 0; i < n->nfailed_devices; i++) {
            PyList_SetItem(ld, i, PyString_FromString(n->failed_devices[i]));
            PyList_SetItem(lr, i, PyString_FromString(n->failed_reasons[i]));
        }
        PYDICT_SET_ITEM(x, "failed_devices", ld);
        PYDICT_SET_ITEM(x, "failed_reasons", lr);
    }

    if (n->ncompleted_services > 0) {
        PyObject *lcs = PyList_New(n->ncompleted_services);
        PyObject *lcd = PyList_New(n->ncompleted_services);
        int i;
        for (i = 0; i < n->ncompleted_services; i++) {
            PyList_SetItem(lcs, i,
                           PyString_FromString(n->completed_services[i]));
            PyList_SetItem(lcd, i,
                newConfdValue(n->completed_services_completed_devices[i]));
        }
        PYDICT_SET_ITEM(x, "completed_services", lcs);
        PYDICT_SET_ITEM(x, "completed_services_completed_devices", lcd);
    }

    if (n->nfailed_services > 0) {
        PyObject *lfs = PyList_New(n->nfailed_services);
        PyObject *lcd1 = PyList_New(n->nfailed_services);
        PyObject *lfd = PyList_New(n->nfailed_services);
        int i;
        for (i = 0; i < n->nfailed_services; i++) {
            PyList_SetItem(lfs, i,
                           PyString_FromString(n->failed_services[i]));
            PyList_SetItem(lcd1, i,
                newConfdValue(n->failed_services_completed_devices[i]));
            PyList_SetItem(lfd, i,
                newConfdValue(n->failed_services_failed_devices[i]));
        }
        PYDICT_SET_ITEM(x, "failed_services", lfs);
        PYDICT_SET_ITEM(x, "failed_services_completed_devices", lcd1);
        PYDICT_SET_ITEM(x, "failed_services_failed_devices", lfd);
    }

    if (n->trace_id != NULL) {
        PYDICT_SET_ITEM(x, "trace_id", PyString_FromString(n->trace_id));
    }

    PYDICT_SET_ITEM(d, "cq_progress", x);
}

/* event delivered from the NCS_NOTIF_CALL_HOME_INFO flag */
/*
    struct ncs_call_home_notification {
        enum ncs_call_home_info_type type; * type of call home event
        char* device;                      * the device connected
        struct confd_ip ip;                * IP address of device
        u_int16_t port;                    * port of device
        char* ssh_host_key;                * host key of device
        char* ssh_key_alg;                 * SSH key algorithm
    };
*/
static void build_ncs_call_home_notification(
        PyObject *d, struct ncs_call_home_notification *n)
{
    PyObject *x = PyDict_New();

    PYDICT_SET_ITEM(x, "type", PyInt_FromLong(n->type));

    if (n->type == CALL_HOME_DEVICE_CONNECTED) {
        PYDICT_SET_ITEM(x, "device", PyString_FromString(n->device));
    }
    PYDICT_SET_ITEM(x, "af", PyInt_FromLong(n->ip.af));
    if (n->ip.af == AF_INET) {
        char tmp[INET_ADDRSTRLEN + 1];
        if (inet_ntop(n->ip.af,
                      &n->ip.ip.v4,
                      tmp, INET_ADDRSTRLEN)) {
            PYDICT_SET_ITEM(x, "ip4", PyString_FromString(tmp));
        }
        else {
            PYDICT_SET_ITEM(
                x, "ip4",
                PyString_FromString("ip address conversion failed"));
        }
    }
    else if (n->ip.af == AF_INET6) {
        char tmp[INET6_ADDRSTRLEN + 1];
        if (inet_ntop(n->ip.af,
                      &n->ip.ip.v6,
                      tmp, INET6_ADDRSTRLEN)) {
            PYDICT_SET_ITEM(x, "ip6", PyString_FromString(tmp));
        }
        else {
            PYDICT_SET_ITEM(
                x, "ip6",
                PyString_FromString("ip address conversion failed"));
        }
    }
    PYDICT_SET_ITEM(x, "port", PyInt_FromLong(n->port));
    PYDICT_SET_ITEM(x, "ssh_host_key",
                    PyString_FromString(n->ssh_host_key));
    PYDICT_SET_ITEM(x, "ssh_key_alg", PyString_FromString(n->ssh_key_alg));

    PYDICT_SET_ITEM(d, "call_home", x);
}

/* event delivered from the NCS_NOTIF_AUDIT_NETWORK flag */
/*
    struct ncs_audit_network_notification {
        int usid;                          * user session id
        int tid;                           * transaction id
        char* user;                        * username
        char* device;                      * device name
        char trace_id[MAX_TRACE_ID_LEN];   * trace id for the transaction
        char* config;                      * the payload sent to the device
    };
*/
static void build_ncs_audit_network_notification(
        PyObject *d, struct ncs_audit_network_notification *n)
{
    PyObject *x = PyDict_New();
    PYDICT_SET_ITEM(x, "usid", PyInt_FromLong(n->usid));
    PYDICT_SET_ITEM(x, "tid", PyInt_FromLong(n->tid));
    PYDICT_SET_ITEM(x, "user", PyString_FromString(n->user));
    PYDICT_SET_ITEM(x, "device", PyString_FromString(n->device));
    if (n->trace_id[0] != '\0') {
        PYDICT_SET_ITEM(x, "trace_id", PyString_FromString(n->trace_id));
    }
    if (n->config != NULL) {
        PYDICT_SET_ITEM(x, "config", PyString_FromString(n->config));
    }

    PYDICT_SET_ITEM(d, "audit_network", x);
}
#endif

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_events_read_notification, EXT_API_FUN_EVENTS_READ_NOTIFICATION)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int sock;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&", kwlist,
            &sock_arg, &sock)) {
        return NULL;
    }

    confdNotification *notif = newConfdNotification();

    CHECK_CONFD_ERR_EXECERR(confd_read_notification(sock, &notif->n),
                            Py_DECREF(notif));

    int type = notif->n.type;

    PyObject *d = PyDict_New();

    PYDICT_SET_ITEM(d, "_notif", (PyObject*)notif);
    PYDICT_SET_ITEM(d, "type", PyInt_FromLong(type));

    if (type == CONFD_NOTIF_AUDIT) {
        build_audit_notification(d, &notif->n.n.audit);
    }
    else if (type == CONFD_NOTIF_DAEMON ||
             type == CONFD_NOTIF_NETCONF ||
             type == CONFD_NOTIF_DEVEL ||
             type == CONFD_NOTIF_JSONRPC ||
             type == CONFD_NOTIF_WEBUI ||
             type == CONFD_NOTIF_TAKEOVER_SYSLOG) {
        build_syslog_notification(d, &notif->n.n.syslog);
    }
    else if (type == CONFD_NOTIF_COMMIT_SIMPLE) {
        build_commit_notification(d, &notif->n.n.commit);
    }
    else if (type == CONFD_NOTIF_COMMIT_DIFF) {
        build_commit_diff_notification(d, &notif->n.n.commit_diff);
    }
    else if (type == CONFD_NOTIF_USER_SESSION) {
        build_user_sess_notification(d, &notif->n.n.user_sess);
    }
    else if (type == CONFD_NOTIF_HA_INFO) {
        build_ha_notification(d, &notif->n.n.hnot);
    }
    else if (type == CONFD_NOTIF_SUBAGENT_INFO) {
        build_subagent_notification(d, &notif->n.n.subagent);
    }
    else if (type == CONFD_NOTIF_COMMIT_FAILED) {
        build_commit_failed_notification(d, &notif->n.n.cfail);
    }
    else if (type == CONFD_NOTIF_SNMPA) {
        build_snmpa_notification(d, &notif->n.n.snmpa);
    }
    else if (type == CONFD_NOTIF_FORWARD_INFO) {
        build_forward_notification(d, &notif->n.n.forward);
    }
    else if (type == CONFD_NOTIF_CONFIRMED_COMMIT) {
        build_confirmed_commit_notification(d, &notif->n.n.confirm);
    }
    else if (type == CONFD_NOTIF_UPGRADE_EVENT) {
        build_upgrade_notification(d, &notif->n.n.upgrade);
    }
    else if (type == CONFD_NOTIF_COMMIT_PROGRESS) {
        build_progress_notification(d, &notif->n.n.progress);
    }
    else if (type == CONFD_NOTIF_COMMIT_PROGRESS ||
             type == CONFD_NOTIF_PROGRESS) {
        build_progress_notification(d, &notif->n.n.progress);
    }
    else if (type == CONFD_NOTIF_STREAM_EVENT) {
        build_stream_notification(d, &notif->n.n.stream);
    }
#ifdef CONFD_PY_PRODUCT_NCS
    else if (type == NCS_NOTIF_CQ_PROGRESS) {
        build_ncs_cq_progress_notification(d, &notif->n.n.cq_progress);
    }
    else if (type == NCS_NOTIF_CALL_HOME_INFO) {
        build_ncs_call_home_notification(d, &notif->n.n.call_home);
    }
    else if (type == NCS_NOTIF_AUDIT_NETWORK) {
        build_ncs_audit_network_notification(d, &notif->n.n.audit_network);
    }
#endif

    /*
     * These notification types don't have any additional data
     *
     * CONFD_NOTIF_HEARTBEAT
     * CONFD_NOTIF_HEALTH_CHECK
     * NCS_NOTIF_PACKAGE_RELOAD
     * CONFD_NOTIF_REOPEN_LOGS
     */

    /*
     * These are not found in the C-api
     *
     * CONFD_NOTIF_AUDIT_SYNC
     * CONFD_NOTIF_HA_INFO_SYNC
    */

    CONFD_EXEC(confd_free_notification(&notif->n));

    return d;
}


/* ------------------------------------------------------------------------- */

EXT_API_FUN(_events_diff_notification_done,
            EXT_API_FUN_EVENTS_DIFF_NOTIFICATION_DONE)
{
    static char *kwlist[] = {
        "sock",
        "tctx",
        NULL
    };

    int sock;
    confdTransCtxRef *tctx;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&O", kwlist,
            &sock_arg, &sock,
            &tctx)) {
        return NULL;
    }

    if (!isConfdTransCtxRef((PyObject *)tctx)) {
        PyErr_Format(PyExc_TypeError,
            "tctx argument must be a "
            CONFD_PY_MODULE ".TransCtxRef instance");
        return NULL;
    }

    CHECK_CONFD_ERR(confd_diff_notification_done(sock, tctx->tc));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_events_sync_audit_notification,
            EXT_API_FUN_EVENTS_SYNC_AUDIT_NOTIFICATION)
{
    static char *kwlist[] = {
        "sock",
        "usid",
        NULL
    };

    int sock;
    int usid;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&i", kwlist,
            &sock_arg, &sock,
            &usid)) {
        return NULL;
    }

    CHECK_CONFD_ERR(confd_sync_audit_notification(sock, usid));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

EXT_API_FUN(_events_sync_ha_notification,
            EXT_API_FUN_EVENTS_SYNC_HA_NOTIFICATION)
{
    static char *kwlist[] = {
        "sock",
        NULL
    };

    int sock;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&", kwlist,
            &sock_arg, &sock)) {
        return NULL;
    }

    CHECK_CONFD_ERR(confd_sync_ha_notification(sock));

    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------------- */

#ifdef CONFD_PY_PRODUCT_NCS
EXT_API_FUN(_events_sync_audit_network_notification,
            EXT_API_FUN_EVENTS_SYNC_AUDIT_NETWORK_NOTIFICATION)
{
    static char *kwlist[] = {
        "sock",
        "usid",
        NULL
    };

    int sock;
    int usid;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "O&i", kwlist,
            &sock_arg, &sock,
            &usid)) {
        return NULL;
    }

    CHECK_CONFD_ERR(ncs_sync_audit_network_notification(sock, usid));

    Py_RETURN_NONE;
}
#endif
/* ------------------------------------------------------------------------- */

#include "../doc/src/events_doc.c"


#define PYMOD_ENTRY(NAME) {# NAME, (PyCFunction)_events_ ## NAME, \
                           METH_VARARGS | METH_KEYWORDS, \
                           _events_ ## NAME ## __doc__}

static PyMethodDef confd_events_Methods[] = {

    PYMOD_ENTRY(notifications_connect),
    PYMOD_ENTRY(notifications_connect2),
    PYMOD_ENTRY(read_notification),
    PYMOD_ENTRY(diff_notification_done),
    PYMOD_ENTRY(sync_audit_notification),
    PYMOD_ENTRY(sync_ha_notification),
#ifdef CONFD_PY_PRODUCT_NCS
    PYMOD_ENTRY(sync_audit_network_notification),
#endif

    {NULL, NULL, 0, NULL}
};

#undef PYMOD_ENTRY

/* ************************************************************************ */
/* Module initialization                                                    */
/* ************************************************************************ */

#define MODULE CONFD_PY_MODULE ".events"

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        MODULE,
        EVENTS_MODULE_DOCSTR(CONFD_PY_PRODUCT),
        0,
        confd_events_Methods,
        NULL,
        NULL,
        NULL,
        NULL
};

PyObject* init__events_module(void)
{
    PyObject *m = NULL;

    if ((m = PyModule_Create(&moduledef)) == NULL) {
        goto error;
    }

    init_events_types(m);

    /* Add constants */
#define ADD_CONST(C_NAME, PY_NAME) \
    (void)PyModule_AddIntConstant(m, PY_NAME, C_NAME);

#define ADD_CONST_STR(C_NAME, PY_NAME) \
    (void)PyModule_AddStringConstant(m, PY_NAME, C_NAME);

#include "gen_add_events_const.c"

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
