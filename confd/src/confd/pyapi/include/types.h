/*
 * Copyright 2013 Tail-F Systems AB
 */

#ifndef NCSCONFD_TYPES_H
#define NCSCONFD_TYPES_H

#include <confd.h>
#include <confd_maapi.h>
#include "confdpy_config.h"


/* ************************************************************************ */
/*                                                                          */
/* ************************************************************************ */

PyObject* init_types_module(void);
void init_dp_types(PyObject *m);
void init_events_types(PyObject *m);
void init_lib_types(PyObject *m);
void init_maapi_types(PyObject *m);

/* ************************************************************************ */
/* confd_value_t -> confd._lib.Value                                        */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD
    confd_value_t ob_val;
} PyConfd_Value_Object;

#define PyConfd_Value_PTR(v) (&(((PyConfd_Value_Object*)(v))->ob_val))

PyObject* newConfdValue(confd_value_t *v);
extern PyConfd_Value_Object *PyConfd_Value_New_DupTo(const confd_value_t *v);
extern PyObject *PyConfd_Value_New_DupTo_Py(const confd_value_t *v);
extern PyConfd_Value_Object *PyConfd_Value_New_NoInit(void);
extern int PyConfd_Value_CheckExact(PyObject *o);
extern PyObject *PyConfd_Values_New_DupTo_PyList(
        const confd_value_t *values, int num);


/* ************************************************************************ */
/* confd_tag_value_t -> confd._lib.TagValue                                 */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;
    confd_tag_value_t tv;
} PyConfd_TagValue_Object;

#define PyConfd_TagValue_PTR(v) (&(((PyConfd_TagValue_Object *)(v))->tv))

extern PyObject* PyConfd_TagValue_New(confd_tag_value_t *tv);
extern int PyConfd_TagValue_CheckExact(PyObject *o);

/* ************************************************************************* */
/* Python PyConfd_TagValue_Object list helper functions                      */
/* ************************************************************************* */

typedef struct {
    int size;
    confd_tag_value_t *list;
} py_confd_tag_value_t_list_t;

extern void init_py_confd_tag_value_t_list(py_confd_tag_value_t_list_t *sl);
extern int alloc_py_confd_tag_value_t_list(
        PyObject *o, py_confd_tag_value_t_list_t *sl, const char argname[]);
extern void free_py_confd_tag_value_t_list(py_confd_tag_value_t_list_t *sl);

/* ************************************************************************ */
/* confd_attr_value_t -> confd._lib.AttrValue                               */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;

    /*
     * attr really u_int32_t, but converted to object sine the PyMemberDef
     * T_UINT/T_ULONG/T_ULONGLONG all seems to return an <int>, which
     * is to small in 32-bit linux
     */
    PyObject *attr;

    PyObject *v;

} PyConfd_AttrValue_Object;

#define PyConfd_AttrValue_PTR(v) (&(((PyConfd_AttrValue_Object *)(v))->av))

extern PyObject* PyConfd_AttrValue_New_DupTo(const confd_attr_value_t *av);
extern PyObject* PyConfd_AttrValue_New_DupTo_Py(const confd_attr_value_t *av);
extern int PyConfd_AttrValue_CheckExact(PyObject *o);



/* ************************************************************************ */
/* struct xml_tag -> confd._lib.XmlTag                                      */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;

    u_int32_t tag;
    u_int32_t ns;

} PyConfd_XmlTag_Object;

extern PyObject* PyConfd_XmlTag_New(const struct xml_tag *xmltag);
extern int PyConfd_XmlTag_CheckExact(PyObject *o);



/* ************************************************************************ */
/* confd_hkeypath_t -> confd._lib.HKeypathRef                               */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;
    confd_hkeypath_t *kp;
    int autoFree;
} confdHKeypathRef;

extern PyObject* newConfdHKeypathRefAutoFree(confd_hkeypath_t *kp);
extern PyObject* newConfdHKeypathRefNoAutoFree(confd_hkeypath_t *kp);
extern int isConfdHKeypathRef(PyObject *o);
extern void unrefConfdHKeypathRef(PyObject *kpref);

PyObject* _confd_hkeypath2PyString(const confd_hkeypath_t *hkeypath,
                                   int kp_len);
int hkeypath2str(char *buf, int n, const confd_hkeypath_t *hkeypath,
                 int kp_len);
/* ************************************************************************ */
/* struct confd_trans_ctx -> confd._lib.TransCtxRef                         */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;
    struct confd_trans_ctx *tc;
} confdTransCtxRef;

extern PyObject* newConfdTransCtxRef(struct confd_trans_ctx *tc);
extern int isConfdTransCtxRef(PyObject *o);

/* ************************************************************************ */
/* struct confd_tr_item -> _confd.dp.TrItemRef                              */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;
    struct confd_tr_item *tr;
} confdTrItemRef;

extern PyObject* newConfdTrItemRef(struct confd_tr_item *tr);
extern int isConfdTrItemRef(PyObject *o);

/* ************************************************************************ */
/* struct confd_db_ctx -> confd._dp.DbCtxRef                                */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;
    struct confd_db_ctx *dbx;
} confdDbCtxRef;

extern PyObject* newConfdDbCtxRef(struct confd_db_ctx *dbx);
extern int isConfdDbCtxRef(PyObject *o);

/* ************************************************************************ */
/* struct confd_user_info -> confd._lib.UserInfo                            */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;

    PyObject *username;
    int usid;
    PyObject *context;
    int af;
    PyObject *addr;
    PyObject *snmp_v3_ctx;
    PyObject *clearpass;

    PyObject *logintime;

    enum confd_proto proto;
    int port;
    int lmode;
    int flags;
    int actx_thandle;
    struct confd_user_info *uinfo;

    int free_uinfo;

} confdUserInfo;

extern PyObject* newConfdUserInfo(struct confd_user_info *ui);
extern PyObject* newConfdUserInfoFree(struct confd_user_info *ui);
extern int isConfdUserInfo(PyObject *o);

/* ************************************************************************ */
/* struct confd_authorization_info -> confd._lib.AuthorizationInfo          */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;

    PyObject *groups;
} confdAuthorizationInfo;

extern PyObject* newConfdAuthorizationInfo(struct confd_authorization_info *tc);
extern int isConfdAuthorizationInfo(PyObject *o);

/* ************************************************************************ */
/* struct confd_auth_ctx -> confd._dp.AuthCtxRef                            */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;
    struct confd_auth_ctx *actx;
    PyObject *groups;
    PyObject *logno;
    PyObject *reason;
} confdAuthCtxRef;

extern PyObject* newConfdAuthCtxRef(struct confd_auth_ctx *actx);
extern int isConfdAuthCtxRef(PyObject *o);

/* ************************************************************************ */
/* struct confd_authorization_ctx -> confd._dp.AuthorizationCtxRef          */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;
    struct confd_authorization_ctx *actx;
    PyObject *uinfo;
    PyObject *groups;
} confdAuthorizationCtxRef;

extern PyObject* newConfdAuthorizationCtxRef(
        struct confd_authorization_ctx *actx);
extern int isConfdAuthorizationCtxRef(PyObject *o);

/* ************************************************************************ */
/* struct confd_notification_ctx -> confd._dp.NotificationCtxRef            */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;
    struct confd_notification_ctx *nctx;
} confdNotificationCtxRef;

extern PyObject* newConfdNotificationCtxRef(
        struct confd_notification_ctx *nctx);
extern int isConfdNotificationCtxRef(PyObject *o);

/* ************************************************************************ */
/* struct confd_notifications_data -> confd._events.NotificationsData       */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;

    struct confd_notifications_data nd;

} confdNotificationsData;

extern int isConfdNotificationsData(PyObject *o);

/* ************************************************************************ */
/* just holds a struct confd_notification                                   */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;

    struct confd_notification n;

} confdNotification;

extern confdNotification *newConfdNotification(void);

/* ************************************************************************ */
/* struct confd_datetime -> confd._lib.DateTime                             */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;
    struct confd_datetime dt;
} confdDateTime;

extern PyObject* newConfdDateTime(struct confd_datetime *dt);
extern int isConfdDateTime(PyObject *o);

/* ************************************************************************ */
/* struct confd_snmp_varbind -> confd._lib.SnmpVarbind                      */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;
    struct confd_snmp_varbind vb;
} confdSnmpVarbind;

extern PyObject* newConfdSnmpVarbind(struct confd_snmp_varbind *vb);
extern int isConfdSnmpVarbind(PyObject *o);

/* ************************************************************************ */
/* struct confd_daemon_ctx -> confd._dp.DaemonCtxRef                        */
/* ************************************************************************ */


typedef struct {
    PyObject_HEAD
    struct confd_daemon_ctx *ctx;
    int autoFree;
} PyConfd_DaemonCtxRef_Object;

#define PyConfd_DaemonCtxRef_PTR(v) (((v)->ctx))

extern PyConfd_DaemonCtxRef_Object *PyConfd_DaemonCtxRef_New(
        struct confd_daemon_ctx *ctx);
extern PyConfd_DaemonCtxRef_Object *PyConfd_DaemonCtxRef_New_NoAutoFree(
        struct confd_daemon_ctx *ctx);
extern int PyConfd_DaemonCtxRef_CheckExact(PyObject *o);

/* ************************************************************************ */
/* struct maapi_rollback -> confd._maapi.MaapiRollback                      */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD
    struct maapi_rollback rollback;

    const char *creator_;
    const char *datestr_;
    const char *via_;
    const char *label_;
    const char *comment_;
} PyConfd_MaapiRollback_Object;

#define PyConfd_MaapiRollback_PTR(v) \
    (&(((PyConfd_MaapiRollback *)tv)->rollback))

extern PyConfd_MaapiRollback_Object
            *PyConfd_MaapiRollback_New(const struct maapi_rollback *rollback);
extern int PyConfd_MaapiRollback_CheckExact(PyObject *o);


/* ************************************************************************ */
/* struct confd_query_result -> confd._lib.QueryResult                      */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD

    struct confd_query_result *qrs;

    enum confd_query_result_type type;
    int offset;
    int nresults;
    int nelements;

} PyConfd_QueryResult_Object;

#define PyConfd_QueryResult_PTR(v) \
    (&(((PyConfd_QueryResult *)v)->qrs))

extern PyConfd_QueryResult_Object
            *PyConfd_QueryResult_New(struct confd_query_result *qrs);
extern int PyConfd_QueryResult_CheckExact(PyObject *o);




/* ************************************************************************ */
/*                                                                          */
/* ************************************************************************ */

extern int confdValue_arg(PyObject *arg, void *p);

/* ************************************************************************ */
/* struct confd_cs_node -> _lib.CsNode                                      */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD
    struct confd_cs_node *node;
} confdCsNode;

extern PyObject *newConfdCsNode(struct confd_cs_node *node);
extern int isConfdCsNode(PyObject *o);

/* ************************************************************************ */
/* struct confd_cs_node_info -> _lib.CsNodeInfo                             */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD
    struct confd_cs_node_info info;
} confdCsNodeInfo;

extern PyObject *newConfdCsNodeInfo(struct confd_cs_node_info *info);
extern int isConfdCsNodeInfo(PyObject *o);

/* ************************************************************************ */
/* struct confd_type -> _lib.CsType                                         */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD
    struct confd_type *type;
} confdCsType;

extern PyObject *newConfdCsType(struct confd_type *type);
extern int isConfdCsType(PyObject *o);

/* ************************************************************************ */
/* struct confd_cs_choice -> _lib.CsChoice                                  */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD
    struct confd_cs_choice *choice;
} confdCsChoice;

extern PyObject *newConfdCsChoice(struct confd_cs_choice *choice);
extern int isConfdCsChoice(PyObject *o);

/* ************************************************************************ */
/* struct confd_cs_case -> _lib.CsCase                                      */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD
    struct confd_cs_case *cscase;
} confdCsCase;

extern PyObject *newConfdCsCase(struct confd_cs_case *cscase);
extern int isConfdCsCase(PyObject *o);

/* ************************************************************************ */
/* struct confd_list_filter -> confd._lib.ListFilter                        */
/* ************************************************************************ */

typedef struct {
    PyObject_HEAD;
    struct confd_list_filter *lf;
    PyObject *lf_owner;
} confdListFilter;

extern PyObject* newConfdListFilter(struct confd_list_filter *lf,
                                    PyObject *lf_owner);
extern int isConfdListFilter(PyObject *o);

/* ************************************************************************* */
/* Python PyConfd_Value_Object list helper functions                         */
/* ************************************************************************* */

typedef struct {
    int size;
    confd_value_t *list;
} py_confd_value_t_list_t;

extern void init_py_confd_value_t_list(py_confd_value_t_list_t *sl);
extern int alloc_py_confd_value_t_list(
        PyObject *o, py_confd_value_t_list_t *sl, const char argname[]);
extern void free_py_confd_value_t_list(py_confd_value_t_list_t *sl);

/* ************************************************************************* */
/* Python callback method argument check                                     */
/* ************************************************************************* */

extern int check_callback_method(PyObject *o, const char *cbname, int argcount);

#define CHECK_CB_MTH(obj, name, count) \
        if (!check_callback_method(obj, name, count)) return NULL;


/* ************************************************************************* */
/* Utility functions                                                         */
/* ************************************************************************* */

extern void PYDICT_SET_ITEM(PyObject *d, const char *name, PyObject *obj);

#endif // NCSCONFD_TYPES_H
