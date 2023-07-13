/*
 * Copyright 2005-2009 Tail-f Systems AB
 *
 * Permission to use this code as a starting point hereby granted
 *
 * Command line interface towards some cdb and maapi functions
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <sys/poll.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <assert.h>

#include <confd.h>
#include <confd_cdb.h>
#include <confd_maapi.h>

#include "ietf-origin.h"

/* #define EXTERNAL_IPC */ /* Uncomment this to provide support for user-
                            * defined IPC towards the ConfD/NCS daemon.
                            * The CONFD_IPC_EXTADDR and CONFD_IPC_EXTSOPATH
                            * - or NCS_IPC_EXTADDR and NCS_IPC_EXTSOPATH -
                            * environment variables can then be used to
                            * request a connection using this IPC mechanism,
                            * see the deployment chapter in the User Guide.
                            * Requires that the shared object provides the
                            * getaddrinfo() and socket() IPC callbacks.
                            * Note, on Linux this requires that -ldl is
                            * added to the LIBS definition in the Makefile.
                            */

#ifdef EXTERNAL_IPC
#include <dlfcn.h>
#include "ipc_drv.h"
#endif

#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MAX_ARGS
#define MAX_ARGS 16
#endif

struct cmdline {
    int lineno;
    int argc;
    char *argv[MAX_ARGS];
    struct cmdline *next;
};

struct script {
    char *source;
    struct cmdline *pgm;
};


/* fallback if schema isn't loaded */
#define MAX_ELEMS_PER_OBJECT 42

static char *progname;
static int debug_trace = 0;
static enum confd_debug_level debug = CONFD_SILENT;
static FILE *debugf = NULL;
static int family, type, protocol;
static struct sockaddr *addr;
static socklen_t addrlen;
#ifdef EXTERNAL_IPC
static struct confd_ext_ipc_cbs *ecbs;
#endif
static enum cdb_db_type db = CDB_RUNNING;
static int sess_flags = -1;
static int cs = -1;             /* global cdb socket variable */
static int ms = -1;             /* global maapi socket variable */
static int mtid = 0;            /* global maapi transaction id */
static int mflags = 0;          /* global maapi transaction flags */
static int gmcommit = 0;        /* global auto-commit (0 = enabled) */
static int mcommit = 0;         /* whether mtid has been commited or not */
static int hs = -1;             /* global ha socket variable */
static enum confd_dbname mdb = CONFD_RUNNING;
static char *muser = "system";
static char *groups[32]; int ngroups = 0;
static char *mctxt = "system";
static int preserve_session = 1;
static int partial_lock_id = 0;
static int load_schema = 0;     /* -1 = never load, 0 = not loaded yet,
                                   1 = already loaded  */
static int leaf_iter = 0;       /* If non zero, do diff_iterate on
                                 * leaf-lists as leafs. Deprecated. */
static int biased_free = 1;    /* global biased free terms in output */
static enum confd_db_status status = CONFD_DB_VALID;

#ifdef NCS
#define SERVER "NCS"
#define PORT NCS_PORT
#define IPC_ADDR "NCS_IPC_ADDR"
#define IPC_PORT "NCS_IPC_PORT"
#define IPC_EXTADDR "NCS_IPC_EXTADDR"
#define IPC_EXTSOPATH "NCS_IPC_EXTSOPATH"
#else
#define SERVER "ConfD"
#define PORT CONFD_PORT
#define IPC_ADDR "CONFD_IPC_ADDR"
#define IPC_PORT "CONFD_IPC_PORT"
#define IPC_EXTADDR "CONFD_IPC_EXTADDR"
#define IPC_EXTSOPATH "CONFD_IPC_EXTSOPATH"
#endif

#define OK(E) ok((E), #E, __FUNCTION__, __LINE__, "FAILED")
#define OK_PREF(prefix, E) ok((E), #E, __FUNCTION__, __LINE__, (prefix))

#define CMD_CDB        (1 << 0)
#define CMD_CDB_SESS   (1 << 1)
#define CMD_CDB_SUB    (1 << 2)
#define CMD_MAAPI      (1 << 3)
#define CMD_MAAPI_NOUSER (1 << 4)
#define CMD_MAAPI_NOTRANS (1 << 5)
#define CMD_HA         (1 << 6)
#define CMD_WANT_SCHEMA  (1 << 7)

#define SUBWAIT_ITER_SUSPEND 1
#define SUBWAIT_ITER_USID    2

#define DBGLOG(...) \
    if (debugf) { \
        fprintf(debugf, __VA_ARGS__); \
    }

static int ok(int res, char *expr, const char *func, int line, char *prefix)
{
    if (res == CONFD_EOF) {
        fprintf(stderr, "%s: %s, " SERVER " closed connection (CONFD_EOF), "
                "in function %s, line %d\n", prefix, expr, func, line);
        exit(1);
    }
    if (res == CONFD_ERR) {
        fprintf(stderr, "%s: %s, Error: %s (%d): %s, "
                "in function %s, line %d\n", prefix, expr,
                confd_strerror(confd_errno), confd_errno,
                (confd_errno == CONFD_ERR_OS) ? strerror(errno):
                confd_lasterr(), func, line);
        exit(1);
    }
    return res;
}


void get_daemon_addr(char *addrstr, int port)
{
    static struct sockaddr_in in_addr;
    static struct sockaddr_in6 in6_addr;
    static struct sockaddr_un un_addr;
    char *daemon_addr = "127.0.0.1";
    int daemon_port = PORT;
    char *etmp;
#ifdef EXTERNAL_IPC
    char *path;
    void *handle;
    confd_ext_ipc_init_func_t *ext_init_ops;
    char *errstr = NULL;
#endif

    if (addrstr != NULL) {
        daemon_addr = addrstr;
    } else if ((etmp = getenv(IPC_ADDR)) != NULL) {
        daemon_addr = etmp;
    } else if ((etmp = getenv(IPC_EXTADDR)) != NULL) {
        daemon_addr = etmp;
#ifdef EXTERNAL_IPC
        if ((path = getenv(IPC_EXTSOPATH)) != NULL) {
            if ((handle = dlopen(path, RTLD_LOCAL|RTLD_LAZY)) == NULL) {
                fprintf(stderr, "Failed to load %s\n", path);
            } else {
                if ((ext_init_ops = (confd_ext_ipc_init_func_t *)
                     dlsym(handle, "confd_ext_ipc_init")) == NULL ||
                    ((ecbs = (*ext_init_ops)()) == NULL) ||
                    ecbs->getaddrinfo == NULL || ecbs->socket == NULL) {
                    fprintf(stderr,
                            "Failed to find getaddrinfo()/socket() in %s\n",
                            path);
                } else {
                    if (ecbs->getaddrinfo(daemon_addr,
                                          &family, &type, &protocol,
                                          &addr, &addrlen, &errstr) != 0) {
                        fprintf(stderr, "getaddrinfo() in %s failed", path);
                        if (errstr != NULL) {
                            fprintf(stderr, ": %s\n", errstr);
                            free(errstr);
                        } else {
                            fprintf(stderr, "\n");
                        }
                    } else {
                        return;
                    }
                }
            }
            ecbs = NULL;
            fprintf(stderr, "Ignoring environment " IPC_EXTSOPATH "\n");
        }
#endif
    }
    if (port != 0) {
        daemon_port = port;
    } else if ((etmp = getenv(IPC_PORT)) != NULL) {
        daemon_port = atoi(etmp);
    }

    memset(&in_addr, '\0', sizeof(in_addr));
    memset(&in6_addr, '\0', sizeof(in6_addr));
    memset(&un_addr, '\0', sizeof(un_addr));
    type = SOCK_STREAM;
    protocol = 0;
    if (inet_pton(AF_INET, daemon_addr, &in_addr.sin_addr) == 1) {
        family = PF_INET;
        in_addr.sin_family = AF_INET;
        in_addr.sin_port = htons(daemon_port);
        addr = (struct sockaddr *)&in_addr;
        addrlen = sizeof(in_addr);
    } else if (inet_pton(AF_INET6, daemon_addr, &in6_addr.sin6_addr) == 1) {
        family = PF_INET6;
        in6_addr.sin6_family = AF_INET6;
        in6_addr.sin6_port = htons(daemon_port);
        addr = (struct sockaddr *)&in6_addr;
        addrlen = sizeof(in6_addr);
    } else {
        family = PF_UNIX;
        un_addr.sun_family = AF_UNIX;
        snprintf(un_addr.sun_path, sizeof(un_addr.sun_path),
                 "%s", daemon_addr);
        addr = (struct sockaddr *)&un_addr;
        addrlen = sizeof(un_addr);
    }
}

int get_socket()
{
#ifdef EXTERNAL_IPC
    char *errstr;

    if (ecbs != NULL)
        return ecbs->socket(family, type, protocol, &errstr);
    else
#endif
        return socket(family, type, protocol);
}

void fatal(char *str)
{
    fprintf(stderr, "%s: fatal: %s\n", progname, str);
    exit(1);
}

static void start_session(int s, enum cdb_db_type d)
{
    int retry = 10;
    while (retry) {
        if (sess_flags == -1) {
            if (cdb_start_session(s, db) == CONFD_OK)
                return;
        } else {
            if (cdb_start_session2(s, db, sess_flags) == CONFD_OK)
                return;
        }
        if (confd_errno == CONFD_ERR_LOCKED) {
            if (sess_flags != -1) {
                if (sess_flags & CDB_LOCK_WAIT) {
                    fatal("got CONFD_ERR_LOCKED when using CDB_LOCK_WAIT");
                } else if (!(sess_flags & CDB_LOCK_SESSION)) {
                    fatal("got CONFD_ERR_LOCKED without CDB_LOCK_SESSION");
                }
            }
            if (debug > CONFD_SILENT) {
                DBGLOG("start_session locked, retry %d\n", retry);
            }
            usleep(500000);
            retry--;
            continue;
        }
        fatal("start session failed");
    }
    fatal("start session failed (after repeated retries)");
}

static void free_values(confd_value_t *v, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        confd_free_value(&v[i]);
    }
}

static void free_tag_values(confd_tag_value_t *tv, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        confd_free_value(CONFD_GET_TAG_VALUE(&tv[i]));
    }
}

static void print_value(confd_value_t *valp,
                        struct confd_cs_node *start, char *path, char *eol)
{
    char tmpbuf[BUFSIZ];
    struct confd_cs_node *node = NULL;

    /* Don't call with start NULL and path "", gives ugly error */
    if (start != NULL || path != NULL) {
        node = confd_cs_node_cd(start, path ? path : "");
    }

    if ((node == NULL) ||
        (confd_val2str(node->info.type, valp, tmpbuf, BUFSIZ) == CONFD_ERR)) {
        confd_pp_value(tmpbuf, BUFSIZ, valp);
    }
    printf("%s%s", tmpbuf, eol);
}

static void print_2p_info(int type, int flags) {
    switch (type) {
    case CDB_SUB_PREPARE: printf("PREPARE"); break;
    case CDB_SUB_COMMIT:  printf("COMMIT");  break;
    case CDB_SUB_ABORT:   printf("ABORT");   break;
    case CDB_SUB_OPER:    printf("OPER");    break;
    }
    if (flags & CDB_SUB_FLAG_TRIGGER) { printf(" (trigger)"); }
    if (flags & CDB_SUB_FLAG_REVERT)  { printf(" (revert)"); }
    if (flags & CDB_SUB_FLAG_IS_LAST) { printf(" (last)"); }
    if (flags & CDB_SUB_FLAG_HA_IS_SECONDARY)
    {
        if (biased_free)
        {
            printf(" (secondary)");
        }
        else
        {
            printf(" (slave)");
        }
    }
    printf("\n");
}

static void print_db_status(int status) {
  switch (status) {
  case CONFD_DB_INVALID: printf("invalid"); break;
  case CONFD_DB_VALID: printf("valid"); break;
  }
  printf("\n");
}

static int max_object_elems(struct confd_cs_node *start)
{
    if (start) {
        return confd_max_object_size(start);
    } else {
        return MAX_ELEMS_PER_OBJECT;
    }
}

static void print_and_free_attrs(confd_attr_value_t **attrvals, int nvals)
{
    if (*attrvals != NULL) {
        int i;
        for (i = 0; i < nvals; i++) {
            switch ((*attrvals)[i].attr) {
            case CONFD_ATTR_TAGS:
                printf("ATTR_TAG: "); break;
            case CONFD_ATTR_ANNOTATION:
                printf("ATTR_ANNOTATION: "); break;
            case CONFD_ATTR_INACTIVE:
                printf("ATTR_INACTIVE: "); break;
            case CONFD_ATTR_BACKPOINTER:
                printf("ATTR_BACKPOINTER: "); break;
            case CONFD_ATTR_ORIGIN:
                printf("ATTR_ORIGIN: "); break;
            case CONFD_ATTR_ORIGINAL_VALUE:
                printf("ATTR_ORIGINAL_VALUE: "); break;
            case CONFD_ATTR_WHEN:
                printf("ATTR_WHEN: "); break;
            case CONFD_ATTR_REFCOUNT:
                printf("ATTR_REFCOUNT: "); break;
            default:
                printf("ATTR_UNKNOWN: "); break;
            }
            print_value(&(*attrvals)[i].v, NULL, NULL, "\n");
            confd_free_value(&(*attrvals)[i].v);
        }
        free(*attrvals);
    } else {
        printf("Attribute not found\n");
    }
}

static void set_origin_val(confd_value_t *val, const char *origin)
{
    struct confd_identityref idref = {.ns = or__ns,
                                      .id = confd_str2hash(origin)};
    CONFD_SET_IDENTITYREF(val, idref);
}

static void cdb_delete_attribute(u_int32_t attr, char *argv)
{
    confd_value_t val;
    CONFD_SET_NOEXISTS(&val);
    OK(cdb_set_attr(cs, attr, &val, argv));
}

static void do_cdb_get(char *argv[]) /* <key> */
{
    confd_value_t val;

    OK(cdb_get(cs, &val, argv[0]));
    print_value(&val, NULL, argv[0], "\n");
    confd_free_value(&val);
}

static void do_cdb_is_default(char *argv[]) /* <key> */
{
    int res;

    res = cdb_is_default(cs, argv[0]);
    switch (res) {
    case 1: printf("yes\n"); break;
    case 0: printf("no\n"); break;
    default:
        OK(res);
    }
}

static void do_cdb_get_case(char *argv[]) /* <path> <choice> */
{
    confd_value_t val;

    OK(cdb_get_case(cs, argv[1], &val, argv[0]));
    print_value(&val, NULL, NULL, "\n");
}

static void do_cdb_cd(char *argv[]) /* <key> */
{
    OK(cdb_cd(cs, argv[0]));
}

static void do_cdb_getcwd(char *argv[])
{
    char tmpbuf[BUFSIZ];

    OK(cdb_getcwd(cs, BUFSIZ, tmpbuf));
    printf("%s\n", tmpbuf);
}

static void do_cdb_exists(char *argv[])
{
    int res;
    res = cdb_exists(cs, argv[0]);
    switch (res) {
    case 1: printf("yes\n"); break;
    case 0: printf("no\n"); break;
    default:
        OK(res);
    }
}

static void print_value_array(struct confd_cs_node *start,
                              confd_value_t vs[], int n, int ptags, char *eol)
{
    int i;
    struct confd_cs_node *cur;

    if (start == NULL) {
        for (i=0; i<n; i++) { print_value(&vs[i], NULL, NULL, eol); }
        return;
    }
    cur = start->children;
    for (i=0; i<n; i++) {
        switch (vs[i].type) {
        case C_XMLTAG:
            if (cur && ptags) {
                printf("%s\n", confd_hash2str(cur->tag));
            } else {
                printf("\n");
            }
            break;
        case C_NOEXISTS:
            printf("\n");
            break;
        default:
            if (cur && ptags) { printf("%s = ", confd_hash2str(cur->tag)); }
            print_value(&vs[i], cur, "", eol);
        }
        cur = confd_next_object_node(start, cur, &vs[i]);
    }
}

static void do_cdb_get_object(char *argv[]) /* <key> */
{
    struct confd_cs_node *start = confd_cs_node_cd(NULL, argv[0]);
    int max_elems = max_object_elems(start);
    confd_value_t val[max_elems];
    int ret;

    ret = cdb_get_object(cs, val, max_elems, argv[0]);
    assert(ret > 0 && ret <= max_elems);
    print_value_array(start, val, ret, 0, "\n");
    free_values(val, ret);
}

static void do_cdb_get_object_tags(char *argv[]) /* <key> */
{
    struct confd_cs_node *start = confd_cs_node_cd(NULL, argv[0]);
    int max_elems = max_object_elems(start);
    confd_value_t val[max_elems];
    int ret;

    ret = cdb_get_object(cs, val, max_elems, argv[0]);
    assert(ret > 0 && ret <= max_elems);
    print_value_array(start, val, ret, 1, "\n");
    free_values(val, ret);
}

static void do_cdb_get_objects(char *argv[]) /* <start> <num> <key> */
{
    int ix = atoi(argv[0]);
    int nobj = atoi(argv[1]);
    int max_elems = max_object_elems(confd_cs_node_cd(NULL, argv[2]));
    confd_value_t val[nobj*max_elems];
    char tmpbuf[BUFSIZ]; int o, i, ret;

    ret = cdb_get_objects(cs, val, max_elems, ix, nobj, argv[2]);
    assert(ret > 0 && ret <= max_elems);
    for (o = 0; o < nobj; o++) {
        /* we assume that we have the same number of values in each object */
        for (i = 0; i < ret; i++) {
            confd_pp_value(tmpbuf, BUFSIZ, &val[o*max_elems+i]);
            printf("%s\n", tmpbuf);
            confd_free_value(&val[o*max_elems+i]);
        }
        if (o < nobj - 1)
            printf("\n");
    }
}

static void do_cdb_get_values(char *argv[]) /* <key> <elem>... */
{
    confd_tag_value_t val[MAX_ARGS]; u_int32_t tag;
    char tmpbuf[BUFSIZ]; int i, num;

    for (i = 0; argv[i+1] != NULL; i++) {
        assert((tag = confd_str2hash(argv[i+1])) != 0);
        CONFD_SET_TAG_NOEXISTS(&val[i], tag);
    }
    num = i;
    OK(cdb_get_values(cs, val, num, argv[0]));
    for (i = 0; i < num; i++) {
        confd_pp_value(tmpbuf, BUFSIZ, CONFD_GET_TAG_VALUE(&val[i]));
        printf("%s\n", tmpbuf);
        confd_free_value(CONFD_GET_TAG_VALUE(&val[i]));
    }
}

static void do_cdb_num_instances(char *argv[]) /* <key> */
{
    int n;

    n = OK(cdb_num_instances(cs, argv[0]));
    printf("%d\n", n);
}

static void do_cdb_set(char *argv[]) /* <key> <value> */
{
    OK(cdb_set_elem2(cs, argv[1], argv[0]));
}

static void do_cdb_set_case(char *argv[]) /* <path> <choice> <case> */
{
    OK(cdb_set_case(cs, argv[1], argv[2], argv[0]));
}

static void do_cdb_create(char *argv[]) /* <key> */
{
    OK(cdb_create(cs, argv[0]));
}

static void do_cdb_delete(char *argv[])
{
    OK(cdb_delete(cs, argv[0]));
}

static void do_cdb_set_object(char *argv[]) /* <path> <leaf1> ... <leafN> */
{
    char *path = argv[0];
    struct confd_cs_node *node, *ntmp;
    confd_value_t *vs, *v;
    int i, ai, n, argc;
    node = confd_cs_node_cd(NULL, path);
    if (node) { node = node->children; }
    if (!node) {
        fprintf(stderr, "invalid path (couldn't lookup schema info)\n");
        OK(CONFD_ERR);
    }
    for (i=1,argc=0; argv[i]; i++,argc++) ; /* count args */
    for (n=0, ntmp = node; ntmp ; ntmp=ntmp->next, n++) ; /* count leafs */
    if (argc > n) {
        fprintf(stderr, "too many leafs (at %d, expected %d)\n", i, n);
        OK(CONFD_ERR);
    }
    vs = (confd_value_t *)malloc(sizeof(*vs) * n);
    for (i=0, ai=1, v = vs; i<n; i++, ai++, v++) {
        if (ai > argc) {
            fprintf(stderr, "too few leafs\n");
            OK(CONFD_ERR);
        }
        if ((node->info.flags & CS_NODE_IS_CDB) &&
            node->info.type != NULL) {
            confd_str2val(node->info.type, argv[ai], v);
        } else {
            CONFD_SET_NOEXISTS(v);
        }
        node = node->next;
    }
    OK(cdb_set_object(cs, vs, n, path));
    free_values(vs, n);
    free(vs);
}

static void do_cdb_get_attrs(char *argv[])
{
    confd_attr_value_t *attrvals = NULL;
    int nvals;
    u_int32_t attrs;
    int num_attrs = 0;
    OK(cdb_get_attrs(cs, &attrs, num_attrs, &attrvals, &nvals, argv[0]));
    print_and_free_attrs(&attrvals, nvals);
}

static void do_cdb_set_annotation(char *argv[])
{
    confd_value_t val;
    CONFD_SET_STR(&val, argv[1]);
    OK(cdb_set_attr(cs, CONFD_ATTR_ANNOTATION, &val, argv[0]));
}

static void do_cdb_delete_annotation(char *argv[])
{
    cdb_delete_attribute(CONFD_ATTR_ANNOTATION, argv[0]);
}

static void do_cdb_set_origin(char *argv[])
{
    confd_value_t val;
    set_origin_val(&val, argv[1]);
    OK(cdb_set_attr(cs, CONFD_ATTR_ORIGIN, &val, argv[0]));
}

static void do_cdb_delete_origin(char *argv[])
{
    cdb_delete_attribute(CONFD_ATTR_ORIGIN, argv[0]);
}


/* take a cdb read-lock, then sleep for <s> seconds */
static void do_sleep(char *argv[]) /* <seconds> */
{
    int sec = atoi(argv[0]);
    sleep(sec);
}

static void do_echo(char *argv[])
{
    int i;
    for (i=0; argv[i]; i++) printf("%s", argv[i]);
    printf("\n");
}

/* take a cdb read-lock, then suspend process */
static void do_suspend(char *argv[])
{
    kill(getpid(), SIGSTOP);
}

/* fork, child takes a cdb read-lock and then suspends itself */
static void do_suspend2(char *argv[])
{
    int s;
    pid_t pid;
    assert((s = get_socket()) >= 0);
    OK(cdb_connect(s, CDB_DATA_SOCKET, addr, addrlen));
    start_session(s, db);
    if ((pid = fork()) == 0) {
        /* child */
        close(fileno(stdout)); /* make sure shell doesn't wait for output */
        kill(getpid(), SIGSTOP);
        OK(cdb_close(s));
        exit(0);
    }
    printf("%ld\n", (long)pid);
}

static void benone(char *argv[])
{
    OK(confd_ha_benone(hs));
}

static void beprimary(char *argv[]) /* <nodename> */
{
    confd_value_t nodeid;
    CONFD_SET_BUF(&nodeid, (unsigned char*)argv[0], strlen(argv[0]));
    OK(confd_ha_beprimary(hs, &nodeid));
}

static void besecondary(char *argv[])
         /* <nodename> <primaryname> <primaryaddr> [async] */
{
    confd_value_t nodeid;
    struct confd_ha_node m;
    char *primary = argv[1]; char *primary_addr = argv[2];
    int waitreply = (argv[3] && strcmp(argv[3], "async") == 0) ? 0 : 1;
    CONFD_SET_BUF(&nodeid, (unsigned char*)argv[0], strlen(argv[0]));
    CONFD_SET_BUF(&m.nodeid, (unsigned char*)primary, strlen(primary));
    if (inet_pton(AF_INET, primary_addr, &m.addr.ip4) == 1) {
        m.af = AF_INET;
    } else if (inet_pton(AF_INET6, primary_addr, &m.addr.ip6) == 1) {
        m.af = AF_INET6;
    } else {
        m.af = AF_UNSPEC;
        m.addr.str = primary_addr;
    }
    OK(confd_ha_besecondary(hs, &nodeid, &m, waitreply));
}

static void berelay(char *argv[])
{
    OK(confd_ha_berelay(hs));
}

static void dead_secondary(char *argv[]) /* <secondaryname> */
{
    confd_value_t nodeid;
    CONFD_SET_BUF(&nodeid, (unsigned char*)argv[0], strlen(argv[0]));
    OK(confd_ha_secondary_dead(hs, &nodeid));
}

static void ha_status(char *argv[])
{
    struct confd_ha_status status;
    OK(confd_ha_get_status(hs, &status));
    switch (status.state) {
    case CONFD_HA_STATE_NONE:
        printf("none\n");
        break;
    case CONFD_HA_STATE_SECONDARY:
    {
        char str[128];
        assert(status.num_nodes == 1);
        memset(str, 0, sizeof(str));
        memcpy(str, CONFD_GET_BUFPTR(&status.nodes[0].nodeid),
               max((sizeof(str)-1),CONFD_GET_BUFSIZE(&status.nodes[0].nodeid)));
        if (biased_free)
        {
            printf("secondary primary: %s\n", str);
        }
        else
        {
            printf("slave master: %s\n", str);
        }
    }
    break;
    case CONFD_HA_STATE_PRIMARY:
    {
        int i;
        if (biased_free)
        {
            printf("primary %d secondaries", status.num_nodes);
        }
        else
        {
            printf("master %d slaves", status.num_nodes);
        }
        for (i=0; i<status.num_nodes; i++) {
            char str[128];
            memset(str, 0, sizeof(str));
            memcpy(str, CONFD_GET_BUFPTR(&status.nodes[i].nodeid),
                   max(127, CONFD_GET_BUFSIZE(&status.nodes[i].nodeid)));
            printf(" %s", str);
        }
        printf("\n");
        break;
    }
        case CONFD_HA_STATE_SECONDARY_RELAY:
        {
        int i;
        char str[128];
        memset(str, 0, sizeof(str));
        memcpy(str, CONFD_GET_BUFPTR(&status.nodes[0].nodeid),
               max((sizeof(str)-1),CONFD_GET_BUFSIZE(&status.nodes[0].nodeid)));
        if (biased_free)
        {
            printf("relay secondary primary: %s %d secondaries",
                   str, status.num_nodes - 1);
        }
        else
        {
            printf("relay slave master: %s %d slaves",
                   str, status.num_nodes - 1);
        }
        for (i=1; i<status.num_nodes; i++) {
            memset(str, 0, sizeof(str));
            memcpy(str, CONFD_GET_BUFPTR(&status.nodes[i].nodeid),
                   max(127, CONFD_GET_BUFSIZE(&status.nodes[i].nodeid)));
            printf(" %s", str);
        }
        printf("\n");
    }
        break;
    default:
        printf("UNKNOWN?\n");
        break;
    }
}

static void print_modifications(confd_tag_value_t *val, int nvals,
                                struct confd_cs_node *start_node,
                                int start_indent)
{
    int i, indent = start_indent;
    struct confd_cs_node root, *pnode = start_node, *node;
    char tmpbuf[BUFSIZ];
    char *tmp;

    for (i=0; i<nvals; i++) {
        if (indent == start_indent && start_node == NULL) {
            node = confd_find_cs_root(CONFD_GET_TAG_NS(&val[i]));
            root.children = node;
            pnode = &root;
        }
        switch (CONFD_GET_TAG_VALUE(&val[i])->type) {
        case C_XMLBEGIN:
            tmp = "begin";
            if (pnode != NULL)
                pnode = confd_find_cs_node_child(pnode, val[i].tag);
            break;
        case C_XMLBEGINDEL:
            tmp = "begin-deleted";
            if (pnode != NULL)
                pnode = confd_find_cs_node_child(pnode, val[i].tag);
            break;
        case C_XMLEND:
            tmp = "end";
            if (pnode != NULL)
                pnode = pnode->parent;
            indent -= 2;
            break;
        case C_XMLTAG:
            tmp = "created";
            break;
        case C_NOEXISTS:
            tmp = "deleted";
            break;
        case C_XMLMOVEFIRST:
            tmp = "moved-first";
            break;
        case C_XMLMOVEAFTER:
            tmp = "moved-after";
            break;
        default:
            if (pnode == NULL ||
                (node = confd_find_cs_node_child(pnode, val[i].tag)) == NULL ||
                confd_val2str(node->info.type, CONFD_GET_TAG_VALUE(&val[i]),
                              tmpbuf, sizeof(tmpbuf)) == CONFD_ERR) {
                confd_pp_value(tmpbuf, sizeof(tmpbuf),
                               CONFD_GET_TAG_VALUE(&val[i]));
            }
            tmp = tmpbuf;
        }
        printf("%*s%s %s\n", indent, "",
               confd_hash2str(CONFD_GET_TAG_TAG(&val[i])), tmp);
        switch (CONFD_GET_TAG_VALUE(&val[i])->type) {
        case C_XMLBEGIN:
        case C_XMLBEGINDEL:
            indent += 2;
            break;
        default:
            break;
        }
    }
}

static int common_trigger_subscriptions(int sock, int sub_points[], int len)
{
    if (db == CDB_OPERATIONAL)
        return cdb_trigger_oper_subscriptions(sock, sub_points, len,
                                             sess_flags == -1 ? 0 : sess_flags);
    else
        return cdb_trigger_subscriptions(sock, sub_points, len);
}

static int common_subscribe(int sock, int prio, int nspace,
                            int *spoint, char *path)
{
    if (db == CDB_OPERATIONAL)
        return cdb_oper_subscribe(sock, nspace, spoint, path);
    else
        return cdb_subscribe(sock, prio, nspace, spoint, path);
}

static int common_sync_subscription_socket(int sock,
                                           enum cdb_subscription_sync_type st)
{
    return cdb_sync_subscription_socket(sock, db == CDB_OPERATIONAL ?
                                        CDB_DONE_OPERATIONAL : st);
}

static int common_sub_progress(int sock, char *fmt, ...)
{
    va_list args;
    char buf[BUFSIZ];

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    return cdb_sub_progress(sock, "%s", buf);
}

static void iter_common(confd_hkeypath_t *kp,
                        enum cdb_iter_op op,
                        confd_value_t *oldv,
                        confd_value_t *newv,
                        void *state)
{
    char tmppath[BUFSIZ];
    char tmpbuf1[BUFSIZ], tmpbuf2[BUFSIZ];
    char *opstr = "";
    char *subpath = (char *)state;
    struct confd_cs_node *tnode = confd_find_cs_node(kp, kp->len);
    confd_pp_kpath(tmppath, BUFSIZ, kp);

#define PPV(VP, BUF)                                                    \
    {                                                                   \
        if ((tnode == NULL) ||                                          \
            (confd_val2str(tnode->info.type, VP, BUF,                   \
                           sizeof(BUF)/sizeof(*BUF)) == CONFD_ERR)) {   \
            confd_pp_value(BUF, sizeof(BUF)/sizeof(*BUF), VP);          \
        }                                                               \
    }

    switch (op) {
    case MOP_CREATED:      opstr = "created";  break;
    case MOP_DELETED:      opstr = "deleted";  break;
    case MOP_VALUE_SET:    opstr = "set";      break;
    case MOP_MODIFIED:     opstr = "modified"; break;
    case MOP_MOVED_AFTER:  opstr = "moved";    break;
    case MOP_ATTR_SET:     fatal("got MOP_ATTR_SET in cdb_diff_iterate()");
    }

    tmpbuf1[0] = tmpbuf2[0] = '\0';
    if (oldv) { PPV(oldv, tmpbuf1); }
    if (op != MOP_MOVED_AFTER) {
        if (newv) { PPV(newv, tmpbuf2); }
    } else {
        if (newv) {
            char *p = tmpbuf2;
            confd_value_t *vp = newv;
            if (tnode != NULL)
                tnode = tnode->children;
            while (vp->type != C_NOEXISTS && p - tmpbuf2 < BUFSIZ) {
                if (p == tmpbuf2) {
                    p += snprintf(p, BUFSIZ, "after {");
                } else {
                    p += snprintf(p, BUFSIZ - (p - tmpbuf2), " ");
                }
                {
                    int c = 0;
                    int sz = BUFSIZ - (p - tmpbuf2);

                    if ((tnode == NULL) ||
                        ((c = confd_val2str(tnode->info.type, vp, p, sz)) ==
                         CONFD_ERR)) {
                        c = confd_pp_value(p, sz, vp);
                    }
                    p += c;
                }
                if (tnode != NULL)
                    tnode = tnode->next;
                vp++;
            }
            if (p - tmpbuf2 < BUFSIZ)
                snprintf(p, BUFSIZ - (p - tmpbuf2), "}");
        } else {
            snprintf(tmpbuf2, BUFSIZ, "first");
        }
    }

#undef PPV

    common_sub_progress(cs, "diff_iterate: %s %s %s (%s -> %s)",
                        subpath, tmppath, opstr, tmpbuf1, tmpbuf2);

    if (oldv || newv) {
        printf("%s %s %s (%s -> %s)\n",
               subpath, tmppath, opstr, tmpbuf1, tmpbuf2);
    } else {
        printf("%s %s %s\n", subpath, tmppath, opstr);
    }
}


static enum cdb_iter_ret subwait_iter(confd_hkeypath_t *kp,
                                      enum cdb_iter_op op,
                                      confd_value_t *oldv,
                                      confd_value_t *newv,
                                      void *state)
{
    iter_common(kp, op, oldv, newv, state);
    return ITER_RECURSE;
}

static enum cdb_iter_ret subwait_iter_m(confd_hkeypath_t *kp,
                                        enum cdb_iter_op op,
                                        confd_value_t *oldv,
                                        confd_value_t *newv,
                                        void *state)
{
    int nvals;
    confd_tag_value_t *val;
    int flags = CDB_GET_MODS_INCLUDE_LISTS | CDB_GET_MODS_INCLUDE_MOVES
      | CDB_GET_MODS_WANT_ANCESTOR_DELETE;

    iter_common(kp, op, oldv, newv, state);
    if (kp->v[0][0].type != C_XMLTAG &&
        (op == MOP_CREATED || op == MOP_MODIFIED)) {
        /* a created or modified list entry */
        OK(cdb_get_modifications_iter(cs, flags, &val, &nvals));
        //OK(cdb_get_modifications_iter(cs, 0, &val, &nvals));
        print_modifications(val, nvals, confd_find_cs_node(kp, kp->len), 2);
        free_tag_values(val, nvals);
        free(val);
    }
    return ITER_RECURSE;
}

/* Wait for a path to change */
static void do_subwait_iter(char *argv[]) /* <path> [prio] [loop] [opts] */
{
    int id;
    int n;
    int prio;
    int loop;
    int opts = 0;
    int subids[1];
    int usid;
    if (argv[1]) {
        prio = atoi(argv[1]);
    } else {
        prio = 10;
    }
    if (argv[1] && argv[2]) {
        loop = atoi(argv[2]);
        if (loop == 0) loop = 1;
    } else {
        loop = 1;
    }
    if (argv[3]) {
      if (strcmp(argv[3], "suspend") == 0) {
          opts = SUBWAIT_ITER_SUSPEND;
      } else if (strcmp(argv[3], "usid") == 0) {
          opts = SUBWAIT_ITER_USID;
      }
    }
    OK(common_subscribe(cs, prio, 0, &id, argv[0]));
    OK(cdb_subscribe_done(cs));
    printf("SUBSCRIBED TO %s\n", argv[0]);
    for (int i=0; i<loop; i++) {
        OK(cdb_read_subscription_socket(cs, subids, &n));
        if (opts == SUBWAIT_ITER_USID) {
            usid = cdb_get_user_session(cs);
            printf("usid=%d COMMIT\n", usid);
        } else {
            printf("COMMIT\n");
        }
        if (opts == SUBWAIT_ITER_SUSPEND) {
            kill(getpid(), SIGSTOP);
        }
        common_sub_progress(cs, "going into diff_iterate on id %d", id);
        OK(cdb_diff_iterate(cs, id, subwait_iter,
                            leaf_iter|ITER_WANT_PREV|ITER_WANT_ANCESTOR_DELETE,
                            argv[0]));
        common_sub_progress(cs, "cdb_diff_iterate(%d) done", id);
        common_sync_subscription_socket(cs, CDB_DONE_PRIORITY);
        printf("DONE\n");
        fflush(stdout);
    }
}

/* <path> [prio] [loop] [modpath] ['suppress_defaults'] ['exclude_lists'] */
static void do_subwait_mods(char *argv[])
{
    int id, n, i, prio, loop, subids[1];
    int flags = CDB_GET_MODS_INCLUDE_LISTS | CDB_GET_MODS_INCLUDE_MOVES
      | CDB_GET_MODS_WANT_ANCESTOR_DELETE;
    const char *mp = NULL;
    if (argv[1]) {
        prio = atoi(argv[1]);
    } else {
        prio = 10;
    }
    if (argv[1] && argv[2]) {
        loop = atoi(argv[2]);
        if (loop == 0) loop = 1;
    } else {
        loop = 1;
    }
    if (argv[1] && argv[2] && argv[3]) {
        mp = argv[3];
    } else {
        mp = argv[0];
    }
    if (argv[1] && argv[2] && argv[3] && argv[4] &&
        strcmp(argv[4], "suppress_defaults") == 0) {
        flags |= CDB_GET_MODS_SUPPRESS_DEFAULTS;
    }
    if (argv[5] && strcmp(argv[5], "exclude_lists") == 0) {
      flags &= ~(CDB_GET_MODS_INCLUDE_LISTS);
    }
    OK(common_subscribe(cs, prio, 0, &id, argv[0]));
    OK(cdb_subscribe_done(cs));
    printf("SUBSCRIBED TO %s\n", argv[0]);
    for (i=0; i<loop; i++) {
        OK(cdb_read_subscription_socket(cs, subids, &n));
        printf("COMMIT\n");
        {
            int nvals;
            confd_tag_value_t *val;

            OK(cdb_get_modifications(cs, id, flags, &val, &nvals, mp));
            if (strcmp(mp, "/") == 0)
                print_modifications(val, nvals, NULL, 0);
            else
                print_modifications(val, nvals, confd_cs_node_cd(NULL, mp), 0);
            free_tag_values(val, nvals);
            free(val);
        }
        common_sync_subscription_socket(cs, CDB_DONE_PRIORITY);
        printf("DONE\n");
        fflush(stdout);
    }
}
/* Two-phase subscription */
static void do_subwait_mods2p(char *argv[])
/* <path> [prio] [loop] [modpath] ['suppress_defaults'] */
{
    int id, i, prio, loop;
    const char *mp = NULL;
    int flags = CDB_GET_MODS_INCLUDE_LISTS | CDB_GET_MODS_INCLUDE_MOVES
      | CDB_GET_MODS_WANT_ANCESTOR_DELETE;

    if (argv[1]) {
        prio = atoi(argv[1]);
    } else {
        prio = 10;
    }
    if (argv[1] && argv[2]) {
        loop = atoi(argv[2]);
        if (loop == 0) loop = 1;
    } else {
        loop = 1;
    }
    if (argv[1] && argv[2] && argv[3]) {
        mp = argv[3];
    } else {
        mp = argv[0];
    }
    if (argv[1] && argv[2] && argv[3] && argv[4] &&
        strcmp(argv[4], "suppress_defaults") == 0) {
        flags |= CDB_GET_MODS_SUPPRESS_DEFAULTS;
    }

    OK(cdb_subscribe2(cs, CDB_SUB_RUNNING_TWOPHASE, 0, prio, &id, 0, argv[0]));
    OK(cdb_subscribe_done(cs));
    printf("SUBSCRIBED TO %s\n", argv[0]);

    for (i=0; i<loop; i++) {
        int len;
        int subflags;
        int *subids;
        enum cdb_sub_notification type;

        OK(cdb_read_subscription_socket2(cs, &type, &subflags, &subids, &len));
        print_2p_info(type, subflags);

        if (type == CDB_SUB_PREPARE || type == CDB_SUB_COMMIT)
        {
            int nvals;
            confd_tag_value_t *val;

            OK(cdb_get_modifications(cs, id, flags, &val, &nvals, mp));
            if (strcmp(mp, "/") == 0)
                print_modifications(val, nvals, NULL, 0);
            else
                print_modifications(val, nvals, confd_cs_node_cd(NULL, mp), 0);
            free_tag_values(val, nvals);
            free(val);
        }
        common_sync_subscription_socket(cs, CDB_DONE_PRIORITY);
        free(subids);
        printf("DONE\n");
        fflush(stdout);
    }
}

static void do_subwait_dimods(char *argv[]) /* <path> [prio] [loop] */
{
    int id, n, i, prio, loop, subids[1];
    if (argv[1]) {
        prio = atoi(argv[1]);
    } else {
        prio = 10;
    }
    if (argv[1] && argv[2]) {
        loop = atoi(argv[2]);
        if (loop == 0) loop = 1;
    } else {
        loop = 1;
    }
    OK(common_subscribe(cs, prio, 0, &id, argv[0]));
    OK(cdb_subscribe_done(cs));
    printf("SUBSCRIBED TO %s\n", argv[0]);
    for (i=0; i<loop; i++) {
        OK(cdb_read_subscription_socket(cs, subids, &n));
        printf("COMMIT\n");
        OK(cdb_diff_iterate(cs, id, subwait_iter_m,
                            leaf_iter|ITER_WANT_PREV|ITER_WANT_ANCESTOR_DELETE,
                            argv[0]));
        common_sync_subscription_socket(cs, CDB_DONE_PRIORITY);
        printf("DONE\n");
        fflush(stdout);
    }
}

/* Two-phase subscription */
/* <path> [prio] [loop] [suspend] [abort] */
static void do_subwait_iter2p(char *argv[]) {
    int id, i, prio, loop;
    unsigned char suspend = 0, abort = 0;
    enum cdb_sub_type type;

    if (argv[1]) {
        prio = atoi(argv[1]);
    } else {
        prio = 10;
    }
    if (argv[1] && argv[2]) {
        loop = atoi(argv[2]);
        if (loop == 0) loop = 1;
    } else {
        loop = 1;
    }
    if (argv[3]) {
        if (strcmp(argv[3], "prepare") == 0) {
            suspend |= CDB_SUB_PREPARE;
        } else if (strcmp(argv[3], "commit") == 0) {
            suspend |= CDB_SUB_COMMIT;
        } else if (strcmp(argv[3], "both") == 0) {
            suspend |= CDB_SUB_PREPARE;
            suspend |= CDB_SUB_COMMIT;
        }
    }
    if (argv[4] && (strcmp(argv[4], "abort") == 0)) {
        abort = 1;
    }
    /* we don't have (and won't get) two-phase oper subscriptions, but we may
       use this command with '-o' for the cdb_read_subscription_socket2() */
    type = db == CDB_OPERATIONAL ?
        CDB_SUB_OPERATIONAL : CDB_SUB_RUNNING_TWOPHASE;
    OK(cdb_subscribe2(cs, type, 0, prio, &id, 0, argv[0]));
    OK(cdb_subscribe_done(cs));
    printf("SUBSCRIBED TO %s\n", argv[0]);
    for (i=0; i<loop; i++) {
        int flags, len, *subids;
        enum cdb_sub_notification type;
        OK(cdb_read_subscription_socket2(cs, &type, &flags, &subids, &len));
        print_2p_info(type, flags);
        if ((suspend & CDB_SUB_PREPARE) && (type == CDB_SUB_PREPARE)) {
            kill(getpid(), SIGSTOP);
        } else if ((suspend & CDB_SUB_COMMIT) && (type == CDB_SUB_COMMIT)) {
            kill(getpid(), SIGSTOP);
        }
        if (abort && (type == CDB_SUB_PREPARE)) {
            common_sub_progress(cs, "going to abort active trans.");
            printf("SEND ABORT\n");
            OK(cdb_sub_abort_trans(cs, CONFD_ERRCODE_RESOURCE_DENIED,
                                   0, 0, "ABORT BY SUBSCRIBER"));
        } else if ((type == CDB_SUB_PREPARE) ||
                   (type == CDB_SUB_COMMIT) ||
                   (type == CDB_SUB_OPER)) {
            common_sub_progress(cs, "going into diff_iterate on id %d", id);
            OK(cdb_diff_iterate(cs, id, subwait_iter,
                                leaf_iter
                                | ITER_WANT_PREV
                                | ITER_WANT_ANCESTOR_DELETE,
                                argv[0]));
            common_sub_progress(cs, "cdb_diff_iterate(%d) done.", id);
        }
        free(subids);
        common_sync_subscription_socket(cs, CDB_DONE_PRIORITY);
        printf("DONE\n");
        fflush(stdout);
    }
}

static void do_subwait_get_cli(char *argv[]) /* 1|2 <path> [prio] [loop] */
{
    int id, i, prio, loop;
    int modsflags = 0;
    enum cdb_sub_type subtype;
    if (argv[2]) {
        prio = atoi(argv[2]);
    } else {
        prio = 10;
    }
    if (argv[2] && argv[3]) {
        loop = atoi(argv[3]);
        if (loop == 0) loop = 1;
    } else {
        loop = 1;
    }
    if (argv[2] && argv[3] && argv[4] &&
        strcmp(argv[4], "no_backquotes") == 0) {
        modsflags |= CDB_GET_MODS_CLI_NO_BACKQUOTES;
    }
    subtype = (argv[0][0] == '2') ? CDB_SUB_RUNNING_TWOPHASE : CDB_SUB_RUNNING;
    OK(cdb_subscribe2(cs, subtype, 0, prio, &id, 0, argv[1]));
    OK(cdb_subscribe_done(cs));
    printf("SUBSCRIBED TO %s\n", argv[1]);
    for (i=0; i<loop; i++) {
        int flags, len, *subids;
        enum cdb_sub_notification type;
        char *str = NULL;
        OK(cdb_read_subscription_socket2(cs, &type, &flags, &subids, &len));
        print_2p_info(type, flags);
        OK(cdb_get_modifications_cli(cs, subids[0], modsflags, &str));
        printf("CLI OUTPUT:\n%s", str);
        free(subids);
        if (str) { free(str); }
        common_sync_subscription_socket(cs, CDB_DONE_PRIORITY);
        printf("DONE\n");
        fflush(stdout);
    }
}



/* Wait for a path to change */
static void do_subwait(char *argv[]) /* <path> [prio] */
{
    int id, n, prio, subids[1];
    if (argv[1]) {
        prio = atoi(argv[1]);
    } else {
        prio = 10;
    }
    OK(common_subscribe(cs, prio, 0, &id, argv[0]));
    OK(cdb_subscribe_done(cs));
    OK(cdb_read_subscription_socket(cs, subids, &n));
    printf("%s triggered\n", argv[0]);
    common_sync_subscription_socket(cs, CDB_DONE_PRIORITY);
}

/* Wait for a path to change, with a timeout */
static void do_subwait_timeout(char *argv[]) /* <timeout> <path> [prio] */
{
    int id, n, prio, subids[1];
    int timeout = atoi(argv[0]) * 1000;
    struct pollfd fds[1];
    if (argv[2]) {
        prio = atoi(argv[2]);
    } else {
        prio = 10;
    }
    OK(common_subscribe(cs, prio, 0, &id, argv[1]));
    OK(cdb_subscribe_done(cs));
    fds[0].fd = cs; fds[0].events = POLLIN; fds[0].revents = 0;
    if (poll(fds, 1, timeout) <= 0) {
        printf("timeout\n");
        exit(1);
    }
    OK(cdb_read_subscription_socket(cs, subids, &n));
    printf("%s triggered\n", argv[0]);
    common_sync_subscription_socket(cs, CDB_DONE_PRIORITY);
}

static void do_cdb_trigger_subscriptions(char *argv[])
{
    if (argv[0] == NULL) {
        OK(common_trigger_subscriptions(cs, NULL, 0));
    } else {
        int i, subids[MAX_ARGS];
        for (i=0; argv[i] != NULL; i++) {
            subids[i] = atoi(argv[i]);
        }
        OK(common_trigger_subscriptions(cs, subids, i));
    }
}

static void do_cdb_replay_subscriptions(char *argv[])
{
    struct cdb_txid *txid;
    int len;
    OK(cdb_get_replay_txids(cs, &txid, &len));
    assert(len >= 2);

    if (argv[0] == NULL) {
        OK(cdb_replay_subscriptions(cs, txid+1, NULL, 0));
    } else {
        int i, subids[MAX_ARGS];
        for (i=0; argv[i] != NULL; i++) {
            subids[i] = atoi(argv[i]);
        }
        OK(cdb_replay_subscriptions(cs, txid+1, subids, i));
    }
    free(txid);
}

static void do_cdb_start_session(char *argv[])
{
    start_session(cs, db);
}

static void do_wait_cdb(char *argv[])
{
    OK(cdb_wait_start(cs));
}

static void do_cdb_close(char *argv[])
{
    if (cs >= 0) {
        cdb_close(cs);
        cs = -1;
    }
}

static void do_cdb_initiate_journal_compaction(char *argv[])
{
    OK(cdb_initiate_journal_compaction(cs));
}

static void do_get_phase(char *argv[])
{
    struct cdb_phase p;

    OK(cdb_get_phase(cs, &p));
    printf("phase: %d flags: 0x%x", p.phase, p.flags);
    if (p.flags & CDB_FLAG_INIT)    printf(" INIT");
    if (p.flags & CDB_FLAG_UPGRADE) printf(" UPGRADE");
    printf("\n");
}

static void do_get_txid(char *argv[])
{
    struct cdb_txid txid;

    OK(cdb_get_txid(cs, &txid));
    printf("%d-%d-%d%s%s\n", txid.s1, txid.s2, txid.s3,
           (txid.primary[0] != 0) ? "@" : "", txid.primary);
}

static void do_get_replay_txids(char *argv[])
{
    struct cdb_txid *txidr, *txid;
    int len, i;

    OK(cdb_get_replay_txids(cs, &txidr, &len));
    for (i=0, txid=txidr; i<len; i++, txid++) {
        printf("txid[%d] %d-%d-%d%s%s\n", i, txid->s1, txid->s2, txid->s3,
               (txid->primary[0] != 0) ? "@" : "", txid->primary);
    }
    free(txidr);
}

static void do_maapi_request_action(char *argv[])
{
    confd_tag_value_t *values;
    int nval;
    OK(maapi_request_action(ms, NULL, 0, &values, &nval, 0, argv[0]));
    print_modifications(values, nval, NULL, 0);
    free_tag_values(values, nval);
}

static void do_maapi_request_action_th(char *argv[])
{
    confd_tag_value_t *values;
    int nval;
    OK(maapi_request_action_th(ms, mtid, NULL, 0, &values, &nval, argv[0]));
    print_modifications(values, nval, NULL, 0);
    free_tag_values(values, nval);
}

static void do_maapi_attach_init(char *argv[])
{
    if (mtid == 0) {
        OK(maapi_attach_init(ms, &mtid));
        /* When we have attached to init, we don't want "auto" commit,
         * so pretend we already commited by setting mcommit */
        mcommit = 1;
    }
}

static void do_maapi_new_read_write_trans(char *argv[])
{
    if (mtid == 0) {
        mtid = OK(maapi_start_trans_flags(ms, mdb, CONFD_READ_WRITE, 0,
                                          mflags));
        mcommit = gmcommit;
        if (debug_trace) {
            DBGLOG("+%s() new mtid=%d, mflags=%d\n", __FUNCTION__,
                   mtid, mflags);
        }
    } else {
        if (debug_trace) {
            DBGLOG("%s() mtid=%d\n", __FUNCTION__, mtid);
        }
    }
}

static void do_maapi_new_readonly_trans(char *argv[])
{
    if (mtid == 0) {
        mtid = OK(maapi_start_trans(ms, mdb, CONFD_READ));
        /* When we do a readonly transaction, we don't want "auto" commit,
         * so pretend we already commited by setting mcommit */
        mcommit = 1;
        if (debug_trace) {
            DBGLOG("+%s() new mtid=%d\n", __FUNCTION__, mtid);
        }
    } else {
        if (debug_trace) {
            DBGLOG("%s() mtid=%d\n", __FUNCTION__, mtid);
        }
    }
}

static void do_maapi_new_trans(char *argv[])
{
    if (mdb == CONFD_INTENDED) {
        do_maapi_new_readonly_trans(argv);
    } else {
        do_maapi_new_read_write_trans(argv);
    }
}

static void do_maapi_new_candidate_trans(char *argv[])
{
    if (mtid == 0) {
        mtid = OK(maapi_start_trans(ms, CONFD_CANDIDATE, CONFD_READ_WRITE));
        mcommit = gmcommit;
        if (debug_trace) {
            DBGLOG("+%s() new mtid=%d\n", __FUNCTION__, mtid);
        }
    } else {
        if (debug_trace) {
            DBGLOG("%s() mtid=%d\n", __FUNCTION__, mtid);
        }
    }
}

static void do_maapi_commit(char *argv[])
{
    if ((mtid != 0) && !mcommit) {
        if (debug_trace) {
            DBGLOG("+maapi_apply_trans(ms, %d, 0)\n", mtid);
        }
        if (maapi_apply_trans(ms, mtid, 0) == CONFD_ERR) {
            OK_PREF("apply failed", CONFD_ERR);
            exit(1);
        }
        OK(maapi_finish_trans(ms, mtid));
        mcommit = 1;
        mtid = 0;
    }
}

static void do_maapi_commit2(char *argv[])
{
    if ((mtid != 0) && !mcommit) {
        int r;
        r = maapi_validate_trans(ms, mtid, 0, 0);
        if (r == CONFD_ERR_VALIDATION_WARNING) {
            printf("validation warning: %s\n", confd_lasterr());
        } else if (r != CONFD_OK) {
            OK_PREF("validation failed", CONFD_ERR);
            exit(1);
        }
        OK(maapi_prepare_trans(ms, mtid));
        OK(maapi_commit_trans(ms, mtid));
        OK(maapi_finish_trans(ms, mtid));
        mcommit = 1;
        mtid = -1;
    }
}

static void do_maapi_confirmed_commit(char *argv[]) /* <timeout> */
{
    int timeout = atoi(argv[0]);
    OK(maapi_candidate_confirmed_commit(ms, timeout));
}

static void do_maapi_ccommit(char *argv[])
{
    OK(maapi_candidate_commit(ms));
}

static void do_maapi_cabort(char *argv[])
{
    OK(maapi_candidate_abort_commit(ms));
}

static void do_maapi_creset(char *argv[])
{
    OK(maapi_candidate_reset(ms));
}

static void do_maapi_set(char *argv[])
{
    OK(maapi_set_elem2(ms, mtid, argv[1], argv[0]));
}

static void do_maapi_load(char *argv[])
{
  OK(maapi_load_config(ms, mtid, (MAAPI_CONFIG_XML), argv[0]));
}

static void do_maapi_create(char *argv[])
{
    OK(maapi_create(ms, mtid, argv[0]));
}

static void do_maapi_delete(char *argv[])
{
    OK(maapi_delete(ms, mtid, argv[0]));
}

static void do_maapi_delete_config(char *argv[])
{
    OK(maapi_delete_config(ms, mdb));
}

static void do_maapi_get(char *argv[]) /* <key> */
{
    confd_value_t val;

    OK(maapi_get_elem(ms, mtid, &val, argv[0]));
    print_value(&val, NULL, argv[0], "\n");
    confd_free_value(&val);
}

static void do_maapi_exists(char *argv[])
{
    int res;
    res = maapi_exists(ms, mtid, argv[0]);
    switch (res) {
    case 1: printf("yes\n"); break;
    case 0: printf("no\n"); break;
    default:
        OK(res);
    }
}

/* move path key where [refkey] */
/* TODO We should be able to handle longer keys and keys having other
 * types than string.  Both are hard wired right now.
 */
static void do_maapi_move(char *argv[]) {
    confd_value_t *tokey;
    confd_value_t key[1];
    enum maapi_move_where where;
    int n;

    where =
        strcmp(argv[2], "first") == 0 ? MAAPI_MOVE_FIRST
        : strcmp(argv[2], "last") == 0 ? MAAPI_MOVE_LAST
        : strcmp(argv[2], "after") == 0 ? MAAPI_MOVE_AFTER
        : strcmp(argv[2], "before") == 0 ? MAAPI_MOVE_BEFORE
        : MAAPI_MOVE_LAST;

    switch (where) {
    case MAAPI_MOVE_FIRST:
    case MAAPI_MOVE_LAST:
        n = 0;
        tokey = NULL;
        break;
    case MAAPI_MOVE_BEFORE:
    case MAAPI_MOVE_AFTER:
        n = 1;
        CONFD_SET_STR(&key[0], argv[3]);
        tokey = key;
        break;
    }

    OK(maapi_move_ordered(ms, mtid, where, tokey,
                          n, "%s%s", argv[0], argv[1]));
}

static void do_maapi_num_instances(char *argv[]) /* <key> */
{
    int n;

    n = OK(maapi_num_instances(ms, mtid, argv[0]));
    printf("%d\n", n);
}

static void do_traverse_list_keys(char *argv[]) /* <path> [<xpath> [sec-idx]] */
{
    struct maapi_cursor mc;
    int n = 1;

    printf("path: <%s>\n", argv[0]);
    printf("expr: <%s>\n", argv[1]);
    printf("secondary-index: <%s>\n", argv[2]);
    OK(maapi_init_cursor(ms, mtid, &mc, argv[0]));
    mc.xpath_expr = argv[1];
    mc.secondary_index = argv[2];
    while (1) {
        OK(maapi_get_next(&mc));
        if (mc.n == 0) {
            break;
        }
        printf("%d: ", n++);
        print_value_array(NULL, &(mc.keys[0]), mc.n, 0, " ");
        printf("\n");
    }
    maapi_destroy_cursor(&mc);
}

/* just print the first 5 values per entry */
#define VALUES_PER_ENTRY 5
#define ENTRIES_PER_REQUEST 10
static void do_traverse_list(char *argv[]) /* <path> [<xpath> [sec-idx]] */
{
    struct maapi_cursor mc;
    confd_value_t v[ENTRIES_PER_REQUEST*VALUES_PER_ENTRY];
    int n = 1, nobj, i;

    printf("path: <%s>\n", argv[0]);
    printf("expr: <%s>\n", argv[1]);
    printf("secondary-index: <%s>\n", argv[2]);
    OK(maapi_init_cursor(ms, mtid, &mc, argv[0]));
    mc.xpath_expr = argv[1];
    mc.secondary_index = argv[2];
    while (1) {
        nobj = ENTRIES_PER_REQUEST;
        OK(maapi_get_objects(&mc, v, VALUES_PER_ENTRY, &nobj));
        for (i = 0; i < nobj; i++) {
            printf("%d: ", n++);
            print_value_array(NULL, &v[i*VALUES_PER_ENTRY], nobj, 0, " ");
            printf("\n");
        }
        if (mc.n == 0) {
            break;
        }
    }
    maapi_destroy_cursor(&mc);
}


static void do_maapi_get_case(char *argv[]) /* <path> <choice> */
{
    confd_value_t val;

    OK(maapi_get_case(ms, mtid, argv[1], &val, argv[0]));
    print_value(&val, NULL, NULL, "\n");
}

static void do_maapi_get_attrs(char *argv[])
{
    confd_attr_value_t *attrvals = NULL;
    int nvals;
    u_int32_t attrs;
    int num_attrs = 0;
    OK(maapi_get_attrs(ms, mtid, &attrs, num_attrs,
                       &attrvals, &nvals, argv[0]));
    print_and_free_attrs(&attrvals, nvals);
}

static void maapi_delete_attribute(u_int32_t attr, char *argv)
{
    confd_value_t val;
    CONFD_SET_NOEXISTS(&val);
    OK(maapi_set_attr(ms, mtid, attr, &val, argv));
}

static void do_maapi_set_annotation(char *argv[])
{
    confd_value_t val;
    CONFD_SET_STR(&val, argv[1]);
    OK(maapi_set_attr(ms, mtid, CONFD_ATTR_ANNOTATION, &val, argv[0]));
}

static void do_maapi_delete_annotation(char *argv[])
{
    maapi_delete_attribute(CONFD_ATTR_ANNOTATION, argv[0]);
}

static void do_maapi_set_origin(char *argv[])
{
    confd_value_t val;
    set_origin_val(&val, argv[1]);
    OK(maapi_set_attr(ms, mtid, CONFD_ATTR_ORIGIN, &val, argv[0]));
}
static void do_maapi_delete_origin(char *argv[])
{
    maapi_delete_attribute(CONFD_ATTR_ORIGIN, argv[0]);
}

static void do_maapi_cd(char *argv[])
{
    OK(maapi_cd(ms, mtid, argv[0]));
}

static void do_maapi_activate(char *argv[])
{
    confd_value_t val;
    val.type = C_NOEXISTS;
    OK(maapi_set_attr(ms, mtid, CONFD_ATTR_INACTIVE, &val, argv[0]));
}

static void do_maapi_deactivate(char *argv[])
{
    confd_value_t val;
    CONFD_SET_BOOL(&val, 1);
    OK(maapi_set_attr(ms, mtid, CONFD_ATTR_INACTIVE, &val, argv[0]));
}

static void do_maapi_lock(char *argv[])
{
    OK(maapi_lock(ms, mdb));
}

static void do_maapi_unlock(char *argv[])
{
    OK(maapi_unlock(ms, mdb));
}

static void do_maapi_lock_partial(char *argv[])
{
    OK(maapi_lock_partial(ms, mdb, argv, 1, &partial_lock_id));
}

static void do_maapi_unlock_partial(char *argv[])
{
    OK(maapi_unlock_partial(ms, partial_lock_id));
}

static void do_maapi_clear_opcache(char *argv[])
{
    OK(maapi_clear_opcache(ms, argv[0]));
}

static void xpath_trace(char *str)
{
    fprintf(debugf, "XPATH_TRACE: %s\n", str);
}

static void (*xpath_trace_f(void))(char *str)
{
    if (debugf) {
        return xpath_trace;
    }
    return NULL;
}

static int xpath_iter(confd_hkeypath_t *kp, confd_value_t *v, void *state)
{
    char tmppath[BUFSIZ];
    char tmpbuf[BUFSIZ];
    struct confd_cs_node *tnode = confd_find_cs_node(kp, kp->len);
    confd_pp_kpath(tmppath, BUFSIZ, kp);
    tmpbuf[0] = '\000';
    if (v) {
        if ((tnode == NULL) ||
            (confd_val2str(tnode->info.type, v, tmpbuf, BUFSIZ) == CONFD_ERR)) {
            confd_pp_value(tmpbuf, BUFSIZ, v);
        }
    }
    printf("%s [%s]\n", tmppath, tmpbuf);
    return ITER_CONTINUE;
}

static void do_maapi_xpath_eval(char *argv[])
{
    OK(maapi_xpath_eval(ms, mtid, argv[0],
                        xpath_iter, xpath_trace_f(), NULL, argv[1]));
}

static void do_maapi_xpath_eval_expr(char *argv[])
{
    char *res = NULL;

    OK(maapi_xpath_eval_expr(ms, mtid, argv[0], &res, xpath_trace_f(),
                             argv[1]));
    if (res) {
        printf("%s\n", res);
        free(res);
    }
}

static void do_maapi_close_user(char *argv[])
{
    do_maapi_commit(argv);
    if (ms >= 0) {
        maapi_end_user_session(ms);
        maapi_close(ms);
        ms = -1;
    }
    ms = -1;
}

static void do_maapi_disconnect_remote(char *argv[])
{
    if (ms >= 0) {
        int r = OK(maapi_disconnect_remote(ms, argv[0]));
        printf("disconnected %d clients\n", r);
    }
}

static void do_maapi_disconnect_sockets(char *argv[])
{
    int sockets[MAX_ARGS];
    int i = 0;

    for (i = 0; i < MAX_ARGS && argv[i]; i++)
        sockets[i] = atoi(argv[i]);
    int r = OK(maapi_disconnect_sockets(ms, sockets, i));
    printf("disconnected %d sockets\n", r);
}

static void do_maapi_kill_user_session(char *argv[])
{
    int usessid = atoi(argv[0]);
    OK(maapi_kill_user_session(ms, usessid));
}

static void do_maapi_set_running_status(char *argv[])
{
  enum confd_db_status newstatus = status;

  if (strcmp(argv[0], "valid") == 0) {
    newstatus = CONFD_DB_VALID;
  } else if (strcmp(argv[0], "invalid") == 0) {
    newstatus = CONFD_DB_INVALID;
  } else {
    DBGLOG("set_running_status failed: unknown status %s\n", argv[0]);
    fatal("Unknown status to set_running_status");
  }
  OK(maapi_set_running_db_status(ms, newstatus));
}

static void do_maapi_get_running_status(char *argv[])
{
  enum confd_db_status val;
  val = maapi_get_running_db_status(ms);
  print_db_status(val);
}

static void do_read_only_mode(char *argv[])
{
    maapi_set_readonly_mode(ms, 1);
}

static void do_read_write_mode(char *argv[])
{
    maapi_set_readonly_mode(ms, 0);
}

static void do_in_service_upgrade(char *argv[])
{
    int argc;
    for (argc = 0; argv[argc]; argc++) ;

    OK(maapi_init_upgrade(ms, 10, MAAPI_UPGRADE_KILL_ON_TIMEOUT));
    OK(maapi_perform_upgrade(ms, (const char **)argv, argc));
    OK(maapi_commit_upgrade(ms));
}

static void do_in_service_upgrade_interactive(char *argv[])
{
    char tmp[256], *s;
    int argc;
    for (argc = 0; argv[argc]; argc++) ;

    printf("Initializing upgrade...\n");
    OK(maapi_init_upgrade(ms, 10, MAAPI_UPGRADE_KILL_ON_TIMEOUT));
    printf("Init OK\n");
    printf("press enter... "); fflush(stdout); s=fgets(tmp, 255, stdin);
    if (!s) exit(1);
    printf("Performing upgrade...\n");
    if (maapi_perform_upgrade(ms, (const char **)argv, argc) != CONFD_OK) {
        char * error_str = confd_strerror(confd_errno);
        printf("Perform failed: %s, %d\n", error_str, confd_errno);
    } else {
        printf("Perform OK\n");
        printf("press enter to commit, feed EOF to abort... ");
        fflush(stdout); s=fgets(tmp, 255, stdin);
        if (!s) {
            if( feof(stdin) ) {
                /* Received EOF, abort upgrade */
                printf("Aborting upgrade...\n");
                if (maapi_abort_upgrade(ms) != CONFD_OK) {
                    char *error_str = confd_strerror(confd_errno);
                    printf("Abort failed: %s , %d\n", error_str, confd_errno);
                } else {
                    printf("Abort OK\n");
                }
            } else {
                exit(1);
            }
        } else {
            printf("Committing upgrade...\n");
            if (maapi_commit_upgrade(ms) != CONFD_OK) {
                char * error_str = confd_strerror(confd_errno);
                printf("Commit failed: %s , %d\n", error_str, confd_errno);
            } else {
                printf("Commit OK\n");
            }
        }
    }
}

static void do_start_phase1(char *argv[])
{
    OK(maapi_start_phase(ms, 1, 1));
}

static void do_start_phase2(char *argv[])
{
    OK(maapi_start_phase(ms, 2, 1));
}

static void do_wait_start(char *argv[])
{
    int phase = 2;
    if (argv[0] != NULL) { phase = atoi(argv[0]); }
    OK(maapi_wait_start(ms, phase));
}

static void do_stop(char *argv[])
{
    OK(maapi_stop(ms, 1));
}

static void do_astop(char *argv[])
{
    OK(maapi_stop(ms, 0));
}

static void do_reload(char *argv[])
{
    OK(maapi_reload_config(ms));
}

static void do_reopen_logs(char *argv[])
{
    OK(maapi_reopen_logs(ms));
}

static void do_aaa_reload(char *argv[])
{
    if (argv[0] != NULL) {
        OK(maapi_aaa_reload_path(ms, 1, argv[0]));
    } else {
        OK(maapi_aaa_reload(ms, 1));
    }
}

static void do_snmpa_reload(char *argv[])
{
    OK(maapi_snmpa_reload(ms, 1));
}

static void do_netconf_ssh_call_home(char *argv[]) /* host [port] */
{
    confd_value_t host;
    int port = 4334;

    if (inet_pton(AF_INET, argv[0], &host.val.ip) == 1) {
        host.type = C_IPV4;
    } else if (inet_pton(AF_INET6, argv[0], &host.val.ip6) == 1) {
        host.type = C_IPV6;
    } else {
        CONFD_SET_STR(&host, argv[0]);
    }
    if (argv[1] != NULL) {
        port = atoi(argv[1]);
    }
    OK(maapi_netconf_ssh_call_home(ms, &host, port));
}

static void do_netconf_ssh_call_home_opaque(char *argv[]) /*host opaque [port]*/
{
    confd_value_t host;
    int port = 4334;

    if (inet_pton(AF_INET, argv[0], &host.val.ip) == 1) {
        host.type = C_IPV4;
    } else if (inet_pton(AF_INET6, argv[0], &host.val.ip6) == 1) {
        host.type = C_IPV6;
    } else {
        CONFD_SET_STR(&host, argv[0]);
    }
    if (argv[2] != NULL) {
        port = atoi(argv[2]);
    }
    OK(maapi_netconf_ssh_call_home_opaque(ms, &host, argv[1], port));
}

static void do_rebind_listener(char *argv[])
{
    int listener =
        strcmp(argv[0], "netconf") == 0 ? CONFD_LISTENER_NETCONF
        : strcmp(argv[0], "snmp") == 0 ? CONFD_LISTENER_SNMP
        : strcmp(argv[0], "cli") == 0 ? CONFD_LISTENER_CLI
        : strcmp(argv[0], "webui") == 0 ? CONFD_LISTENER_WEBUI
        : strcmp(argv[0], "netconf_call_home") == 0 ?
        NCS_LISTENER_NETCONF_CALL_HOME
        : 0;

    OK(maapi_rebind_listener(ms, listener));
}

static void do_aaa_clear(char *argv[])
{
    if (argv[0] != NULL) {
        OK(maapi_aaa_reload_path(ms, 0, argv[0]));
    } else {
        OK(maapi_aaa_reload(ms, 0));
    }
}

static void do_clear_opcache(char *argv[])
{
    OK(maapi_clear_opcache(ms, argv[0]));
}

static void do_set_next_usessid(char *argv[])
{
    OK(maapi_set_next_user_session_id(ms, atoi(argv[0])));
}

static const char *vtype2str(enum confd_vtype t)
{
    switch (t) {
    case C_NOEXISTS: return "NOEXISTS";
    case C_XMLTAG: return "XMLTAG";
    case C_SYMBOL: return "SYMBOL";
    case C_STR: return "STR";
    case C_BUF: return "BUF";
    case C_INT8: return "INT8";
    case C_INT16: return "INT16";
    case C_INT32: return "INT32";
    case C_INT64: return "INT64";
    case C_UINT8: return "UINT8";
    case C_UINT16: return "UINT16";
    case C_UINT32: return "UINT32";
    case C_UINT64: return "UINT64";
    case C_DOUBLE: return "DOUBLE";
    case C_IPV4: return "IPV4";
    case C_IPV6: return "IPV6";
    case C_BOOL: return "BOOL";
    case C_QNAME: return "QNAME";
    case C_DATETIME: return "DATETIME";
    case C_DATE: return "DATE";
    case C_TIME: return "TIME";
    case C_DURATION: return "DURATION";
    case C_ENUM_HASH: return "ENUM_HASH";
    case C_BIT32: return "BIT32";
    case C_BIT64: return "BIT64";
    case C_LIST: return "LIST";
    case C_XMLBEGIN: return "XMLBEGIN";
    case C_XMLEND: return "XMLEND";
    case C_OBJECTREF: return "OBJECTREF";
    case C_UNION: return "UNION";
    case C_PTR: return "PTR";
    case C_CDBBEGIN: return "CDBBEGIN";
    case C_OID: return "OID";
    case C_BINARY: return "BINARY";
    case C_IPV4PREFIX: return "IPV4PREFIX";
    case C_IPV6PREFIX: return "IPV6PREFIX";
    case C_DEFAULT: return "DEFAULT";
    case C_DECIMAL64: return "DECIMAL64";
    case C_IDENTITYREF: return "IDENTITYREF";
    case C_XMLBEGINDEL: return "XMLBEGINDEL";
    case C_MAXTYPE:
    default:
        return "UNKNOWN";
    }
}

static void print_node(int indent, struct confd_cs_node *node)
{
    printf("%*s%s", indent, " ", confd_hash2str(node->tag));

    if (node->info.shallow_type != C_XMLTAG) {
        printf(" type=%s", vtype2str(node->info.shallow_type));
    }
    if (node->info.defval) {
        char tmpbuf[BUFSIZ];
        if ((node == NULL) ||
            (confd_val2str(node->info.type, node->info.defval, tmpbuf, BUFSIZ)
             == CONFD_ERR)) {
            confd_pp_value(tmpbuf, BUFSIZ, node->info.defval);
        }
        printf(" default=%s", tmpbuf);
    }
    if (node->info.flags != 0) {
        char tmpbuf[BUFSIZ];
        tmpbuf[0] = '\0';
#define COMMA { if (tmpbuf[0] != '\0') { strcat(tmpbuf, ","); } }
#define FFLAG(FLAG, STR)                        \
        {                                       \
            if (node->info.flags & FLAG) {      \
                COMMA;                          \
                strcat(tmpbuf, STR);            \
            }                                   \
        }
        FFLAG(CS_NODE_IS_CONTAINER, "container");
        FFLAG(CS_NODE_IS_LIST, "list");
        FFLAG(CS_NODE_IS_WRITE, "write");
        FFLAG(CS_NODE_IS_CDB, "cdb");
        FFLAG(CS_NODE_IS_ACTION, "action");
        FFLAG(CS_NODE_IS_PARAM, "param");
        FFLAG(CS_NODE_IS_RESULT, "result");
        FFLAG(CS_NODE_IS_NOTIF, "notif");
        FFLAG(CS_NODE_IS_CASE, "case");
#undef FFLAG
#undef COMMA
        printf(" flags=%s", tmpbuf);
    }
//    if (node->parent) printf(" parent=%s", confd_hash2str(node->parent->tag));
//    if (node->next)   printf(" next=%s", confd_hash2str(node->next->tag));
    printf("\n");
}

static void print_node_recurse(int indent, struct confd_cs_node *start)
{
    if (start == NULL) return;
    print_node(indent, start);
    print_node_recurse(indent + 2, start->children);
    print_node_recurse(indent, start->next);
    return;
}

static void do_dump_schema(char *argv[])
{
    int nns;
    struct confd_nsinfo *nsinfo;
    struct confd_cs_node *node;
    nns = confd_get_nslist(&nsinfo);

    if (argv[0]) {
        node = confd_cs_node_cd(NULL, argv[0]);
        if (node) {
            for (; nns--; nsinfo++) {
                if (nsinfo->hash == node->ns) break;
            }
            printf("ns=%s prefix=%s (%d)\n",
                   nsinfo->uri, nsinfo->prefix, nsinfo->hash);
            print_node(2, node);
            print_node_recurse(4, node->children);
        } else {
            printf("couldn't cd to %s: %s\n", argv[0], confd_lasterr());
        }
        return;
    }

    for (; nns--; nsinfo++) {
        struct confd_cs_node *root = confd_find_cs_root(nsinfo->hash);
        printf("ns=%s prefix=%s (%d)\n",
               nsinfo->uri, nsinfo->prefix, nsinfo->hash);
        print_node_recurse(2, root);
    }
}

static void do_exit(char *argv[])
{
    exit(atoi(argv[0]));
}

static void do_dbset(char *argv[]) {
    enum confd_dbname newmdb = mdb;
    enum cdb_db_type newdb = db;

    if (strcmp(argv[0], "running") == 0) {
        newdb = CDB_RUNNING;
        newmdb = CONFD_RUNNING;
    } else if (strcmp(argv[0], "operational") == 0) {
        newdb = CDB_OPERATIONAL;
        newmdb = CONFD_OPERATIONAL;
    } else if (strcmp(argv[0], "startup") == 0) {
        newdb = CDB_STARTUP;
        newmdb = CONFD_STARTUP;
    } else {
        DBGLOG("dbset failed: unknown db %s\n", argv[0]);
        fatal("Unknown db to dbset");
    }

    if (newdb != db || newmdb != mdb) {
        DBGLOG("[change] dbset %s\n", argv[0]);
        /* Commit any ongoing transaction */
        do_maapi_commit(NULL);

        db = newdb;
        mdb = newmdb;

        /* Start a new transaction with the new database */
        do_maapi_new_trans(NULL);
    }
}

static struct cmd_t {
    char *cmd;
    char *aliases[4];
    void (*func)(char **);
    int nargs;              /*  N            = exactly N arguments
                               -N            = at least N arguments
                               -(MAX_ARGS-1) = zero or more arguments,*/
#define ZERO_OR_MORE_ARGS (-(MAX_ARGS-1))
    int cmd_flags;
    char *help_args;
    char *help;
} cmds[] = {
    /* CDB commands */
    {
        "cdb_get", {"get","g",NULL}, do_cdb_get, 1,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA,
        "<path>", NULL
    },
    {
        "cdb_is_default", {"is_default",NULL}, do_cdb_is_default, 1,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA,
        "<path>", NULL
    },
    {
        "get_case", {NULL}, do_cdb_get_case, 2,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA,
        "<path> <choice>", NULL
    },
    {
        "cdb_cd", {"cd",NULL}, do_cdb_cd, 1, CMD_CDB|CMD_CDB_SESS,
        "<path>", NULL
    },
    {
        "cdb_getcwd", {"cwd",NULL}, do_cdb_getcwd, 0, CMD_CDB|CMD_CDB_SESS,
        NULL, NULL
    },
    {
        "cdb_exists", {"exists",NULL}, do_cdb_exists, 1, CMD_CDB|CMD_CDB_SESS,
        "<path>", NULL
    },
    {
        "get_object", {NULL}, do_cdb_get_object, 1,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA,
        "<path>", NULL
    },
    {
        "get_object_tag", {NULL}, do_cdb_get_object_tags, 1,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA,
        "<path>", NULL
    },
    {
        "get_objects", {NULL}, do_cdb_get_objects, 3,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA,
        "<start> <num> <path>", NULL
    },
    {
        "get_values", {NULL}, do_cdb_get_values, -2,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA,
        "<path> <leaf-node>...",
        "Use cdb_get_values() to get all leafs requested"
    },
    {
        "cdb_set", {"set","s",NULL}, do_cdb_set, 2, CMD_CDB|CMD_CDB_SESS,
        "<path> <value>", NULL
    },
    {
        "set_case", {NULL}, do_cdb_set_case, 3, CMD_CDB|CMD_CDB_SESS,
        "<path> <choice> <case>", NULL
    },
    {
        "num_instances", {"n",NULL}, do_cdb_num_instances, 1,
        CMD_CDB|CMD_CDB_SESS,
        "<path>", NULL
    },
    {
        "cdb_create", {"c","create",NULL}, do_cdb_create, 1,
        CMD_CDB|CMD_CDB_SESS,
        "<path>", NULL
    },
    {
        "delete", {"del",NULL}, do_cdb_delete, 1, CMD_CDB|CMD_CDB_SESS,
        "<path>", NULL
    },
    {
        "cdb_set_object", {"so", NULL}, do_cdb_set_object, -2,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA,
        "<path> <value1> .. <valueN>", NULL
    },
    {
        "start_session", {NULL}, do_cdb_start_session, 0, CMD_CDB, NULL, NULL
    },
    {
        "cdb_close", {NULL}, do_cdb_close, 0, 0, NULL, NULL
    },
    {
        "cdb_initiate_journal_compaction", {"initiate_journal_compaction"},
        do_cdb_initiate_journal_compaction, 0, CMD_CDB, NULL,
        "tell CDB to initiate journal compaction"
    },
    {
        "cdb_get_attrs", {"get_attrs", NULL}, do_cdb_get_attrs, 1,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA, "<path>",
        "get all attributes of given node"
    },
    {
        "cdb_set_annotation", {"set_annotate", NULL}, do_cdb_set_annotation, 2,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA, "<path> <origin>", NULL
    },
    {
        "cdb_delete_annotation", {"del_annotate", NULL},
        do_cdb_delete_annotation, 1, CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA,
        "<path>", NULL
    },
    {
        "cdb_set_origin", {"set_origin", NULL}, do_cdb_set_origin, 2,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA, "<path> <origin>", NULL
    },
    {
        "cdb_delete_origin", {"del_origin", NULL}, do_cdb_delete_origin, 1,
        CMD_CDB|CMD_CDB_SESS|CMD_WANT_SCHEMA, "<path>", NULL
    },

    /* CDB subscription */
    {
        "subwait_iter", {NULL}, do_subwait_iter, -1,
        CMD_CDB|CMD_CDB_SUB|CMD_WANT_SCHEMA,
        "<path> [priority] [loop] [opts]",
        "subscribe to <path> and run cdb_diff_iterate() when notified.\n"
        "  If [opts] is \"suspend\", the subscription will be suspended when\n"
        "  it received first notification.\n"
        "  If [opts] is \"usid\", the subscriber will get usid of the write\n"
        "  transaction that causing the notification."
    },
    {
        "subwait_mods", {"sm",NULL}, do_subwait_mods, -1,
        CMD_CDB|CMD_CDB_SUB|CMD_WANT_SCHEMA,
        "<path> [priority] [loop] [modpath] ['suppress_defaults']"
        " ['exclude_lists']",
        "subscribe to <path> and run cdb_get_modifications() when notified"
    },
    {
        "subwait_mods2", {NULL}, do_subwait_mods2p, -1,
        CMD_CDB|CMD_CDB_SUB|CMD_WANT_SCHEMA,
        "<path> [priority] [loop] [modpath] ['suppress_defaults']",
        "subscribe to <path> using two phase subscription "
        "and run cdb_get_modifications() when notified"
    },
    {
        "subwait_mods_iter", {"smi",NULL},
        do_subwait_dimods, -1, CMD_CDB|CMD_CDB_SUB|CMD_WANT_SCHEMA,
        "<path> [priority] [loop]",
        "subscribe to <path> and run cdb_diff_iterate() (and "
        "cdb_get_modifications_iter() on created/modified list entries) "
        "when notified"
    },
    {
        "subwait_iter2", {NULL}, do_subwait_iter2p, -1,
        CMD_CDB|CMD_CDB_SUB|CMD_WANT_SCHEMA,
        "<path> [priority] [loop] [suspend] [abort]",
        "subscribe to <path> using two phase subscription and run"
        " cdb_diff_iterate() when notified.\n"
        "  If provided [suspend], where possible values are \"prepare\",\n"
        "    \"commit\", or \"both\", the subscription will be suspended\n"
        "    after it receives prepare, commit, or both of the notifications.\n"
        "  If provided [abort] as \"abort\", the subscriber will abort\n"
        "    ongoing transaction at prepare phase."
    },
    {
        "get_cli", {"get_modifications_cli", NULL}, do_subwait_get_cli, -2,
        CMD_CDB|CMD_CDB_SUB,
        "1|2 <path> [priority] [loop] ['no_backquotes']", NULL
    },
    {
        "subwait", {"w",NULL}, do_subwait, -1, CMD_CDB|CMD_CDB_SUB,
        "<path> [priority]", NULL
    },
    {
        "subto", {NULL}, do_subwait_timeout, -2, CMD_CDB|CMD_CDB_SUB,
        "<timeout> <path> [priority]", NULL
    },
    {
        "trigger_subscriptions", {"trigger", NULL},
        do_cdb_trigger_subscriptions, ZERO_OR_MORE_ARGS, CMD_CDB,
        "[subid]...", "Trigger all, or specified, CDB subscriptions"
    },
    {
        "replay_subscriptions", {"replay", NULL},
        do_cdb_replay_subscriptions, ZERO_OR_MORE_ARGS, CMD_CDB,
        "[subid]...", "Replay all, or specified, CDB subscriptions" },
    {
        "get_replay_txids", {"txids", NULL}, do_get_replay_txids, 0, CMD_CDB,
        NULL, NULL
    },

    /* Misc commands */
    {
        "echo", {NULL}, do_echo, ZERO_OR_MORE_ARGS, 0, "<args...>",
        "Echo args to stdout"
    },
    {
        "sleep", {NULL}, do_sleep, 1, 0, "<n>", "Sleep for <n> seconds",
    },
    {
        "suspend", {NULL}, do_suspend, 0, CMD_CDB|CMD_CDB_SESS, NULL,
        "Suspend myself."
    },
    {
        "suspend2", {NULL}, do_suspend2, 0, 0, NULL,
        "Fork, then print child-pid on stdout. Child takes a read-lock, "
        "then suspends itself"
    },
    {
        "wait", {NULL}, do_wait_cdb, 0, CMD_CDB, NULL,
        "Wait until " SERVER " is in phase1"
    },
    {
        "get_phase", {NULL}, do_get_phase, 0, CMD_CDB, NULL,
        "Print current phase"
    },
    {
        "get_txid", {"txid", NULL}, do_get_txid, 0, CMD_CDB, NULL,
        "Print current txid"
    },
    {
        "exit", {NULL}, do_exit, 1, 0,
        "<exit-code>", "Immediately quit (without ending session cleanly)" },
    {
        "dump_schema", {NULL}, do_dump_schema,
        ZERO_OR_MORE_ARGS, CMD_WANT_SCHEMA, NULL,
        "Print schema"
    },
    {
        "dbset", {NULL}, do_dbset, 1, CMD_MAAPI,
        "<dbname>", "Use <dbname> for following commands."
        " <dbname> should be one of 'running', 'operational' or 'startup'."
        " An ongoing transaction will be committed and a new one created."
    },

    /* HA commands */
    {
        "primary", {NULL}, beprimary, 1, CMD_HA, "<nodename>",
        "Tell " SERVER " to become primary"
    },
    {
        "secondary", {NULL}, besecondary, -3, CMD_HA,
        "<nodename> <primaryname> <primaryaddr> [async]",
        "Tell " SERVER " to become secondary"
    },
    {
        "none", {NULL}, benone, 0, CMD_HA, NULL,
        "Tell " SERVER " to exit HA \"be_none()\""
    },
    {
        "relay", {NULL}, berelay, 0, CMD_HA, NULL,
        "Tell " SERVER " to become relay (when secondary)"
    },
    {
        "dead_secondary", {NULL}, dead_secondary, 1, CMD_HA, "<nodename>",
        "Tell " SERVER " that the secondary <nodename> is dead"
    },
    {
        "ha_status", {NULL}, ha_status, 0, CMD_HA, NULL,
        "Get " SERVER " HA status"
    },


    /* Deprecated HA commands */
    {
        "master", {NULL}, beprimary, 1, CMD_HA, "<nodename>",
        "Tell " SERVER " to become master"
    },
    {
        "slave", {NULL}, besecondary, -3, CMD_HA,
        "<nodename> <mastername> <masteraddr> [async]",
        "Tell " SERVER " to become slave"
    },
    {
        "dead_slave", {NULL}, dead_secondary, 1, CMD_HA, "<nodename>",
        "Tell " SERVER " that the slave <nodename> is dead"
    },
    /* MAAPI commands */
    {
        "maction", {NULL}, do_maapi_request_action, 1,
        CMD_MAAPI|CMD_MAAPI_NOTRANS|CMD_WANT_SCHEMA,
        "<path>", "Request action outside the transaction context"
    },
    {
        "maction_th", {NULL}, do_maapi_request_action_th, 1,
        CMD_MAAPI|CMD_WANT_SCHEMA,
        "<path>", "Request action with the transaction context"
    },
    {
        "mattach_init", {NULL}, do_maapi_attach_init, 0,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        NULL, "Attach to current upgrade or init session"
    },
    {
        "mtrans", {NULL}, do_maapi_new_trans, 0, CMD_MAAPI|CMD_MAAPI_NOTRANS,
        NULL, NULL
    },
    {
        "mrtrans", {NULL}, do_maapi_new_readonly_trans, 0,
        CMD_MAAPI|CMD_MAAPI_NOTRANS, NULL, NULL
    },
    {
        "mctrans", {NULL}, do_maapi_new_candidate_trans, 0,
        CMD_MAAPI|CMD_MAAPI_NOTRANS, NULL, NULL
    },
    {
        "mcommit", {NULL}, do_maapi_commit, 0, CMD_MAAPI, NULL, NULL
    },
    {
        "mcommit2", {NULL}, do_maapi_commit2, 0, CMD_MAAPI, NULL, NULL
    },
    {
        "cccommit", {"ccc", NULL}, do_maapi_confirmed_commit, 1,
        CMD_MAAPI|CMD_MAAPI_NOTRANS, "<timeout>", NULL
    },
    {
        "ccommit", {NULL}, do_maapi_ccommit, 0,
        CMD_MAAPI|CMD_MAAPI_NOTRANS, NULL, NULL
    },
    {
        "cabort", {NULL}, do_maapi_cabort, 0, CMD_MAAPI, NULL, NULL
    },
    {
        "creset", {NULL}, do_maapi_creset, 0, CMD_MAAPI, NULL, NULL
    },
    {
        "mset", {NULL}, do_maapi_set, 2, CMD_MAAPI, "<path> <value>", NULL
    },
    {
        "mload", {NULL}, do_maapi_load, 1, CMD_MAAPI, "<filename>", NULL
    },
    {
        "mcreate", {NULL}, do_maapi_create, 1, CMD_MAAPI, "<path>", NULL
    },
    {
        "maapi_delete", {"mdel",NULL}, do_maapi_delete, 1, CMD_MAAPI,
        "<path>", NULL
    },
    {
        "maapi_delete_config", {NULL}, do_maapi_delete_config, 0,
        CMD_MAAPI|CMD_MAAPI_NOTRANS,
        NULL, NULL
    },
    {
        "maapi_get", {"mget",NULL}, do_maapi_get, 1,
        CMD_MAAPI|CMD_WANT_SCHEMA, "<path>", NULL
    },
    {
        "maapi_move", {"mmove",NULL}, do_maapi_move, -2,
        CMD_MAAPI|CMD_WANT_SCHEMA,
        "<path> <where>\n"
        " <where> = first | last | after <refkey> | before <refkey>\n"
        " [experimental - can currently only handle one string key]",
        NULL
    },
    {
        "maapi_exists", {"mexists", NULL}, do_maapi_exists, 1, CMD_MAAPI,
        "<path>", NULL
    },
    {
        "maapi_num_instances", {"mn",NULL}, do_maapi_num_instances, 1,
        CMD_MAAPI, "<path>", NULL
    },
    {
        "traverse_list_keys", {NULL}, do_traverse_list_keys, -1,
        CMD_MAAPI, "<path> [<xpathexpr>]", NULL
    },
    {
        "traverse_list", {NULL}, do_traverse_list, -1,
        CMD_MAAPI, "<path> [<xpathexpr>]", NULL
    },
    {
        "maapi_get_case", {"mget_case", NULL}, do_maapi_get_case, 2,
        CMD_MAAPI|CMD_WANT_SCHEMA,
        "<path> <choice>", NULL
    },
    {
        "maapi_cd", {"mcd", NULL}, do_maapi_cd, 1, CMD_MAAPI, "<path>", NULL
    },
    {
        "activate", {NULL}, do_maapi_activate, 1, CMD_MAAPI, "<path>",
        "set <path> to active"
    },
    {
        "deactivate", {NULL}, do_maapi_deactivate, 1, CMD_MAAPI, "<path>",
        "set <path> to inactive"
    },
    {
        "maapi_lock", {NULL}, do_maapi_lock, 0, CMD_MAAPI, NULL, NULL
    },
    {
        "maapi_unlock", {NULL}, do_maapi_unlock, 0, CMD_MAAPI, NULL, NULL
    },
    {
        "maapi_lock_partial", {NULL}, do_maapi_lock_partial, 1, CMD_MAAPI,
        "<path>", NULL
    },
    {
        "maapi_unlock_partial", {NULL}, do_maapi_unlock_partial, 0, CMD_MAAPI,
        NULL, NULL
    },
    {
        "maapi_clear_opcache", {NULL}, do_maapi_clear_opcache, 1, CMD_MAAPI,
        "<path>", NULL
    },
    {
        "xpath_eval", {"x",NULL}, do_maapi_xpath_eval, -1,
        CMD_MAAPI|CMD_WANT_SCHEMA,
        "<expression> [<context node>]", NULL
    },
    {
        "xpath_eval_expr", {"xe",NULL}, do_maapi_xpath_eval_expr, -1, CMD_MAAPI,
        "<expression> [<context node>]", NULL
    },
    {
        "maapi_close", {NULL}, do_maapi_close_user, 0, 0, NULL, NULL
    },
    {
        "disconnect_remote", {NULL}, do_maapi_disconnect_remote, 1,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        "<address>", NULL
    },
    {
        "disconnect_sockets", {NULL}, do_maapi_disconnect_sockets, -1,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        "<socket fd> ...", NULL
    },
    {
        "maapi_read_only", {"mro",NULL}, do_read_only_mode, 0,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        NULL, "set node in read-only mode (see maapi_set_readonly_mode(3))"
    },
    {
        "maapi_read_write", {"mrw",NULL}, do_read_write_mode, 0,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        NULL, "set node in read-write mode (see maapi_set_readonly_mode(3))"
    },
    {
      "set_running_status", {NULL}, do_maapi_set_running_status, 1, CMD_MAAPI,
      "<value>", NULL
    },
    {
      "get_running_status", {NULL}, do_maapi_get_running_status, 0, CMD_MAAPI,
      NULL, NULL
    },
    {
        "upgrade", {NULL}, do_in_service_upgrade, ZERO_OR_MORE_ARGS,
        CMD_MAAPI|CMD_MAAPI_NOTRANS,
        NULL, NULL
    },
    {
        "upgrade_interactive", {NULL}, do_in_service_upgrade_interactive,
        ZERO_OR_MORE_ARGS,
        CMD_MAAPI|CMD_MAAPI_NOTRANS,
        NULL, NULL
    },
    {
        "start-phase1", {"phase1"}, do_start_phase1, 0,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS, NULL, NULL
    },
    {
        "start-phase2", {"phase2"}, do_start_phase2, 0,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS, NULL, NULL
    },
    {
        "wait-start", {NULL}, do_wait_start, ZERO_OR_MORE_ARGS,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        "[phase]", "Wait until a start-phase is reached"
    },
    {
        "stop", {NULL}, do_stop, 0,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        NULL, "Stop daemon (returns when daemon is stopped)"
    },
    {
        "astop", {NULL}, do_astop, 0,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        NULL, "Initiate stop of daemon"
    },
    {
        "reload", {NULL}, do_reload, 0,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        NULL, "Reload daemon configuration file"
    },
    {
        "reopen_logs", {NULL}, do_reopen_logs, 0,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        NULL, "Reopen daemon log files"
    },
    {
        "aaa_reload", {NULL}, do_aaa_reload, ZERO_OR_MORE_ARGS,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        "[<path>]", "Reload AAA cache (returns when load is complete)"
    },
    {
        "aaa_clear", {NULL}, do_aaa_clear, ZERO_OR_MORE_ARGS,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        "[<path>]", "Clear AAA cache (reload is asynchronous)"
    },
    {
        "clear_opcache", {NULL}, do_clear_opcache, ZERO_OR_MORE_ARGS,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        "[<path>]", "Clear (part of) the operational data cache"
    },
    {
        "set_next_usessid", {NULL}, do_set_next_usessid, 1,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        "<usessid>", "Set the next user session id integer"
    },
    {
        "snmpa_reload", {NULL}, do_snmpa_reload, 0,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        NULL, "Reload SNMP Agent config (returns when load is complete)"
    },
    {
        "netconf_ssh_call_home", {NULL}, do_netconf_ssh_call_home, -1,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        "<host> [<port>]", "Initiate a NETCONF SSH call home session"
    },
    {
        "netconf_ssh_call_home_opaque", {NULL},
        do_netconf_ssh_call_home_opaque, -1,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        "<host> <opaque> [<port>]",
        "Initiate a NETCONF SSH call home session passing <opaque>"
    },
    {
        "rebind_listener", {NULL}, do_rebind_listener, -1,
        CMD_MAAPI|CMD_MAAPI_NOUSER|CMD_MAAPI_NOTRANS,
        "<listener> = netconf | snmp | cli | webui | netconf_call_home",
        "Rebind northbound listener"
    },
    {
        "maapi_get_attrs", {"mget_attrs", NULL}, do_maapi_get_attrs, 1,
        CMD_MAAPI|CMD_WANT_SCHEMA, "<path>", NULL
    },
    {
        "maapi_set_annotation", {"mset_annotate", NULL},
        do_maapi_set_annotation, 2, CMD_MAAPI|CMD_WANT_SCHEMA,
        "<path> <annotation>", NULL
    },
    {
        "maapi_set_origin", {"mset_origin", NULL}, do_maapi_set_origin, 2,
        CMD_MAAPI|CMD_WANT_SCHEMA, "<path> <origin>", NULL
    },
    {
        "maapi_delete_annotation", {"mdel_annotate", NULL},
        do_maapi_delete_annotation, 1, CMD_MAAPI|CMD_WANT_SCHEMA,
        "<path>", NULL
    },
    {
        "maapi_delete_origin", {"mdel_origin", NULL},
        do_maapi_delete_origin, 1, CMD_MAAPI|CMD_WANT_SCHEMA,
        "<path>", NULL
    },
    {
        "maapi_kill_user_session", {NULL}, do_maapi_kill_user_session, 1,
        CMD_MAAPI|CMD_MAAPI_NOTRANS,
        "<usessid>", "Kill the user session with provided id."
    },

    { NULL, {NULL}, NULL, 0, 0, NULL, NULL }
};

static void free_script(struct script *pgm)
{
    if (pgm) {
        struct cmdline *p, *pnext;
        for (p=pgm->pgm; p; p=pnext) {
            int i;
            for (i=0; i<p->argc; i++) {
                free(p->argv[i]);
            }
            pnext = p->next;
            free(p);
        }
        free(pgm);
    }
}

static int run(struct script *pgm, int do_close)
{
    struct cmdline *pc;

    for (pc=pgm->pgm; pc; pc=pc->next) {
        char *cmd = pc->argv[0];
        int argc = pc->argc - 1;
        struct cmd_t *cc;
        if (pc->argc == 0) continue;

        for (cc = cmds; cc->cmd != NULL; cc++) {
            if (strcmp(cmd, cc->cmd) == 0) {
                break;
            }
            if (cc->aliases[0]) {
                char **alias;
                for (alias = cc->aliases; *alias != NULL; alias++) {
                    if (strcmp(cmd, *alias) == 0) {
                        break;
                    }
                }
                if (*alias) {
                    break;
                }
            }
        }
        if (cc->cmd) {
            if (debug_trace) {
                int i;
                DBGLOG("+%s", cc->cmd);
                for (i=1; i<pc->argc; i++) {
                    DBGLOG(" \"%s\"", pc->argv[i]);
                }
                fprintf(stderr, "\n");
            }
            if ((cc->nargs != ZERO_OR_MORE_ARGS) && (argc < abs(cc->nargs))) {
                DBGLOG("too few arguments to cmd: %s\n", cc->cmd);
                fatal("too few arguments");
            }
            if ((cc->cmd_flags & CMD_WANT_SCHEMA) && (load_schema == 0)) {
                OK(confd_load_schemas(addr, addrlen));
                load_schema = 1;
            }
            if ((cc->cmd_flags & CMD_CDB) && (cs < 0)) {
                enum cdb_sock_type st = (cc->cmd_flags & CMD_CDB_SUB) ?
                    CDB_SUBSCRIPTION_SOCKET : CDB_DATA_SOCKET;
                assert((cs = get_socket()) >= 0);
                OK(cdb_connect(cs, st, addr, addrlen));
                if (cc->cmd_flags & CMD_CDB_SESS) {
                    do_cdb_start_session(NULL);
                }
            }
            if (cc->cmd_flags & CMD_MAAPI) {
                /* start user session */
                if (ms < 0) {
                    struct confd_ip msrc;
                    msrc.af = AF_INET;
                    inet_pton(AF_INET, "127.0.0.1", &msrc.ip.v4);
                    assert((ms = get_socket()) >= 0);
                    OK(maapi_connect(ms, addr, addrlen));
                    if (!(cc->cmd_flags & CMD_MAAPI_NOUSER)) {
                        OK(maapi_start_user_session(
                               ms, muser, mctxt,
                               (const char **)groups, ngroups,
                               &msrc, CONFD_PROTO_TCP));
                    }
                }
                if ((mtid == 0) && !(cc->cmd_flags & CMD_MAAPI_NOTRANS)) {
                    do_maapi_new_trans(NULL);
                }
            }
            if ((cc->cmd_flags & CMD_HA) && (hs < 0)) {
                assert((hs = get_socket()) >= 0);
                OK(confd_ha_connect(hs, addr, addrlen, progname));
            }
            cc->func(pc->argv + 1);
            if (!preserve_session && (cs >= 0)) {
                if (cc->cmd_flags & CMD_CDB_SESS) { OK(cdb_end_session(cs)); }
                OK(cdb_close(cs));
                cs = -1;
            }
            if (!preserve_session && (ms >= 0)) {
                if (mtid != 0) {
                    do_maapi_commit(NULL);
                }
            }
        } else {
            fprintf(stderr, "%s:%d: unknown command: %s (try "
                    "\"%s -h commands\" for a list of avaliable commands)\n",
                    pgm->source, pc->lineno, cmd, progname);
            fatal("unknown command");
        }
    }
    if (do_close) {
        do_cdb_close(NULL);
        do_maapi_close_user(NULL);
    }
    return 0;
}

static void print_script(struct script *program, FILE *f)
{
    struct cmdline *c, *prev = NULL;
    int line=1, i;
    for (c=program->pgm; c != NULL; prev=c, c=c->next) {
        for (; line < c->lineno; line++) { fprintf(f, "\n"); }
        if (prev && (prev->lineno == c->lineno)) {
            fprintf(f, " ; ");
        }
        if (c->argc > 0) {
            fprintf(f, "%s", c->argv[0]);
            for (i=1; i < c->argc; i++) {
                fprintf(f, " \"%s\"", c->argv[i]);
            }
        }
    }
    fprintf(f, "\n");
}

static struct cmdline *read_line(int lineno, char *line)
{
    struct cmdline *l;
    char *b, *c;
    int inquote;

    b = line;
    while(isspace(*b)) b++;
    if ((*b == 0) || (*b == '#')) {
        /* empty line */
        return NULL;
    }

    l = (struct cmdline *)malloc(sizeof(struct cmdline));
    assert(l);
    memset(l, 0, sizeof(*l));
    l->lineno = lineno;
    l->argc = 0;
    l->next = NULL;

    for (;;b=c) {
        char *argtmp; size_t argsz;
        inquote = 0;
        while(isspace(*b)) b++;
        if ((*b == 0) || (*b == '#')) goto done;
        if (*b == ';') {
            l->next = read_line(lineno, b+1);
            goto done;
        }
        if (*b == '"') {
            b++;
            inquote=1;
        }
        for (c=b;;c++) {
            if (*c == 0) break;
            if (!inquote && isspace(*c)) break;
            if (!inquote && (*c == '#')) break;
            if (!inquote && (*c == ';')) break;
            if (inquote && (*c == '"')) break;
        }
        argsz = c-b+1;
        argtmp = (char *)malloc(argsz);
        assert(argtmp);
        memset(argtmp, 0, argsz);
        memcpy(argtmp, b, argsz-1);
        if (l->argc == MAX_ARGS) {
            fprintf(stderr, "%d: MAX_ARGS reached: %s\n", lineno, argtmp);
            exit(1);
        }
        l->argv[l->argc] = argtmp;
        l->argc++;
        if (inquote) c++;
    }
    done:
    return l;
}

static struct script *read_file(char *filename)
{
    FILE *f;
    char line[BUFSIZ];
    struct cmdline *cur;
    struct script *program;
    int lineno;

    program = (struct script *)malloc(sizeof(struct script));
    assert(program);

    if (strcmp(filename, "-") == 0) {
        f = stdin;
        program->source = "stdin";
    } else {
        if ((f = fopen(filename, "r")) == NULL) {
            fprintf(stderr, "Couldn't open \"%s\": %s\n",
                    filename, strerror(errno));
            exit(1);
        }
        program->source = filename;
    }
    program->pgm = NULL;
    for (cur = NULL, lineno = 1; !feof(f); lineno++) {
        struct cmdline *tmp;
        if (fgets(line, BUFSIZ, f) == NULL) break;
        tmp = read_line(lineno, line);
        if (program->pgm == NULL) {
            program->pgm = cur = tmp;
        } else {
            cur->next = tmp;
        }
        while (cur && cur->next) { cur = cur->next; }
    }
    if (f != stdin) {
        fclose(f);
    }
    return program;
}

/* fork, listen, child suspends itself */
static void do_listen(int port)
{
    pid_t pid;
    struct sockaddr_in myname;
    int lsock;
    int lineno = 1;
    int on = 1;
    struct script *program;

    lsock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&myname, 0, sizeof(myname));
    myname.sin_family = AF_INET;
    myname.sin_port = htons(port);
    myname.sin_addr.s_addr = inet_addr("127.0.0.1");

    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if (bind(lsock, (struct sockaddr*)&myname, sizeof(myname) ) < 0 ) {
        fprintf(stderr, "network server bind failure %d\n", errno);
        exit(1);
    }
    listen(lsock, 5);

    if ((pid = fork()) == 0) {
        /* child */

        static struct confd_daemon_ctx *dctx;
        static int ctlsock;

        close(fileno(stdout)); /* make sure shell doesn't wait for output */

        /* create a control socket to ConfD so we can terminate if
           ConfD dies */
        if ((dctx = confd_init_daemon("confd_cmd_daemon")) == NULL)
            confd_fatal("Failed to initialize daemon\n");
        if ((ctlsock = get_socket()) < 0)
            confd_fatal("Failed to open ctlsocket\n");
        if (confd_connect(dctx, ctlsock, CONTROL_SOCKET, addr, addrlen) < 0)
            confd_fatal("Failed to confd_connect() to confd \n");

        while (1) {
            struct pollfd set[2];

            set[0].fd = lsock;
            set[0].events = POLLIN;
            set[0].revents = 0;

            set[1].fd = ctlsock;
            set[1].events = POLLIN;
            set[1].revents = 0;

            if (poll(&set[0], 2, -1) < 0) {
                perror("Poll failed:");
                continue;
            }

            if (set[1].revents & POLLIN) {
                // ConfD died - terminate
                exit(1);
            }
            if (set[0].revents & POLLIN) { // someone is connecting to us
                int asock = accept(lsock, 0,  0);
                char buf[BUFSIZ];
                char *p = &buf[0];
                int more = 1;
                int sz = BUFSIZ-1;
                int r;
                // read one line
                while (more && sz) {
                    if ((r = read(asock, p, sz)) <= 0) {
                        fprintf(stderr, "bad ctl read");
                        exit(1);
                    }
                    p[r] = '\0';
                    if (strchr(p, '\n')) {
                        more = 0;
                    }
                    p += r;
                    sz -= r;
                }

                program = (struct script *)malloc(sizeof(struct script));
                assert(program);
                program->source = "socket";
                program->pgm = read_line(lineno, buf);
                // execute the line
                if (debug > CONFD_SILENT) {
                    print_script(program, stderr);
                }
                run(program, 0);
                free_script(program);
                // close the socket to the client
                close(asock);
                lineno++;
            }
        }
    }
    printf("%ld\n", (long)pid);
}


static void usage()
{
    printf("Usage:\n"
           "  %s [options] [filename]\n"
           "  %s [options] -c <script>\n"
           "  %s -h | -h commands | -h <command-name>\n",
           progname, progname, progname);
    printf(
        "A utility that provides a command line interface towards some cdb\n"
        "and maapi functions. Commands are expected in filename (or stdin\n"
        "if not provided). Commands can also be given using the -c option.\n"
        "Valid options are:\n");
    printf(
"  -d             Increase debug level for each -d flag\n"
"  -a <address>   Connect to " SERVER " at <address> (default 127.0.0.1)\n"
"  -p <port>      Connect to " SERVER " at <port> (default %d)\n"
"  -r             Commands work on 'running' database\n"
"  -S             Commands work on 'startup' database\n"
"  -o             CDB commands work on CDB operational database\n"
"  -e             MAAPI commands work on candidate database\n"
"  -I             MAAPI commands work on 'intended' database\n"
"  -f [w][p][r|s] Use cdb_start_session2() to start the CDB session - values\n"
"                 w/p/r/s set the CDB_LOCK_WAIT/PARTIAL/REQUEST/SESSION flags\n"
"  -F [d]         Use maapi_start_trans_flags() to start the transaction.\n"
"                 Value d sets the MAAPI_FLAG_DELAYED_WHEN flag.\n"
"  -u <user>      Connect to maapi as <user> (default system)\n"
"  -g <group>     Connect to maapi with group <group> (more than one allowed)\n"
"  -x <ctxt>      Connect to maapi with context <ctxt> (default system)\n"
"  -s             Perform each command in a different session\n"
"  -c <string>    Commands are read from <string> instead of a file\n"
"  -m             Don't call confd_load_schemas()\n"
"  -U             Make all output unbuffered\n"
"  -L             diff_iterate on leaf-lists as leaf, not list [deprecated]\n"
"  -h             Display this text and exit\n"
"  -h <cmd-name>  Show help for <cmd-name> and exit\n"
"  -h commands    List all available commands and exit\n"
"  -b             Use biased-free language for HA status roles (default)\n"
"  -O             Use deprecated language for HA status roles \n"
"  -n             Do not auto-commit\n",
CONFD_PORT);
}

static void help(int argc, char *argv[])
{
    struct cmd_t *cc;

    if (argc == 0) {
        printf("%s: available commands:\n", progname);
    } else {
        int i;
        printf("%s: help for command%s: ", progname, (argc>1) ? "s" : "");
        for(i=0; i<argc; i++) { printf("%s", argv[i]); }
        printf("\n\n");
    }
    for (cc = cmds; cc->cmd != NULL; cc++) {
        if (argc > 0) {
            char **as;
            int i, found = 0;
            for (i=0; i<argc; i++) {
                if (strcmp(argv[i], cc->cmd) == 0) { found++; }
                for (as = cc->aliases; *as != NULL; as++) {
                    if (strcmp(argv[i], *as) == 0) { found++; }
                }
            }
            if (!found) {
                continue;
            }
        }
        printf("%s", cc->cmd);
        if (cc->aliases[0]) {
            char **alias;
            for (alias = cc->aliases; *alias != NULL; alias++) {
                printf("|%s", *alias);
            }
        }
        if (cc->nargs != 0) {
            if (cc->help_args) {
                printf(" %s", cc->help_args);
            } else {
                printf(" (%s%d arguments)",
                       ((cc->nargs < 0) ? "at least " : ""),
                       (cc->nargs == ZERO_OR_MORE_ARGS) ?
                       0 : abs(cc->nargs));
            }
        }
        printf("\n");
        if (cc->help) { printf("  %s\n", cc->help); }
    }
    printf("\n");
}

static int is_env_set(const char *env_name)
{
    char *env_value = getenv(env_name);

    return env_value == NULL ? 0 : *env_value != 0;
}


int main(int argc, char *argv[])
{
    char *confd_addr = NULL;
    int confd_port = 0;
    int need_help = 0;
    int unbuffered_output = 0;
    int c, ecode = 0;
    char *cmd = NULL;
    struct script *pgm = NULL;
    int lport = 0;

    /* Setup progname (without path component) */
    if ((progname = strrchr(argv[0], (int)'/')) == NULL)
        progname = argv[0];
    else
        progname++;

    const char *ops = "da:p:orSIf:F:isUu:x:g:etc:l:mhL?qbOn";
    /* Parse command line */
    while ((c = getopt(argc, argv, ops)) != EOF) {
        switch (c) {
        case 'd':
            debug++;
            break;
        case 't':
            debug_trace++;
            break;
        case 'a':
            confd_addr = optarg;
            break;
        case 'p':
            confd_port = atoi(optarg);
            break;
        case 'r':
            db = CDB_RUNNING;
            mdb = CONFD_RUNNING;
            break;
        case 'o':
            db = CDB_OPERATIONAL;
            mdb = CONFD_OPERATIONAL;
            break;
        case 'S':
            db = CDB_STARTUP;
            mdb = CONFD_STARTUP;
            break;
        case 'e':
            mdb = CONFD_CANDIDATE;
            break;
        case 'I':
            mdb = CONFD_INTENDED;
            break;
        case 'f':
            sess_flags = 0;
            if (strchr(optarg, 'w')) sess_flags |= CDB_LOCK_WAIT;
            if (strchr(optarg, 'r')) sess_flags |= CDB_LOCK_REQUEST;
            if (strchr(optarg, 's')) sess_flags |= CDB_LOCK_SESSION;
            if (strchr(optarg, 'p')) sess_flags |= CDB_LOCK_PARTIAL;
            break;
        case 'F':
            mflags = 0;
            if (strchr(optarg, 'd')) mflags |= MAAPI_FLAG_DELAYED_WHEN;
            break;
        case 'u':
            muser = optarg;
            break;
        case 'x':
            mctxt = optarg;
            break;
        case 'g':
            groups[ngroups] = optarg;
            ngroups++;
            break;
        case 'i':
            printf("%d\n", getpid());
            fflush(stdout);
            break;
        case 's':
            preserve_session = 0;
            break;
        case 'c':
            cmd = optarg;
            break;
        case 'l':
            lport = atoi(optarg);
            break;
        case 'm':
            load_schema = -1;
            break;
        case 'U':
            unbuffered_output++;
            break;
        case 'L':
            leaf_iter = ITER_WANT_LEAF_LIST_AS_LEAF;
            break;
        case 'h':
            need_help++;
            break;
        case 'b':
            biased_free = 1;
            break;
        case 'O':
            biased_free = 0;
            break;
        case 'n':
            gmcommit = 1;
            break;
        default:
            if (optopt == '?') {
                need_help++;
            } else {
                fprintf(stderr, "%s: unknown option -%c "
                        "(try \"%s -h\" for a list of valid options)\n",
                        progname, (char)optopt, progname);
                exit(1);
            }
            break;
        }
    }
    argc -= optind;
    argv += optind;

    if (need_help) {
        if (argc == 0) {
            usage();
        } else {
            if ((strcmp(argv[0], "commands") == 0) ||
                (strcmp(argv[0], "all") == 0)) {
                help(0, NULL);
            } else {
                help(argc, argv);
            }
        }
        exit(0);
    }

    if ((ngroups == 0) && muser) { /* make sure we are always in a group */
        groups[0] = muser;
        ngroups = 1;
    }

    /* Initialize address to confd daemon */
    get_daemon_addr(confd_addr, confd_port);

    /* always save trace output when testing unless option 'q' is given */
    if ((debug == CONFD_SILENT) && is_env_set("CONFD_CMD_TRACE_TMP_FILE")) {
        char fname[255];
        char *suffix = getenv("CONFD_CMD_TRACE_SUFFIX");
        char *mode;
        struct sockaddr_in *in_addr_p = (struct sockaddr_in *)addr;

        if ((family != PF_INET) || (ntohs(in_addr_p->sin_port) == PORT)) {
            snprintf(fname, sizeof(fname), "_tmp_%s", progname);
        } else {
            snprintf(fname, sizeof(fname), "_tmp_%s.%d", progname, confd_port);
        }
        if (suffix) {
            char tmpstr[16];
            if (strcmp(suffix, "pid") == 0) {
                snprintf(tmpstr, sizeof(tmpstr), "%lu",(unsigned long)getpid());
                suffix = tmpstr;
            }
            strncat(fname, suffix, sizeof(fname) - strlen(fname) - 1);
        }
        if (getenv("CONFD_CMD_TRACE_APPEND")) {
            mode = "a";
        } else {
            mode = "w";
        }
        if ((debugf = fopen(fname, mode)) == NULL) {
            fprintf(stderr, "Couldn't open \"%s\": %s\n",
                    fname, strerror(errno));
            exit(1);
        }
        debug = CONFD_TRACE;
    } else if (debug == CONFD_SILENT) {
        debugf = NULL;
    } else {
        debugf = stderr;
    }
    if (unbuffered_output) {
        setvbuf(stdout, NULL, _IONBF, 0);
        if (debugf) {
            setvbuf(debugf, NULL, _IONBF, 0);
        }
    }
    confd_init(progname, debugf, debug);
    signal(SIGPIPE, SIG_DFL);

    if (cmd) {
        pgm = (struct script *)malloc(sizeof(*pgm));
        assert(pgm);
        pgm->source = "cmdline";
        pgm->pgm = read_line(0, cmd);
    } else if (lport) {
        do_listen(lport);
    } else {
        pgm = read_file((argc == 0) ? "-" : argv[0]);
    }
    if (debug > CONFD_SILENT && pgm) { print_script(pgm, debugf); }

    if (pgm && pgm->pgm) { ecode = run(pgm, 1); }

    /* keep valgrind happy */
    free_script(pgm);

    exit(ecode);
}
