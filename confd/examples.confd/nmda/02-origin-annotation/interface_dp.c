#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>

#include <confd_lib.h>
#include <confd_dp.h>

#include "example-interface.h"
#include "ietf-origin.h"

char *progname = NULL;
int debuglevel = CONFD_SILENT;
int ctlsock    = -1;
int workersock = -1;

#define CB_GET_ELEM 0
#define CB_GET_NEXT 1
#define CB_GET_ATTRS 2

#define N_CB 3

struct cb_stat {
    char *callpoint;
    u_int32_t cb_counters[N_CB];
};
static char *callpoints[255];
static struct cb_stat *cb_stat;
static int n_cb_stat = 0;

struct interface {
    char *name;
    char *ip;
    u_int32_t mtu;
    uint32_t origin;
};

/*
   In order to simplify the example,
   two static operational interfaces are defined.
*/
static struct interface IFACES[] = {
    {"lo", "127.0.0.1", 0, or_system},
    {"eth0", "100.10.0.1", 1500, or_intended},
    {NULL, NULL, -1, -1}
};

/* ------------------------------------------------------------------------ */
static struct interface *find_interface(confd_hkeypath_t *kp)
{
    struct interface *iface;
    char *name = NULL;

    if (kp->v[0][0].type == C_BUF) {
        name = (char*)CONFD_GET_BUFPTR(&kp->v[0][0]);
    } else if (kp->v[1][0].type == C_BUF) {
        name = (char*)CONFD_GET_BUFPTR(&kp->v[1][0]);
    } else {
        return NULL;
    }

    for (iface = IFACES; iface->name != NULL; iface++) {
        if (strcmp(iface->name, name) == 0) {
            return iface;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------------ */
static int cb_get_next(struct confd_trans_ctx *tctx,
                       confd_hkeypath_t *keypath,
                       long next)
{
    struct interface *iface;
    confd_value_t v;

    next = (next == -1) ? 0: next;
    iface = IFACES + next;

    if (iface->name == NULL) {
        confd_data_reply_next_key(tctx, NULL, -1, -1);
        return CONFD_OK;
    }

    CONFD_SET_STR(&v, iface->name);
    confd_data_reply_next_key(tctx, &v, 1, next + 1);
    return CONFD_OK;
}

static int cb_get_elem(struct confd_trans_ctx *tctx,
                       confd_hkeypath_t *keypath)
{
    confd_value_t v;
    struct in_addr ip;

    struct interface *iface = find_interface(keypath);

    if (iface == NULL) {
        confd_data_reply_not_found(tctx);
        return CONFD_OK;
    }
    switch (CONFD_GET_XMLTAG(&(keypath->v[0][0]))) {
    case interface_name:
        CONFD_SET_STR(&v, iface->name);
        break;
    case interface_mtu:
        CONFD_SET_UINT32(&v, iface->mtu);
        break;
    case interface_ipv4_address:
        inet_pton(AF_INET, iface->ip, &ip);
        CONFD_SET_IPV4(&v, ip);
        break;
    default:
        return CONFD_ERR;
    }
    confd_data_reply_value(tctx, &v);
    return CONFD_OK;
}

static int cb_get_attrs(struct confd_trans_ctx *tctx,
                        confd_hkeypath_t *kp,
                        u_int32_t *attrs, int num_attrs)
{
    confd_attr_value_t origin;
    struct interface *iface = find_interface(kp);

    if (iface == NULL) {
        confd_data_reply_not_found(tctx);
        return CONFD_OK;
    }

    origin.attr = CONFD_ATTR_ORIGIN;
    struct confd_identityref idref = {.ns = or__ns, .id = iface->origin};
    CONFD_SET_IDENTITYREF(&origin.v, idref);
    confd_data_reply_attrs(tctx, &origin, 1);
    return CONFD_OK;
}

/* ------------------------------------------------------------------------ */
void register_data_cb(struct confd_daemon_ctx *dctx, char **callpoints)
{
    struct confd_data_cbs dcb;
    char **cp;
    int i;

    assert(dctx);
    memset(&dcb, 0, sizeof(dcb));
    dcb.get_elem = cb_get_elem;
    dcb.get_next = cb_get_next;
    dcb.get_attrs = cb_get_attrs;

    for (cp = callpoints, i = 0; *cp; cp++, i++) {
        strcpy(dcb.callpoint, *cp);
        dcb.cb_opaque = &cb_stat[i];
        cb_stat[i].callpoint = *cp;
        confd_register_data_cb(dctx, &dcb);
        if (debuglevel > CONFD_SILENT)
            fprintf(stderr, "%s: registered %s\n", progname, *cp);
    }
}

/* ------------------------------------------------------------------------ */
static int tr_init(struct confd_trans_ctx *tctx)
{
    confd_trans_set_fd(tctx, workersock);
    return CONFD_OK;
}

static int tr_finish(struct confd_trans_ctx *tctx)
{
    return CONFD_OK;
}

void register_trans_callback(struct confd_daemon_ctx *dctx)
{
    struct confd_trans_cbs tcb;
    assert(dctx);
    memset(&tcb, 0, sizeof(tcb));
    tcb.init = tr_init;
    tcb.finish = tr_finish;

    confd_register_trans_cb(dctx, &tcb);
}

/* ------------------------------------------------------------------------ */
static struct confd_daemon_ctx *dctx = NULL;

static int connect_confd(struct sockaddr_in *addr)
{
    dctx = confd_init_daemon(progname);

    if ((ctlsock = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
        fprintf(stderr, "Failed to open ctlsocket\n");
        return -1;
    }
    if (confd_connect(dctx, ctlsock, CONTROL_SOCKET, (struct sockaddr*)addr,
                      sizeof (struct sockaddr_in)) < 0) {
        fprintf(stderr, "Failed to confd_connect() to confd \n");
        return -1;
    }

    if ((workersock = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
        close(ctlsock);
        fprintf(stderr, "Failed to open workersocket\n");
        return -1;
    }
    if (confd_connect(dctx, workersock, WORKER_SOCKET,(struct sockaddr*)addr,
                      sizeof (struct sockaddr_in)) < 0) {
        close(ctlsock);
        close(workersock);
        fprintf(stderr, "Failed to confd_connect() to confd \n");
        return -1;
    }

    register_trans_callback(dctx);
    register_data_cb(dctx, callpoints);

    if (confd_register_done(dctx) != CONFD_OK) {
        fprintf(stderr, "Failed to complete registration \n");
        close(ctlsock);
        close(workersock);
        return -1;
    }

    return 1;
}

int main(int argc, char *argv[])
{
    int o;
    struct sockaddr_in addr;

    /* Setup progname (without path component) */
    if ((progname = strrchr(argv[0], (int)'/')) == NULL)
        progname = argv[0];
    else
        progname++;

    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    {
        char *port = getenv("CONFD_IPC_PORT");
        if (port) {
            addr.sin_port = htons(atoi(port));
        } else {
            addr.sin_port = htons(CONFD_PORT);
        }
    }

    while ((o = getopt(argc, argv, "hdp:")) != -1) {
        switch (o) {
        case 'd':
            debuglevel++;
            break;
        case 'p':
            addr.sin_port = htons(atoi(optarg));
            break;
        case 'h':
            printf("usage: interface_dp [options] callpoint...\n");
            exit(0);
        default:
            printf("-h for usage\n");
            exit(1);
        }
    }

    argc -= optind;
    argv += optind;

    confd_init(progname, stderr, debuglevel);

    if (argc > 0) {
        int i;
        for (i=0; i<argc; i++) {
            callpoints[i] = argv[i];
        }
        cb_stat = (struct cb_stat *)calloc(i, sizeof(struct cb_stat));
        n_cb_stat = i;
        callpoints[i] = NULL;
    } else {
        fprintf(stderr, "callpoints?\n");
        exit(1);
    }

    if (confd_load_schemas((struct sockaddr*)&addr,
                           sizeof (struct sockaddr_in)) != CONFD_OK) {
        fprintf(stderr, "Failed to load schemas from confd\n");
        return -1;
    }

    if (connect_confd(&addr) < 0) {
        confd_fatal("Failed to connect to confd\n");
    }

    printf("%s: started\n", progname);

    for (;;) {
        struct pollfd pfds[3];
        int ret;

        pfds[0].fd = ctlsock;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = workersock;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        poll(pfds, 2, -1);

        if (pfds[0].revents & POLLIN) {
            if ((ret = confd_fd_ready(dctx, ctlsock)) == CONFD_EOF) {
                confd_fatal("%s: Control socket closed\n", progname);
            } else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
                confd_fatal("%s: Error on control socket request: "
                            "%s (%d): %s\n", progname,
                            confd_strerror(confd_errno), confd_errno,
                            confd_lasterr());
            }
        }
        if (pfds[1].revents & POLLIN) {
            if ((ret = confd_fd_ready(dctx, workersock)) == CONFD_EOF) {
                confd_fatal("%s: Worker socket closed\n", progname);
            } else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
                confd_fatal(
                    "%s: Error on worker socket request: %s (%d): %s\n",
                    progname, confd_strerror(confd_errno),
                    confd_errno, confd_lasterr());
            }
        }
    }
}
