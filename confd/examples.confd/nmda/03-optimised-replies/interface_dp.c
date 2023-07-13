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

int opt_get_object = 0;
int opt_get_next_object = 0;

#define CB_GET_ELEM 0
#define CB_GET_NEXT 1
#define CB_GET_ATTRS 2
#define CB_GET_OBJECT 3
#define CB_GET_NEXT_OBJECT 4
#define CB_GET_NEXT_OBJECTS 5

#define N_CB 6

static const char* cb_names[] = {
    "get_elem",
    "get_next",
    "get_attrs",
    "get_object",
    "get_next_object",
    "get_next_objects"
};

struct cb_stat {
    char *callpoint;
    u_int32_t cb_counters[N_CB];
};
static char *callpoints[255];
static struct cb_stat *cb_stat;
static int n_cb_stat = 0;

struct interface {
    char *name;
    char *ip_address;
    uint16_t mtu;
    uint32_t origin[3];
};

/*
   In order to simplify the example,
   two static operational interfaces are defined.
*/
static struct interface IFACES[] = {
    {"lo", "127.0.0.1", 0, {or_system, or_learned, or_system}},
    {"eth0", "100.10.0.1", 1500, {or_intended, or_learned,  or_default}},
    {NULL, NULL, -1, {0,0,0}}
};

/* ------------------------------------------------------------------------ */
static void cb_inc(struct confd_trans_ctx *tctx, int idx)
{
    struct cb_stat *s = (struct cb_stat *)tctx->cb_opaque;

    s->cb_counters[idx]++;
}

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
                       confd_hkeypath_t *kp, long next)
{
    cb_inc(tctx, CB_GET_NEXT);

    confd_value_t v;
    struct confd_attr_value origin;
    struct confd_identityref idref = {.ns = or__ns};
    origin.attr = CONFD_ATTR_ORIGIN;

    next = (next == -1) ? 0: next;
    struct interface *iface = IFACES + next;
    if (iface->name == NULL) {
        confd_data_reply_next_key(tctx, NULL, 0, 0);
        return CONFD_OK;
    }
    CONFD_SET_STR(&v, iface->name);
    idref.id = iface->origin[0];
    CONFD_SET_IDENTITYREF(&origin.v, idref);

    /*
      Demonstration of 03-optimised-replies:
      An optional reply for the get_next callback that
      returns key value and the list entry's attributes.
    */
    confd_data_reply_next_key_attrs(tctx, &v, 1, next+1, &origin, 1);
    return CONFD_OK;
}

static int cb_get_elem(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    cb_inc(tctx, CB_GET_ELEM);

    confd_value_t v;
    struct in_addr ip;

    confd_attr_value_t origin, av[2];
    origin.attr = CONFD_ATTR_ORIGIN;
    struct confd_identityref idref = {.ns = or__ns};

    struct interface *iface = find_interface(kp);

    if (iface == NULL) {
        confd_data_reply_not_found(tctx);
        return CONFD_OK;
    }

    switch (CONFD_GET_XMLTAG(&(kp->v[0][0]))) {
    case interface_name:
        CONFD_SET_STR(&v, iface->name);
        confd_data_reply_value_attrs(tctx, &v, NULL, 0);
        return CONFD_OK;
    case interface_ipv4_address:
        inet_pton(AF_INET, iface->ip_address, &ip);
        CONFD_SET_IPV4(&v, ip);
        idref.id = iface->origin[1];
        break;
    case interface_mtu:
        CONFD_SET_UINT32(&v, iface->mtu);
        if (strcmp(iface->name, "eth0") == 0) {
                idref.id = iface->origin[2];
                CONFD_SET_IDENTITYREF(&origin.v, idref);
                av[0] = origin;
                av[1].attr = CONFD_ATTR_ANNOTATION;
                CONFD_SET_STR(&av[1].v, "annotated");
                confd_data_reply_value_attrs(tctx, &v, av, 2);
                return CONFD_OK;
        } else {
            idref.id = iface->origin[2];
        }
        break;
    default:
        return CONFD_ERR;
    }
    CONFD_SET_IDENTITYREF(&origin.v, idref);

    /*
      Demonstration of 03-optimised-replies:
      An optional reply for the get_elem callback that
      returns a single node value with its attributes.
    */
    confd_data_reply_value_attrs(tctx, &v, &origin, 1);
    return CONFD_OK;
}

static int cb_get_attrs(struct confd_trans_ctx *tctx,
                        confd_hkeypath_t *kp,
                        u_int32_t *attrs, int num_attrs)
{
    cb_inc(tctx, CB_GET_ATTRS);

    confd_attr_value_t origin;
    origin.attr = CONFD_ATTR_ORIGIN;
    struct confd_identityref idref = {.ns = or__ns};
    struct interface *iface = find_interface(kp);

    if (iface == NULL) {
        confd_data_reply_not_found(tctx);
        return CONFD_OK;
    }

    if (kp->v[0][0].type == C_XMLTAG) {
        switch (CONFD_GET_XMLTAG(&(kp->v[0][0]))) {
        case interface_ipv4_address:
            idref.id = iface->origin[1];
        break;
        case interface_mtu:
            idref.id = iface->origin[2];
        break;
        default:
            confd_data_reply_attrs(tctx, NULL, 0);
            return CONFD_OK;
        }
    } else if (kp->v[1][0].type == C_XMLTAG) {
        idref.id = iface->origin[0];
    } else {
        confd_data_reply_attrs(tctx, NULL, 0);
        return CONFD_OK;
    }
    CONFD_SET_IDENTITYREF(&origin.v, idref);
    confd_data_reply_attrs(tctx, &origin, 1);
    return CONFD_OK;
}

static int cb_get_object(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    cb_inc(tctx, CB_GET_OBJECT);

    struct interface *iface = find_interface(kp);

    confd_tag_value_attr_t tva[2];

    confd_attr_value_t origin[2], av[2];
    struct confd_identityref idref = {.ns = or__ns};

    struct in_addr ip;
    int i = 0;

    origin[i].attr = CONFD_ATTR_ORIGIN;
    /*
       Skip the first element in the origin array as
       it is used for the list entry.
    */
    idref.id = iface->origin[i+1];
    CONFD_SET_IDENTITYREF(&origin[i].v, idref);
    inet_pton(AF_INET, iface->ip_address, &ip);
    CONFD_SET_TAG_ATTR_IPV4(&tva[i], interface_ipv4_address, ip, &origin[i], 1);
    i++;

    origin[i].attr = CONFD_ATTR_ORIGIN;
    idref.id = iface->origin[i+1];
    CONFD_SET_IDENTITYREF(&origin[i].v, idref);
    if (strcmp(iface->name, "eth0") == 0) {
        av[0] = origin[i];
        av[1].attr = CONFD_ATTR_ANNOTATION;
        CONFD_SET_STR(&av[1].v, "annotated");
        CONFD_SET_TAG_ATTR_UINT32(&tva[i], interface_mtu, iface->mtu, av, 2);
    } else {
        CONFD_SET_TAG_ATTR_UINT32(&tva[i], interface_mtu, iface->mtu,
                                  &origin[i], 1);
    }
    i++;

    /*
      Demonstration of 03-optimised-replies:
      An optional reply for the get_object callback that
      returns an array of values and attributes,
      corresponding to a complete list entry.
    */
    confd_data_reply_tag_value_attrs_array(tctx, tva, i);
    return CONFD_OK;
}

static int cb_get_next_object(struct confd_trans_ctx *tctx,
                              confd_hkeypath_t *kp, long next)
{
    cb_inc(tctx, CB_GET_NEXT_OBJECT);
    int i = (next == -1) ? 0: next;
    int j = 0;
    confd_tag_value_attr_t tva[3];

    confd_attr_value_t origin[3], av[2];
    struct confd_identityref idref = {.ns = or__ns};

    struct in_addr ip;
    struct interface *iface = IFACES + i;
    if (iface->name == NULL) {
        confd_data_reply_next_object_tag_value_array(tctx, NULL, -1, -1);
        return CONFD_OK;
    }
    inet_pton(AF_INET, iface->ip_address, &ip);

    /*
      Attributes for a list entry are given to the first key leaf of the list
      (key leafs do not have attributes).
    */
    origin[j].attr = CONFD_ATTR_ORIGIN;
    idref.id = iface->origin[j];
    CONFD_SET_IDENTITYREF(&origin[j].v, idref);
    CONFD_SET_TAG_ATTR_STR(&tva[j], interface_name, iface->name, &origin[j], 1);
    j++;

    origin[j].attr = CONFD_ATTR_ORIGIN;
    idref.id = iface->origin[j];
    CONFD_SET_IDENTITYREF(&origin[j].v, idref);
    CONFD_SET_TAG_ATTR_IPV4(&tva[j], interface_ipv4_address, ip, &origin[j], 1);
    j++;

    origin[j].attr = CONFD_ATTR_ORIGIN;
    idref.id = iface->origin[j];
    CONFD_SET_IDENTITYREF(&origin[j].v, idref);
    if (strcmp(iface->name, "eth0") == 0) {
        av[0] = origin[j];
        av[1].attr = CONFD_ATTR_ANNOTATION;
        CONFD_SET_STR(&av[1].v, "annotated");
        CONFD_SET_TAG_ATTR_UINT32(&tva[j], interface_mtu, iface->mtu, av, 2);
    } else {
        CONFD_SET_TAG_ATTR_UINT32(&tva[j], interface_mtu, iface->mtu,
                                  &origin[j], 1);
    }
    j++;

    /*
      Demonstration of 03-optimised-replies:
      An optional reply for the get_next_object callback that
      returns an entire object including its keys and attributes of lists entry.
    */
    confd_data_reply_next_object_tag_value_attrs_array(tctx, tva, j, i+1);
    return CONFD_OK;
}

static int cb_get_next_objects(struct confd_trans_ctx *tctx,
                               confd_hkeypath_t *kp, long next)
{
    cb_inc(tctx, CB_GET_NEXT_OBJECTS);
    int pos = (next == -1) ? 0: next;

    if (pos >= 2) {
        confd_data_reply_next_object_tag_value_arrays(tctx, NULL, 0, 0);
        return CONFD_OK;
    }

    struct interface *iface = NULL;

    confd_attr_value_t av[2];

    struct confd_identityref idref = {.ns = or__ns};

    struct in_addr ip;
    struct confd_tag_next_object_attrs next_obj[opt_get_next_object];
    int i;
    for (i = 0; i < opt_get_next_object; i++) {

        confd_attr_value_t *origin =
            malloc(3 * sizeof(confd_attr_value_t));
        confd_tag_value_attr_t *tva =
            malloc(3 * sizeof(confd_tag_value_attr_t));

        iface = IFACES + i;
        if (iface->name == NULL) {
            confd_data_reply_next_object_tag_value_arrays(tctx, NULL, 0, 0);
            return CONFD_OK;
        }

        /*
          Attributes for a list entry are given to the first key leaf.
          (key leafs do not have attributes).
        */
        origin->attr = CONFD_ATTR_ORIGIN;
        idref.id = iface->origin[0];
        CONFD_SET_IDENTITYREF(&origin->v, idref);
        CONFD_SET_TAG_ATTR_STR(tva, interface_name, iface->name, origin, 1);
        tva++; origin++;

        inet_pton(AF_INET, iface->ip_address, &ip);
        origin->attr = CONFD_ATTR_ORIGIN;
        idref.id = iface->origin[1];
        CONFD_SET_IDENTITYREF(&origin->v, idref);
        CONFD_SET_TAG_ATTR_IPV4(tva, interface_ipv4_address, ip, origin, 1);
        tva++; origin++;

        origin->attr = CONFD_ATTR_ORIGIN;
        idref.id = iface->origin[2];
        CONFD_SET_IDENTITYREF(&origin->v, idref);
        if (strcmp(iface->name, "eth0") == 0) {
            av[0] = *origin;
            av[1].attr = CONFD_ATTR_ANNOTATION;
            CONFD_SET_STR(&av[1].v, "annotated");
            CONFD_SET_TAG_ATTR_UINT32(tva, interface_mtu, iface->mtu, av, 2);
        } else {
            CONFD_SET_TAG_ATTR_UINT32(tva, interface_mtu, iface->mtu,
                                      origin, 1);
        }
        tva++; origin++;

        next_obj[i].tva = tva-3;
        next_obj[i].n = 3;
        next_obj[i].next = (long)(++pos);
    }

    /*
      Demonstration of 03-optimised-replies:
      An optional reply for the get_next_object callback that returns
      multiple objects including its keys and attributes of lists entries.
    */
    confd_data_reply_next_object_tag_value_attrs_arrays(tctx, next_obj, i, 0);

    for (i = 0; i < opt_get_next_object; i++) {
        if (next_obj[i].tva) {
            free(next_obj[i].tva);
        }

    }
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
    if (opt_get_object) {
        dcb.get_object = cb_get_object;
    }
    if (opt_get_next_object == 1) {
        dcb.get_next_object = cb_get_next_object;
    }
    if (opt_get_next_object > 1) {
        dcb.get_next_object = cb_get_next_objects;
    }
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
    struct sockaddr_in myname;
    int lsock;
    int on = 1;

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

    while ((o = getopt(argc, argv, "dhp:oO:")) != -1) {
        switch (o) {
        case 'd':
            debuglevel++;
            break;
        case 'o':
            opt_get_object = 1;
            break;
        case 'O':
            opt_get_next_object = atoi(optarg);
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

    // Now setup our socket to control this dp

    if ((lsock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
        confd_fatal("Failed to open listen socket\n");

    memset(&myname, 0, sizeof(myname));
    myname.sin_family = AF_INET;
    myname.sin_port = htons(9999);
    myname.sin_addr.s_addr = inet_addr("127.0.0.1");
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if (bind(lsock, (struct sockaddr*)&myname, sizeof(myname) ) < 0 )
        confd_fatal("Failed to bind listen socket\n");

    listen(lsock, 5);

    for (;;) {
        struct pollfd pfds[3];
        int ret;

        pfds[0].fd = ctlsock;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = workersock;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;
        pfds[2].fd = lsock;
        pfds[2].events = POLLIN;
        pfds[2].revents = 0;

        poll(pfds, 3, -1);

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
        if (pfds[2].revents & POLLIN) { // someone is connecting to us
            int asock = accept(lsock, 0,  0);
            char buf[BUFSIZ];
            char *startbuf = "BEGIN\n";

            // write a welcome message
            write(asock, startbuf, strlen(startbuf));

            if (read (asock, buf, BUFSIZ)  <= 0) {
                fprintf(stderr, "bad ctl read");
                exit(1);
            }
            switch (buf[0]) {
            case 'g': { // get counters
                int i, j, n;
                struct cb_stat *s;

                for (i = 0; i < n_cb_stat; i++) {
                    s = &cb_stat[i];
                    for (j = 0; j < N_CB; j++) {
                        n = snprintf(buf, BUFSIZ, "%s %s %d\n",
                                     s->callpoint,
                                     cb_names[j],
                                     s->cb_counters[j]);
                        write(asock, buf, n);
                    }
                }
                close(asock);
                break;
            }
            case 'c': { // clear counters
                int i, j;
                struct cb_stat *s;

                for (i = 0; i < n_cb_stat; i++) {
                    s = &cb_stat[i];
                    for (j = 0; j < N_CB; j++) {
                        s->cb_counters[j] = 0;
                    }
                }
                close(asock);
                break;
            }
            }
        }
    }
}
