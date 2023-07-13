/*
 * Copyright 2021 Tail-f Systems AB
 *
 * Permission to use this code as a starting point hereby granted
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/poll.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <assert.h>

#include <confd_lib.h>
#include <confd_cdb.h>

#include "example.h"


static char *progname;
static enum confd_debug_level debug = CONFD_SILENT;
static FILE *debugf = NULL;
static FILE *outf;
static struct sockaddr_in addr; /* Keeps address to confd daemon */


#define OK(E) assert((E) == CONFD_OK)


struct iter_state {
    int ds;         /* A CDB socket connected to RUNNING */
    int ps;         /* A CDB socket connected to PRE_COMMIT_RUNNING */
    char *subpath;
};

static enum cdb_iter_ret vrf_delete(confd_hkeypath_t *kp,
                                 enum cdb_iter_op op,
                                 confd_value_t *oldv,
                                 confd_value_t *newv,
                                 void *state)
{
    const char *vrf;
    char pathstr[BUFSIZ];

    confd_pp_kpath(pathstr, sizeof(pathstr), kp);
    fprintf(debugf, "%s: vrf_delete %s\n", progname, pathstr);
    vrf = CONFD_GET_CBUFPTR(&kp->v[kp->len - 3][0]);
    if (op == MOP_DELETED) {
        /* other operations ignored or handled elsewhere */
        fprintf(outf, "VRF %s DELETE\n", vrf);
    }
    return ITER_RECURSE;
}

static enum cdb_iter_ret vrf_iter(confd_hkeypath_t *kp,
                                 enum cdb_iter_op op,
                                 confd_value_t *oldv,
                                 confd_value_t *newv,
                                 void *state)
{
    const char *vrf;
    char pathstr[BUFSIZ];

    confd_pp_kpath(pathstr, sizeof(pathstr), kp);
    fprintf(debugf, "%s: vrf_iter %s\n", progname, pathstr);
    vrf = CONFD_GET_CBUFPTR(&kp->v[kp->len - 3][0]);
    if (op == MOP_CREATED) {
        /* other operations ignored or handled elsewhere */
        fprintf(outf, "VRF %s CREATE\n", vrf);
    }
    return ITER_RECURSE;
}

static enum cdb_iter_ret ip_iter(confd_hkeypath_t *kp,
                                 enum cdb_iter_op op,
                                 confd_value_t *oldv,
                                 confd_value_t *newv,
                                 void *state)
{
    const char *if_name;
    char ip[BUFSIZ];
    char pathstr[BUFSIZ];
    char value[BUFSIZ];
    u_int32_t tag;

    confd_pp_kpath(pathstr, sizeof(pathstr), kp);
    fprintf(debugf, "%s: ip_iter %s\n", progname, pathstr);
    if_name = CONFD_GET_CBUFPTR(&kp->v[kp->len - 3][0]);
    confd_pp_value(ip, sizeof(ip), &kp->v[kp->len - 5][0]);
    switch (op) {
    case MOP_CREATED:
        fprintf(outf, "IF %s IP %s CREATE\n", if_name, ip);
        return ITER_RECURSE;
    case MOP_DELETED:
        fprintf(outf, "IF %s IP %s DELETE\n", if_name, ip);
        return ITER_CONTINUE;
    case MOP_MODIFIED:
        return ITER_RECURSE;
    case MOP_VALUE_SET:
        tag = CONFD_GET_XMLTAG(&kp->v[0][0]);
        if (tag != example_address) {
            /* not interested in key value set */
            confd_pp_value(value, sizeof(value), newv);
            fprintf(outf, "IF %s IP %s SET %s %s\n",
                    if_name, ip, confd_hash2str(tag), value);
        }
        return ITER_CONTINUE;
    default:
        return ITER_RECURSE;
    }
}

static enum cdb_iter_ret if_iter(confd_hkeypath_t *kp,
                                 enum cdb_iter_op op,
                                 confd_value_t *oldv,
                                 confd_value_t *newv,
                                 void *state)
{
    const char *if_name;
    char pathstr[BUFSIZ];
    u_int32_t tag;
    char value[BUFSIZ];

    confd_pp_kpath(pathstr, sizeof(pathstr), kp);
    fprintf(debugf, "%s: if_iter %s\n", progname, pathstr);
    if (kp->len > 3 &&
        CONFD_GET_XMLTAG(&kp->v[kp->len - 4][0]) == example_ip) {
        return ITER_CONTINUE;
    }
    if_name = CONFD_GET_CBUFPTR(&kp->v[kp->len - 3][0]);
    switch (op) {
    case MOP_CREATED:
        fprintf(outf, "IF %s CREATE\n", if_name);
        return ITER_RECURSE;
    case MOP_DELETED:
        if (kp->len == 3) {
            /* iface deletion; IP addresses have been already processed */
            fprintf(outf, "IF %s DELETE\n", if_name);
        } else {
            fprintf(outf, "IF %s DELETE %s\n",
                    if_name, confd_hash2str(CONFD_GET_XMLTAG(&kp->v[0][0])));
        }
        return ITER_CONTINUE;
    case MOP_MODIFIED:
        return ITER_RECURSE;
    case MOP_VALUE_SET:
        tag = CONFD_GET_XMLTAG(&kp->v[0][0]);
        if (tag == example_enabled) {
            fprintf(outf, "IF %s %s\n", if_name,
                    CONFD_GET_BOOL(newv) ? "enabled" : "disabled");
        } else if (tag != example_name) {
            confd_pp_value(value, sizeof(value), newv);
            fprintf(outf, "IF %s SET %s %s\n",
                    if_name, confd_hash2str(tag), value);
        }
        return ITER_CONTINUE;
    default:
        return ITER_RECURSE;
    }
}

static enum cdb_iter_ret handle_delete(confd_hkeypath_t *kp,
                                       enum cdb_iter_op op,
                                       confd_value_t *oldv,
                                       confd_value_t *newv,
                                       void *state)
{
    /* Handling only whole interface delete - all IP address instances
       need to be processed too. */
    struct iter_state *is = (struct iter_state *)state;
    int ps = is->ps;

    if (op == MOP_DELETED && kp->len == 3 &&
        CONFD_GET_XMLTAG(&kp->v[1][0]) == example_ifc) {
        /* A whole interface was deleted */
        int i, n;
        confd_value_t *name = &kp->v[0][0];
        char namestr[32];

        confd_pp_value(namestr, sizeof(namestr), name);

        /* Use PRE_COMMIT_RUNNING to read out deleted IP addresses */
        assert(ps >= 0);
        OK(cdb_pushd(ps, "%h", kp));
        n = cdb_num_instances(ps, "ip");
        for (i=0; i<n; i++) {
            confd_value_t ip;
            char ipstr[32];
            cdb_get(ps, &ip, "ip[%d]/address", i);
            confd_pp_value(ipstr, sizeof(ipstr), &ip);
            fprintf(outf, "IF %s IP %s DELETE\n", namestr, ipstr);
        }
        OK(cdb_popd(ps));
    }
    return ITER_CONTINUE;
}


int main(int argc, char *argv[])
{
    char *confd_addr = "127.0.0.1";
    int confd_port = CONFD_PORT;
    int c;
    char *outfname = NULL;

    /* Setup progname (without path component) */
    if ((progname = strrchr(argv[0], (int)'/')) == NULL)
        progname = argv[0];
    else
        progname++;

    {
        char *ptmp = getenv("CONFD_IPC_PORT");
        if (ptmp) {
            confd_port = atoi(ptmp);
        } else {
            confd_port = CONFD_PORT;
        }
    }

    /* Parse command line */
    while ((c = getopt(argc, argv, "da:p:o:")) != EOF) {
        switch (c) {
        case 'd':
            debug++;
            break;
        case 'a':
            confd_addr = optarg;
            break;
        case 'p':
            confd_port = atoi(optarg);
            break;
        case 'o':
            outfname = optarg;
            break;
        default:
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;

    /* Initialize address to confd daemon */
    {
        struct in_addr in;
        if (inet_pton(AF_INET, confd_addr, &in) == 1) {
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = in.s_addr;
            addr.sin_port = htons(confd_port);
        } else {
            fprintf(stderr, "unparsable adress: %s\n", confd_addr);
            exit(1);
        }
    }

    outf = stdout;

    /* always save trace output somewhere */
    if (debug == CONFD_SILENT) {
        char fname[255];
        char *suffix = getenv("CDB_SET_FILE_SUFFIX");
        if (confd_port == CONFD_PORT) {
            snprintf(fname, sizeof(fname), "_tmp_%s", progname);
        } else {
            snprintf(fname, sizeof(fname), "_tmp_%s.%d", progname, confd_port);
        }
        if (suffix) {
            char tmpstr[16];
            if (strcmp(suffix, "pid") == 0) {
                snprintf(tmpstr, sizeof(tmpstr), "%d", (int)getpid());
                suffix = tmpstr;
            }
            strncat(fname, suffix, sizeof(fname) - strlen(fname) - 1);
        }
        if ((debugf = fopen(fname, "w")) == NULL) {
            perror("couldn't open logfile");
            exit(1);
        }
        debug = CONFD_TRACE;
    } else {
        debugf = stderr;
    }

    if (outfname) {
        if ((outf = fopen(outfname, "w")) == NULL) {
            perror("couldn't open output file");
            exit(1);
        }
    }


    /* set stdout and debugf to unbuffered */
    setvbuf(outf, NULL, _IONBF, 0);
    setvbuf(debugf, NULL, _IONBF, 0);

    confd_init(progname, debugf, debug);
    OK(confd_load_schemas((struct sockaddr *)&addr, sizeof(addr)));

    {
        char *if_subpath = "/example:sys/ifc";
        char *ip_subpath = "/example:sys/ifc/ip";
        char *vrf_subpath = "/example:sys/vrf";
        int i, ps, ss, ds;
        struct {
            int subid;
            char *subpath;
            enum cdb_iter_ret (*iter) (confd_hkeypath_t *, enum cdb_iter_op,
                                       confd_value_t *, confd_value_t *,
                                       void *);
        } subs[] =
              {{.subpath=vrf_subpath, .iter=vrf_iter},
               {.subpath=if_subpath, .iter=handle_delete},
               {.subpath=if_subpath, .iter=if_iter},
               {.subpath=ip_subpath, .iter=ip_iter},
               {.subpath=vrf_subpath, .iter=vrf_delete}};

        assert((ss = socket(PF_INET, SOCK_STREAM, 0)) >= 0);
        assert((ds = socket(PF_INET, SOCK_STREAM, 0)) >= 0);
        assert((ps = socket(PF_INET, SOCK_STREAM, 0)) >= 0);
        OK(cdb_connect(ss, CDB_SUBSCRIPTION_SOCKET,
                       (struct sockaddr *)&addr, sizeof(addr)));
        OK(cdb_connect(ds, CDB_DATA_SOCKET,
                       (struct sockaddr *)&addr, sizeof(addr)));
        OK(cdb_connect(ps, CDB_DATA_SOCKET,
                       (struct sockaddr *)&addr, sizeof(addr)));

        for (i=0; i < sizeof(subs)/sizeof(subs[0]); i++) {
            /* use priorities 100, 200, 300, ... to allow other
               subscribers to squeeze in */
            OK(cdb_subscribe(ss, (i+1)*100, 0,
                             &subs[i].subid, subs[i].subpath));
        }
        OK(cdb_subscribe_done(ss));

        fprintf(outf, "%s: started\n", progname);

        /* everything setup, fork and off we go */
        if (fork()) {
            /* parent */
            _exit(0);
        }

        for (;;) {
            struct pollfd fdset;

            fdset.fd = ss;
            fdset.events = POLLIN;
            fdset.revents = 0;

            if (poll(&fdset, 1, -1) < 0) {
                perror("poll() failed:");
                continue;
            }

            if (fdset.revents) {
                int r, i, j, n, subids[cdb_active_subscriptions];
                struct iter_state is;

                if ((r = cdb_read_subscription_socket(ss, subids, &n)) ==
                    CONFD_EOF) {
                    /* ConfD closed socket, take appropriate action... */
                    fprintf(outf, "%s: ConfD closed, exiting\n", progname);
                    exit(0);
                }
                if (r != CONFD_OK) {
                    confd_fatal("Error on ConfD socket: %s (%d): %s\n",
                                confd_strerror(confd_errno), confd_errno,
                                confd_lasterr());
                    exit(1);
                }

                is.subpath = if_subpath;
                OK(cdb_start_session(ds, CDB_RUNNING));
                is.ds = ds;
                if (cdb_start_session(ps, CDB_PRE_COMMIT_RUNNING) ==
                    CONFD_OK) {
                    is.ps = ps;
                } else {
                    /* For synthetic subscription triggers there is no prev */
                    assert(confd_errno == CONFD_ERR_NOEXISTS);
                    is.ps = -1;
                }

                for (i=0; i<n; i++) {
                    for (j=0; j < sizeof(subs)/sizeof(subs[0]); j++) {
                        if (subs[j].subid == subids[i]) {
                            fprintf(debugf,
                                    "%s: ======== path %s triggered\n",
                                    progname, subs[j].subpath);
                            OK(cdb_diff_iterate(ss,
                                                subs[j].subid,
                                                subs[j].iter,
                                                0,
                                                &is));
                        }
                    }
                }

                OK(cdb_end_session(ds));
                if (is.ps >= 0) { OK(cdb_end_session(ps)); }

                OK(cdb_sync_subscription_socket(ss, CDB_DONE_PRIORITY));
            }
        }

        cdb_close(ss);
        cdb_close(ds);

    }


    exit(0);
}
