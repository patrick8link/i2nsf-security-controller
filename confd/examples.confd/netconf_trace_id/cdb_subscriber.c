
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

#include <confd.h>
#include <confd_cdb.h>
#include <confd_maapi.h>

static char *progname;
static enum confd_debug_level debug = CONFD_SILENT;
static FILE *debugf = NULL;
static struct sockaddr_in addr; /* Keeps address to confd daemon */
static struct confd_daemon_ctx *dctx;
static int maapisock, ctlsock;

#define OK(E) assert((E) == CONFD_OK)

void pval(confd_value_t *v)
{
    char buf[BUFSIZ];
    confd_pp_value(buf, BUFSIZ, v);
    fprintf(stderr, "%s\n", buf);
}

int main(int argc, char **argv)
{
    char *confd_addr = "127.0.0.1";
    int confd_port = CONFD_PORT;
    int c, id, subsock;

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
    while ((c = getopt(argc, argv, "da:p:")) != EOF) {
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

    /* always save trace output somewhere */
    if (debug == CONFD_SILENT) {
        debugf = fopen("_tmp_stat.out", "w");
        debug = CONFD_TRACE;
    } else {
        debugf = stderr;
    }

    confd_init(progname, debugf, debug);
    OK(confd_load_schemas((struct sockaddr *)&addr, sizeof(addr)));

    assert((maapisock = socket(PF_INET, SOCK_STREAM, 0)) >= 0);
    OK(maapi_connect(maapisock,
                     (struct sockaddr*)&addr, sizeof(addr)));

    assert((dctx = confd_init_daemon(progname)) != NULL);
    assert((ctlsock = socket(PF_INET, SOCK_STREAM, 0)) >= 0);
    OK(confd_connect(dctx, ctlsock, CONTROL_SOCKET,
                     (struct sockaddr*)&addr, sizeof(addr)));

    fprintf(stderr, "setup done\n");

    assert((subsock = socket(PF_INET, SOCK_STREAM, 0)) >= 0);
    OK(cdb_connect(subsock, CDB_SUBSCRIPTION_SOCKET,
                   (struct sockaddr *)&addr, sizeof(addr)));
    OK(cdb_subscribe(subsock, 10, 0, &id, "/servers/server"));
    OK(cdb_subscribe_done(subsock));

    fprintf(stderr, "subscription done\n");

    while (1) {
        struct pollfd set[1];
        int n, subids[1], thandle;
        confd_tag_value_t *values;
        int nvalues;

        set[0].fd = subsock;
        set[0].events = POLLIN;
        set[0].revents = 0;
        if (poll(set, 1, -1) < 0) {
            perror("poll() failed:");
            continue;
        }
        if (cdb_read_subscription_socket(subsock, subids, &n) == CONFD_EOF) {
            fprintf(stderr, "subsock closed\n");
            exit(0);
        }
        assert(n == 1);
        assert(subids[0] == id);
        fprintf(stderr, "got subid %d\n", subids[0]);
        assert((thandle = cdb_get_transaction_handle(subsock)) >= 0);
        fprintf(stderr, "got thandle %d\n", thandle);
        OK(maapi_attach2(maapisock, 0, 0, thandle));
        OK(maapi_ncs_get_trans_params(maapisock, thandle, &values, &nvalues));
        int i = 0;
        while (i++ < nvalues) {
            confd_value_t *v = &(values[0].v);
            pval(v);
        }
        free(values);
        cdb_sync_subscription_socket(subsock, CDB_DONE_PRIORITY);
    }
    return 0;
}
