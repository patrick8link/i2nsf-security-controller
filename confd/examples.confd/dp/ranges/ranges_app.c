/*********************************************************************
 * ConfD DP API callback range registration example
 *
 * This is ConfD Sample Code.
 *
 * (C) 2018 Tail-f Systems
 * Permission to use this code as a starting point hereby granted
 *
 * See the README file for more information
 ********************************************************************/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <confd_lib.h>
#include <confd_dp.h>
#include <confd_maapi.h>

#include "ranges_cbs.h"

// the "global" variables passed around the daemon execution code
struct global_vars {
    int ctlsock;
    int workersock;
} glob;

// return the struct sockaddr_in with defined IPv4 address / port
struct sockaddr_in get_sockaddr_by_ip_port(in_addr_t addr, in_port_t port) {
    struct sockaddr_in sock_addr;
    sock_addr.sin_addr.s_addr = addr;
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(port);
    return sock_addr;
}

// initialize socket connection of specific type towards ConfD
int confd_sock_init(
    struct confd_daemon_ctx *dctx,
    in_addr_t addr, in_port_t port,
    enum confd_sock_type type,
    int *out_sock
) {
    struct sockaddr_in dest_addr = get_sockaddr_by_ip_port(addr, port);

    *out_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (*out_sock < 0) {
        confd_fatal("Failed to open socket\n");
    }

    int res = confd_connect(dctx, *out_sock, type,
                (struct sockaddr*)&dest_addr, sizeof (struct sockaddr_in));
    if (res < 0) {
        confd_fatal("Failed to confd_connect() to confd \n");
    }

    return CONFD_OK;
}

static int init_transaction(struct confd_trans_ctx *tctx)
{
    confd_trans_set_fd(tctx, glob.workersock);
    return CONFD_OK;
}

static int stop_transaction(struct confd_trans_ctx *tctx)
{
    return CONFD_OK;
}

int main(int argc, char **argv)
{
    const char * daemon_name_str = argv[0];

    // initialize the library as a first mandatory step
    confd_init(daemon_name_str, stderr, CONFD_SILENT);

    const in_addr_t confd_addr = inet_addr("127.0.0.1");
    const int confd_port = CONFD_PORT;

    struct confd_daemon_ctx *dctx = confd_init_daemon(daemon_name_str);
    if (NULL == dctx) {
        confd_fatal("Failed to initialize confd\n");
    }

    confd_set_daemon_flags(dctx, 0);

    // load schemas to get a nicer prints (keypath tag names etc.)
    struct sockaddr_in confd_sock_addr = get_sockaddr_by_ip_port(confd_addr,
                                        confd_port);
    int res = confd_load_schemas((struct sockaddr*)&confd_sock_addr,
                                 sizeof(struct sockaddr_in));
    if (res != CONFD_OK) {
        confd_fatal("Failed to load schemas from confd\n");
    }

    confd_sock_init(dctx, confd_addr, confd_port, CONTROL_SOCKET,
                    &glob.ctlsock);

    confd_sock_init(dctx, confd_addr, confd_port, WORKER_SOCKET,
                    &glob.workersock);

    struct confd_trans_cbs transaction_cb;
    memset(&transaction_cb, 0x00, sizeof(transaction_cb));
    transaction_cb.init = init_transaction;
    transaction_cb.finish = stop_transaction;
    confd_register_trans_cb(dctx, &transaction_cb);

    if (CONFD_OK != register_all_callbacks(dctx)) {
        confd_fatal("Failed to register data callbacks!\n");
    }

    if (CONFD_OK != confd_register_done(dctx)) {
        confd_fatal("Failed to complete registration \n");
    }

    printf("entering poll loop\n");

    // handle infinite socket loop
    while (1) {
        struct pollfd set[2];
        int ret;

        set[0].fd = glob.ctlsock;
        set[0].events = POLLIN;
        set[0].revents = 0;

        set[1].fd = glob.workersock;
        set[1].events = POLLIN;
        set[1].revents = 0;

        if (poll(&set[0], 2, -1) < 0) {
            perror("Poll failed:");
            continue;
        }

        if (set[0].revents & POLLIN) {
            if ((ret = confd_fd_ready(dctx, glob.ctlsock)) == CONFD_EOF) {
                confd_fatal("Control socket closed\n");
            } else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
                confd_fatal("Error on control socket request: %s (%d): %s\n",
                     confd_strerror(confd_errno), confd_errno, confd_lasterr());
            }
        }
        if (set[1].revents & POLLIN) {
            if ((ret = confd_fd_ready(dctx, glob.workersock)) == CONFD_EOF) {
                confd_fatal("Worker socket closed\n");
            } else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
                confd_fatal("Error on worker socket request: %s (%d): %s\n",
                     confd_strerror(confd_errno), confd_errno, confd_lasterr());
            }
        }

    }

    return 0;
}