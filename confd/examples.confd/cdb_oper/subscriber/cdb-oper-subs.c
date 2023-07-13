/*
 * ConfD CDB operational data subscriber example
 *
 * (C) 2018 Tail-f Systems
 * Permission to use this code as a starting point hereby granted
 *
 * See the README file for more information
 */

#include <stdlib.h>
#include <stdio.h>

#include <sys/socket.h>
#include <sys/poll.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>

#include <confd_lib.h>
#include <confd_cdb.h>

#include "routes.h"

// operation type to string helper
static const char * get_op_str(enum cdb_iter_op op) {
    switch (op) {
        case MOP_CREATED: return "CREATED";
        case MOP_DELETED: return "DELETED";
        case MOP_MODIFIED: return "MODIFIED";
        case MOP_VALUE_SET: return "SET";
        default: return "UNEXPECTED";
   }
}

// Iteration procedure invoked by ConfD lib for each atomic change
// being done on registered subscription.
static enum cdb_iter_ret iterate_changes(
    confd_hkeypath_t *kp,
    enum cdb_iter_op op,
    confd_value_t *oldv,
    confd_value_t *newv,
    void *state
) {
    const char * op_str = get_op_str(op);
    char kp_buf[BUFSIZ];
    confd_pp_kpath(kp_buf, sizeof(kp_buf), kp);

    // just print change to standard output
    printf("%s: %s0\n", op_str, kp_buf);

    // here, we'd normally do whatever is necessary on change happening
    // in subscribed operational data, depending on op. type, new value, etc.
    switch (op) {
        case MOP_CREATED:
            // custom processing to be done as needed...
            break;

        case MOP_DELETED:
            // custom processing to be done as needed...
            break;

        case MOP_MODIFIED:
            // custom processing to be done as needed...
            break;

        case MOP_VALUE_SET: ;
            // custom processing to be done as needed...
            char oldv_buf[BUFSIZ];
            confd_pp_value(oldv_buf, sizeof(oldv_buf), newv);
            char newv_buf[BUFSIZ];
            confd_pp_value(newv_buf, sizeof(newv_buf), newv);
            printf("\toldv == %s; newv == %s\n", oldv_buf, newv_buf);
            break;

        default:
            /* We should never get MOP_MOVED_AFTER or MOP_ATTR_SET */
            printf("Unexpected op %d for %s\n", op, kp_buf);
            break;
    }

    return ITER_RECURSE;
}

int main(int argc, char **argv)
{
    int ret = CONFD_OK;

    const char *confd_addr = "127.0.0.1";
    const int confd_port = CONFD_PORT;

    struct sockaddr_in addr;
    addr.sin_addr.s_addr = inet_addr(confd_addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(confd_port);

    const char * app_name = argv[0];
    confd_init(app_name, stderr, CONFD_SILENT);


    struct sockaddr * addr_ptr = (struct sockaddr *)&addr;
    size_t addr_size = sizeof(struct sockaddr_in);

    ret = confd_load_schemas(addr_ptr, addr_size);
    if (CONFD_OK != ret) {
        confd_fatal("%s: Failed to load schemas from confd\n", argv[0]);
    }

    const char * sub_path = "/system/ip/route";

    // socket for subscription data iteration
    int data_sock = -1;
    if ((data_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        confd_fatal("%s: Failed to create socket", app_name);
    }

    ret = cdb_connect(data_sock, CDB_DATA_SOCKET, addr_ptr,addr_size);
    if (CONFD_OK != ret) {
        confd_fatal("%s: Failed to connect to ConfD", app_name);
    }

    // tailf:cdb-oper subscription socket
    int opsub_sock = -1;
    if ((opsub_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        confd_fatal("Failed to open socket\n");
    }

    ret = cdb_connect(opsub_sock, CDB_SUBSCRIPTION_SOCKET, addr_ptr,
                      addr_size);
    if (CONFD_OK != ret) {
        confd_fatal("Failed to cdb_connect() to confd \n");
    }

    // setup subscription socket
    int oper_sub_point = -1;
    ret = cdb_oper_subscribe(opsub_sock, routes__ns, &oper_sub_point,
                             sub_path);
    if (CONFD_OK != ret) {
        confd_fatal("Terminate: subscribe %d\n", ret);
    }

    ret = cdb_subscribe_done(opsub_sock);
    if (CONFD_OK != ret) {
        confd_fatal("cdb_subscribe_done() failed\n");
    }

    printf("entering poll loop\n");

    while (1) {
        struct pollfd set[1];
        set[0].fd = opsub_sock;
        set[0].events = POLLIN;
        set[0].revents = 0;

        if (poll(&set[0], sizeof(set)/sizeof(*set), -1) < 0) {
            if (errno != EINTR) {
                perror("Poll failed:");
                continue;
            }
        }

        if (!(set[0].revents & POLLIN)) {
            continue;
        }

        int sub_points[1];
        int reslen = 0;

        ret = cdb_read_subscription_socket(opsub_sock, &sub_points[0],
                                           &reslen);
        if (CONFD_OK != ret) {
            confd_fatal("terminate sub_read: %d\n", ret);
        }

        if (reslen > 0) {
            printf("CDB operational subscription point triggered\n");

            ret = cdb_start_session(data_sock, CDB_OPERATIONAL);
            if (CONFD_OK != ret) {
                confd_fatal("Cannot start session\n");
            }

            ret = cdb_set_namespace(data_sock, routes__ns);
            if (CONFD_OK != ret) {
                confd_fatal("Cannot set namespace\n");
            }

            cdb_diff_iterate(opsub_sock, sub_points[0], iterate_changes, 0,
                             NULL);
            cdb_end_session(data_sock);

        }

        ret = cdb_sync_subscription_socket(opsub_sock, CDB_DONE_OPERATIONAL);
        if (CONFD_OK != ret) {
            confd_fatal("failed to sync subscription: %d\n", ret);
        }
    }

    return 0;
}
