/*********************************************************************
 * ConfD DP API callback range registration example - "eth" data provider
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

#include "ranges-multi.h"

// identifiers to be printed to console when specific range callback is invoked
#define ID_DAEMON_NAME "Eth-App"
#define ID_RANGE_ETH "ETH"

// check whether specific number is present the array
static int is_int_in_array(const int number, const int * array,
                           const int array_len)
{
    int i;
    for (i = 0; i < array_len; i++) {
        if (number == array[i]) {
            return 1;
        }
    }
    return 0;
}

// return temporary pointer to a confd_value_t filled with customized string;
// used as a return value for a "payload" leaf with a customized text to show
// which registered range the value comes from
static confd_value_t * temp_payload_val_ptr(
    char * daemon, char * range,
    uint32_t enum_value, uint32_t node_id
) {
    static char buff[BUFSIZ];
    snprintf(buff, BUFSIZ, "%s-%s-payload-%u-%u", daemon, range,
             enum_value, node_id);
    static confd_value_t val;
    CONFD_SET_CBUF(&val, buff, strnlen(buff, BUFSIZ));
    return &val;
}

// ---- "eth" range handler ---------------------------------------------------
// for the sake of example, we have some dummy values to be returned
// one after another with each subsequent get-next invocation
static const int eth_node_ids[] = {0, 1, 3, 7};
static const int eth_node_cnt = (sizeof(eth_node_ids)/sizeof(eth_node_ids[0]));

static int get_next_eth(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp,
                       long next)
{
    printf("%s| %s get_next(%ld)\n", ID_DAEMON_NAME, ID_RANGE_ETH, next);

    // range specific implementation would be here; we return some dummy data

    int index = next + 1;
    if (index < eth_node_cnt) {
        // list has two keys - "ethernet" enum + node id integer
        confd_value_t keys[2];
        CONFD_SET_ENUM_HASH(&keys[0], ranges_multi_ethernet);
        CONFD_SET_UINT32(&keys[1], eth_node_ids[index]);
        confd_data_reply_next_key(tctx, keys, 2, index);
    } else {
        confd_data_reply_next_key(tctx, NULL, -1, -1);
    }

    return CONFD_OK;
}

static int get_elem_eth(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    // range specific implementation would be here;
    // for a "payload" leaf, we just return customized string to show which
    // callback it comes from...
    uint32_t leaf_tag = CONFD_GET_XML(&kp->v[0][0]);
    uint32_t node_type = CONFD_GET_ENUM_VALUE(&kp->v[1][0]);
    uint32_t node_id = CONFD_GET_UINT32(&kp->v[1][1]);

    char * leaf_name_str = confd_xmltag2str(ranges_multi__ns, leaf_tag);
    printf("%s| %s get_elem(\"%s\", %u, %u)\n", ID_DAEMON_NAME, ID_RANGE_ETH,
           leaf_name_str, node_type, node_id);

    // verify request is for list entry this callbacks returns via get_next;
    // (that it's "existing" data, not northbound request for non-existing data)
    if (!is_int_in_array(node_id, eth_node_ids, eth_node_cnt)) {
        printf("%s| node-id does not exist in example data!\n", ID_DAEMON_NAME);
        confd_data_reply_not_found(tctx);
        return CONFD_OK;
    }

    int ret_code = CONFD_OK;

    switch (leaf_tag) {
        case ranges_multi_node_type:
            confd_data_reply_value(tctx, &kp->v[1][0]);
            break;

        case ranges_multi_node_id:
            confd_data_reply_value(tctx, &kp->v[1][1]);
            break;

        case ranges_multi_payload: ;
            confd_value_t * vptr = temp_payload_val_ptr(ID_DAEMON_NAME,
                                        ID_RANGE_ETH, node_type, node_id);
            confd_data_reply_value(tctx, vptr);
            break;

        default:
            confd_trans_seterr(tctx, "Unsupported leaf \"%u\"!", leaf_tag);
            ret_code = CONFD_ERR;
    }

    return ret_code;
}

// ---- register all the ranges -----------------------------------------------
int register_all_callbacks(struct confd_daemon_ctx *dctx)
{
    int ret_code = CONFD_OK;

    const char * cp_name = ranges_multi__callpointid_enum_callpoint;
    const char * cp_path = "/ranges-multi/nodes";

    struct confd_data_cbs eth_data_cbs;
    memset(&eth_data_cbs, 0x00, sizeof(eth_data_cbs));
    eth_data_cbs.get_elem = get_elem_eth;
    eth_data_cbs.get_next = get_next_eth;
    strncpy(eth_data_cbs.callpoint, cp_name, MAX_CALLPOINT_LEN);

    // our list has two keys, enumeration node-type and uint32 node-id
    // register for key "ethernet" only, do not define any "node-id" range
    confd_value_t range_low;
    confd_value_t range_high;

    CONFD_SET_ENUM_VALUE(&range_low, ranges_multi_ethernet);
    CONFD_SET_ENUM_VALUE(&range_high, ranges_multi_ethernet);

    ret_code = confd_register_range_data_cb(dctx, &eth_data_cbs,
                                            &range_low, &range_high, 1,
                                            cp_path);
    if (CONFD_OK != ret_code) {
        printf("%s| failed to register range \"%s\"!\n", ID_DAEMON_NAME,
               ID_RANGE_ETH);
        goto term;
    }

    printf("%s| range registered - %s\n", ID_DAEMON_NAME, ID_RANGE_ETH);

term:
    return ret_code;
};

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
    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);

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

    printf("%s| entering poll loop\n", ID_DAEMON_NAME);

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