/*********************************************************************
 * ConfD Stats server-side filtering example
 * Implements an operational data provider with simple filtering
 *
 * (C) 2019 Tail-f Systems
 * Permission to use this code as a starting point hereby granted
 *
 * See the README file for more information
 ********************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>

#include <confd_lib.h>
#include <confd_dp.h>
#include "arpe.h"

#if !defined(Linux) && !defined(__FreeBSD__) && !defined(Darwin)
#warning "arpstat: Not tested on this OS"
#endif

#define ARP_CMD "arp -an"

#if defined(Linux)
#define ARP_CMD_IP ARP_CMD
#else
#define ARP_CMD_IP "arp -n"
#endif


/********************************************************************/

/* Our daemon context as a global variable */
static struct confd_daemon_ctx *dctx;
static int ctlsock;
static int workersock;

/* ARP entries linked list */
struct aentry {
    struct in_addr ip4;
    char *hwaddr;
    int perm;
    int pub;
    char *iface;
    struct aentry *next;
};

enum filtertype {
    FILTER_NONE,
    FILTER_IF,
    FILTER_HOSTNAME,
    FILTER_HWADDR
};

/* simple filter descriptor */
struct arpfilter {
    int exact; /* is our filtering exact? */
    enum filtertype type;
    char value[BUFSIZ];
};

/* transaction state data */
struct arpdata {
    struct aentry *arp_entries;
    int traversal_id;
    struct aentry *curr; /* current ARP entry pointer */
    struct arpfilter arpfilter;
    struct confd_list_filter *filter;
};


/********************************************************************/

static void free_aentry(struct aentry *ae)
{
    if(ae->hwaddr) free(ae->hwaddr);
    if(ae->iface) free(ae->iface);
    free(ae);
}

static void free_arp(struct arpdata *dp)
{
    struct aentry *ae = dp->arp_entries;

    while (ae) {
        struct aentry *next = ae->next;
        free_aentry(ae);
        ae = next;
    }
    if (dp->filter != NULL) {
        confd_free_list_filter(dp->filter);
        dp->filter = NULL;
    }
    dp->arp_entries = NULL;
}

/* add an entry, keeping the list ordered */
static void add_aentry(struct aentry **first, struct aentry *new)
{
    struct aentry **prev = first;

    while (*prev != NULL &&
           (memcmp(&new->ip4, &(*prev)->ip4, sizeof(struct in_addr)) > 0 ||
            (memcmp(&new->ip4, &(*prev)->ip4, sizeof(struct in_addr)) == 0 &&
             strcmp(new->iface, (*prev)->iface) > 0))) {
        prev = &(*prev)->next;
    }
    new->next = *prev;
    *prev = new;
}

/* convert confd filter into arpfilter data */
static void retrieve_arp_filter(struct arpdata *dp,
                                struct confd_list_filter *filter)
{
    switch (filter->type) {
    case CONFD_LF_AND:
        /* in this example only one branch of the AND expression is
           evaluated and the result is reported as inexact to ConfD */
        retrieve_arp_filter(dp, filter->expr1);
        if (dp->arpfilter.type == FILTER_NONE) {
            retrieve_arp_filter(dp, filter->expr2);
        }
        dp->arpfilter.exact = 0;
        break;
    case CONFD_LF_CMP:
        if (filter->op == CONFD_CMP_EQ) {
            dp->arpfilter.exact = 1;
            confd_pp_value(dp->arpfilter.value, BUFSIZ, filter->val);
            switch (filter->node->tag) {
            case arpe_ifname:
                dp->arpfilter.type = FILTER_IF;
                break;
            case arpe_ip:
                dp->arpfilter.type = FILTER_HOSTNAME;
                break;
            case arpe_hwaddr:
                dp->arpfilter.type = FILTER_HWADDR;
                break;
            default:
                dp->arpfilter.type = FILTER_NONE;
                dp->arpfilter.exact = 0;
            }
        }
        break;
    default:
        /* no other filter types are handled */
        dp->arpfilter.type = FILTER_NONE;
    }
}

static void dump_filter_nodes(struct confd_list_filter *filter)
{
    int i;

    printf("[");
    for(i = 0; i < filter->nodelen; i++) {
        if (i > 0) {
            printf(", ");
        }
        printf("%s", confd_hash2str(filter->node[i].tag));
    }
    printf("]");
}

static char *filter_comp_op(enum confd_expr_op op)
{
    switch (op) {
    case CONFD_CMP_NOP:
        return "_";
        break;
    case CONFD_CMP_EQ:
        return "=";
        break;
    case CONFD_CMP_NEQ:
        return "!=";
        break;
    case CONFD_CMP_GT:
        return ">";
        break;
    case CONFD_CMP_GTE:
        return ">=";
        break;
    case CONFD_CMP_LT:
        return "<";
        break;
    case CONFD_CMP_LTE:
        return "<=";
        break;
    case CONFD_EXEC_STARTS_WITH:
        return "starts-with";
        break;
    case CONFD_EXEC_RE_MATCH:
        return "re-match";
        break;
    case CONFD_EXEC_DERIVED_FROM:
        return "derived-from";
        break;
    case CONFD_EXEC_DERIVED_FROM_OR_SELF:
        return "derived-from-or-self";
        break;
    default:
        return "";
    }
}

static void dump_filter(struct confd_list_filter *filter)
{
    char value[BUFSIZ];

    switch(filter->type) {
    case CONFD_LF_OR:
        printf("OR(");
        dump_filter(filter->expr1);
        printf(", ");
        dump_filter(filter->expr2);
        printf(")");
        break;
    case CONFD_LF_AND:
        printf("AND(");
        dump_filter(filter->expr1);
        printf(", ");
        dump_filter(filter->expr2);
        printf(")");
        break;
    case CONFD_LF_NOT:
        printf("NOT(");
        dump_filter(filter->expr1);
        printf(")");
        break;
    case CONFD_LF_CMP:
        dump_filter_nodes(filter);
        printf("%s", filter_comp_op(filter->op));
        confd_pp_value(value, BUFSIZ, filter->val);
        printf("%s", value);
        break;
    case CONFD_LF_EXISTS:
        printf("EXISTS(");
        dump_filter_nodes(filter);
        printf(")");
        break;
    case CONFD_LF_EXEC:
        printf("%s(", filter_comp_op(filter->op));
        confd_pp_value(value, BUFSIZ, filter->val);
        printf("%s", value);
        printf(")");
        break;
    }
}

/* Parse output fom arp -an for this transaction, use the filter.  The
 * filter can come in two forms: as hostname from get_elem handler, or
 * as a confd filter. */
static int run_arp(struct confd_trans_ctx *tctx,
                   struct arpdata *dp,
                   char *hostname)
{
    char *sep = " ?()<>\n";
    struct aentry *ae = NULL;
    FILE *fp;
    char buf[BUFSIZ];
    char command[BUFSIZ];

    strcpy(command, ARP_CMD);
    if (hostname == NULL &&
        confd_data_get_list_filter(tctx, &dp->filter) != CONFD_OK) {
        fprintf(stderr, "Failed to retrieve filters: %s (%d): %s\n",
                confd_strerror(confd_errno), confd_errno, confd_lasterr());
    }
    if (hostname != NULL || dp->filter != NULL) {
        /* some filtering needs to take place */
        if (hostname == NULL) {
            /* filter provided by confd - need to convert to a
             * descriptor */
            printf("\n");
            dump_filter(dp->filter);
            printf("\n");
            dp->arpfilter.type = FILTER_NONE;
            retrieve_arp_filter(dp, dp->filter);
        } else {
            /* filtering by hostname */
            dp->arpfilter = (struct arpfilter){.exact = 1,
                                               .type = FILTER_HOSTNAME};
            strncpy(dp->arpfilter.value, hostname, BUFSIZ);
        }
        switch (dp->arpfilter.type) {
        case FILTER_IF:
            if (snprintf(command, BUFSIZ,
                         ARP_CMD " -i %s",
                         dp->arpfilter.value) >= BUFSIZ) {
                fprintf(stderr, "command too long, truncated");
            }
            break;
        case FILTER_HOSTNAME:
            if (snprintf(command, BUFSIZ,
                         ARP_CMD_IP " %s",
                         dp->arpfilter.value) >= BUFSIZ) {
                fprintf(stderr, "command too long, truncated");
            }
            break;
        case FILTER_HWADDR:
            /* the arp command cannot filter by HW address, but it
             * still makes sense to do some "manual" filtering */
            strcpy(command, ARP_CMD);
            break;
        case FILTER_NONE:
            strcpy(command, ARP_CMD);
            break;
        }
    }
    printf("using command %s\n", command);
    if ((fp = popen(command, "r")) == NULL)
        return CONFD_ERR;
    while (fgets(&buf[0], BUFSIZ, fp) != NULL) {
        if (buf[0] != '?') {
            /* ignore messages from arp... */
            continue;
        }
        char *cp = strtok(&buf[0], sep);

        if ((ae = (struct aentry*) malloc(sizeof(struct aentry))) == NULL) {
            pclose(fp);
            return CONFD_ERR;
        }
        memset((void*)ae, 0, sizeof(struct aentry));

        /* Now lazy parse lines like */
        /* ? (192.168.1.1) at 00:0F:B5:EF:11:00 [ether] on eth0 */
        /* slightly different arp output on Linux and BSD */

        ae->ip4.s_addr = inet_addr(cp);
        /* skip "at" */
        assert(strcmp(strtok(NULL, sep), "at") == 0);
        cp = strtok(NULL, sep);

        if ((strcmp(cp, "incomplete") == 0)) {
            assert(strcmp(strtok(NULL, sep), "on") == 0);
            cp = strtok(NULL, sep);
        } else if ((strcmp(cp, "<from_interface>") == 0)) {
            cp = strtok(NULL, sep);
            while (cp) {
                if (strcmp(cp, "on") == 0) {
                    cp = strtok(NULL, sep);
                    break;
                }
                cp = strtok(NULL, sep);
            }
        } else {
            /* some common error cases handled, get real hw addr */
            ae->hwaddr = strdup(cp);

            while (1) {
                cp = strtok(NULL, sep);
                if (cp == NULL)
                    break;
                else if (strcmp(cp, "PERM") == 0)
                    ae->perm = 1;
                else if (strcmp(cp, "PUB") == 0)
                    ae->pub = 1;
                else if (strcmp(cp, "[ether]") == 0)
                    ;
                else if (strcmp(cp, "on") == 0) {
                    cp = strtok(NULL, sep);
                    break;
                }
            }
        }

        /* cp should now point to the interface name
           - this is required since it is a key */
        if (cp) {
            ae->iface = strdup(cp);

            /* Some OSes have perm/pub after interface name */
            while ((cp = strtok(NULL, sep)) != NULL) {
                if (strcmp(cp, "permanent") == 0)
                    ae->perm = 1;
                else if (strcmp(cp, "published") == 0)
                    ae->pub = 1;
            }

            /* now do the "soft" server-side filtering - this needs to
               be done only for HW address filtering */
            if (dp->arpfilter.type != FILTER_HWADDR
                || (ae->hwaddr != NULL
                    && strcmp(ae->hwaddr, dp->arpfilter.value) == 0)) {
                add_aentry(&dp->arp_entries, ae);
            }
        } else {
            /* skip this entry */
            free_aentry(ae);
        }
    }
    dp->traversal_id = tctx->traversal_id;
    dp->curr = dp->arp_entries;
    pclose(fp);
    return CONFD_OK;
}

/* Completely initialize transaction state data; if already populated,
 * deallocate. */
static int init_dp(struct confd_trans_ctx *tctx, char *hostname) {
    struct arpdata *dp;
    if ((dp = tctx->t_opaque) != NULL) {
        free_arp(dp);
        free(dp);
    }
    if ((dp = tctx->t_opaque = malloc(sizeof(struct arpdata))) == NULL) {
        fprintf(stderr, "Failed to allocate arpdata\n");
        return CONFD_ERR;
    }
    memset(dp, 0, sizeof(struct arpdata));
    if (run_arp(tctx, dp, hostname) != CONFD_OK) {
        return CONFD_ERR;
    }
    return CONFD_OK;
}

/********************************************************************/

static int s_init(struct confd_trans_ctx *tctx)
{
    confd_trans_set_fd(tctx, workersock);
    return CONFD_OK;
}

static int s_finish(struct confd_trans_ctx *tctx)
{
    struct arpdata *dp = tctx->t_opaque;

    if (dp != NULL) {
        free_arp(dp);
        free(dp);
    }
    return CONFD_OK;
}

/********************************************************************/

static int get_next(struct confd_trans_ctx *tctx,
                    confd_hkeypath_t *keypath,
                    long next)
{
    struct arpdata *dp = tctx->t_opaque;
    confd_value_t v[2];

    if (next == -1 ||
        dp == NULL ||
        dp->traversal_id != tctx->traversal_id ||
        dp->curr == NULL ||
        ((long) dp->curr->next) != next) {
        /* first call in a traversal */
        if (init_dp(tctx, NULL) != CONFD_OK) {
            return CONFD_ERR;
        }
        dp = tctx->t_opaque;
    } else {
        dp->curr = dp->curr->next;
    }
    if (dp->curr == NULL) {
        confd_data_reply_next_key(tctx, NULL, -1, -1);
        return CONFD_OK;
    }

    /* 2 keys */
    CONFD_SET_IPV4(&v[0], dp->curr->ip4);
    CONFD_SET_STR(&v[1], dp->curr->iface);
    char buf1[BUFSIZ], buf2[BUFSIZ];
    confd_pp_value(buf1, BUFSIZ, &v[0]);
    confd_pp_value(buf2, BUFSIZ, &v[1]);
    if (dp->arpfilter.exact) {
        tctx->cb_flags = CONFD_TRANS_CB_FLAG_FILTERED;
    }
    confd_data_reply_next_key(tctx, &v[0], 2, (long)dp->curr->next);
    return CONFD_OK;
}

/* Find the ARP entry that corresponds to the provided keypath.  In
 * simple traversals, ConfD calls get_next followed by get_elem on
 * leaves in the list instance - in such cases there is no need to
 * initialize state data again. */
static struct aentry *find_ae(struct confd_trans_ctx *tctx,
                              confd_hkeypath_t *keypath)
{
    struct in_addr ip = CONFD_GET_IPV4(&keypath->v[1][0]);
    char *iface = (char*)CONFD_GET_BUFPTR(&keypath->v[1][1]);
    struct arpdata *dp = tctx->t_opaque;
    struct aentry *ae = dp != NULL ? dp->curr : NULL;
    char hostname[BUFSIZ];

    if (ae != NULL &&
        ip.s_addr == ae->ip4.s_addr &&
        (strcmp(ae->iface, iface) == 0)) {
        /* current ARP entry is the one that ConfD asks for */
        return ae;
    } else {
        /* ConfD asks for an entry outside of a list traversal - we
         * need to initialize and require new ARP data; but since the
         * IP address or hostname is known, it can be used for
         * server-side filtering. */
        confd_pp_value(hostname, BUFSIZ, &keypath->v[1][0]);
        init_dp(tctx, hostname);
        dp = (struct arpdata*) tctx->t_opaque;
        ae = dp != NULL ? dp->arp_entries : NULL;
        while (ae != NULL) {
            if (ip.s_addr == ae->ip4.s_addr &&
                (strcmp(ae->iface, iface) == 0) ) {
                dp->curr = ae;
                return ae;
            }
            ae=ae->next;
        }
    }
    return NULL;
}

/* Keypath example */
/* /arpentries/arpe{192.168.1.1 eth0}/hwaddr */
/*    3         2         1             0    */

static int get_elem(struct confd_trans_ctx *tctx,
                    confd_hkeypath_t *keypath)
{
    confd_value_t v;

    struct aentry *ae = find_ae(tctx, keypath);
    if (ae == NULL) {
        confd_data_reply_not_found(tctx);
        return CONFD_OK;
    }
    switch (CONFD_GET_XMLTAG(&(keypath->v[0][0]))) {
    case arpe_hwaddr:
        if (ae->hwaddr == NULL) {
            confd_data_reply_not_found(tctx);
            return CONFD_OK;
        }
        CONFD_SET_STR(&v, ae->hwaddr);
        break;
    case arpe_permanent:
        CONFD_SET_BOOL(&v, ae->perm);
        break;
    case arpe_published:
        CONFD_SET_BOOL(&v, ae->pub);
        break;
    case arpe_ip:
        CONFD_SET_IPV4(&v, ae->ip4);
        break;
    case arpe_ifname:
        CONFD_SET_STR(&v, ae->iface);
        break;
    default:
        return CONFD_ERR;
    }
    confd_data_reply_value(tctx, &v);
    return CONFD_OK;
}

/********************************************************************/

int main(int argc, char *argv[])
{
    struct sockaddr_in addr;
    int debuglevel = CONFD_TRACE;
    struct confd_trans_cbs trans;
    struct confd_data_cbs data;

    memset(&trans, 0, sizeof (struct confd_trans_cbs));
    trans.init = s_init;
    trans.finish = s_finish;

    memset(&data, 0, sizeof (struct confd_data_cbs));
    data.get_elem = get_elem;
    data.get_next = get_next;
    data.flags = CONFD_DATA_WANT_FILTER;
    strcpy(data.callpoint, arpe__callpointid_arpe);

    /* initialize confd library */
    confd_init("arpe_daemon", stderr, debuglevel);

    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CONFD_PORT);

    if (confd_load_schemas((struct sockaddr*)&addr,
                           sizeof (struct sockaddr_in)) != CONFD_OK)
        confd_fatal("Failed to load schemas from confd\n");

    if ((dctx = confd_init_daemon("arpe_daemon")) == NULL)
        confd_fatal("Failed to initialize confdlib\n");

    /* Create the first control socket, all requests to */
    /* create new transactions arrive here */

    if ((ctlsock = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
        confd_fatal("Failed to open ctlsocket\n");
    if (confd_connect(dctx, ctlsock, CONTROL_SOCKET, (struct sockaddr*)&addr,
                      sizeof (struct sockaddr_in)) < 0)
        confd_fatal("Failed to confd_connect() to confd \n");

    /* Also establish a workersocket, this is the most simple */
    /* case where we have just one ctlsock and one workersock */

    if ((workersock = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
        confd_fatal("Failed to open workersocket\n");
    if (confd_connect(dctx, workersock, WORKER_SOCKET,(struct sockaddr*)&addr,
                      sizeof (struct sockaddr_in)) < 0)
        confd_fatal("Failed to confd_connect() to confd \n");

    if (confd_register_trans_cb(dctx, &trans) == CONFD_ERR)
        confd_fatal("Failed to register trans cb \n");

    if (confd_register_data_cb(dctx, &data) == CONFD_ERR)
        confd_fatal("Failed to register data cb \n");

    if (confd_register_done(dctx) != CONFD_OK)
        confd_fatal("Failed to complete registration \n");

    while(1) {
        struct pollfd set[2];
        int ret;

        set[0].fd = ctlsock;
        set[0].events = POLLIN;
        set[0].revents = 0;

        set[1].fd = workersock;
        set[1].events = POLLIN;
        set[1].revents = 0;

        if (poll(set, sizeof(set)/sizeof(*set), -1) < 0) {
            perror("Poll failed:");
            continue;
        }

        /* Check for I/O */
        if (set[0].revents & POLLIN) {
            if ((ret = confd_fd_ready(dctx, ctlsock)) == CONFD_EOF) {
                confd_fatal("Control socket closed\n");
            } else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
                confd_fatal("Error on control socket request: %s (%d): %s\n",
                     confd_strerror(confd_errno), confd_errno, confd_lasterr());
            }
        }
        if (set[1].revents & POLLIN) {
            if ((ret = confd_fd_ready(dctx, workersock)) == CONFD_EOF) {
                confd_fatal("Worker socket closed\n");
            } else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
                confd_fatal("Error on worker socket request: %s (%d): %s\n",
                     confd_strerror(confd_errno), confd_errno, confd_lasterr());
            }
        }
    }
}

/********************************************************************/
