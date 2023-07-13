/*********************************************************************
 * ConfD example - external authorization
 *
 * (C) 2018 Tail-f Systems
 * Permission to use this code as a starting point hereby granted
 * This is ConfD Sample Code.
 *
 * See the README file for more information
 ********************************************************************/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <confd_lib.h>
#include <confd_dp.h>

#define _TRACE_DECLARE
#include <traceh.h>
#include "datamodel.h"

static const char* CONFD_ADDR = "127.0.0.1";
static const char* EXAMPLE_APP_NAME = "app_example";

static struct confd_daemon_ctx *dctx;
static int ctlsock;

/* Logging support */
static void trace_confd_val(const char *txt, const confd_value_t *val)
{
#ifdef T_LOG_TRACE
    char buf[512];
    confd_pp_value(buf, sizeof(buf), val);
    TRACE("%s%s type=%d", txt, buf, val->type);
#endif
}

static void trace_confd_kp(const char *txt, confd_hkeypath_t *kp)
{
#ifdef T_LOG_TRACE
    if (kp) {
        char buf[1024];
        confd_pp_kpath(buf, sizeof(buf), kp);
        TRACE("%s%s", txt, buf);
    } else {
        TRACE("%s%p", txt, kp);
    }
#endif
}

enum users {
    admin,
    oper,
    public,
    private,

    none // when cannot be found
};

enum users get_user_by_name(const char* username)
{
    TRACE_ENTER("username=%s", username);
    enum users rv = none;

    if (!strcmp("admin", username)) {
        rv = admin;
    } else if (!strcmp("oper", username)) {
        rv = oper;
    } else if (!strcmp("public", username)) {
        rv = public;
    } else if (!strcmp("private", username)) {
        rv = private;
    }

    TRACE_EXIT("rv %i", rv);
    return rv;
}

static int cmd_access_cb(struct confd_authorization_ctx *actx,
                         char **cmdtokens, int ntokens, int cmdop)
{
    TRACE_ENTER("cmdop=%d ntokens=%d", cmdop, ntokens);
    int rv = CONFD_OK;
    char* username = actx->uinfo->username;
    TRACE("username=%s", username);
    int user = get_user_by_name(username);
    int result = CONFD_ACCESS_RESULT_DEFAULT;
#ifdef T_LOG_TRACE
    if (ntokens && cmdtokens != NULL) {
        int i;
        for (i = 0; i < ntokens; ++i) {
            TRACE("cmdtokens[%d]=%s", i, cmdtokens[i]);
        }
    }
#endif

    switch (user) {
    case admin:
        break;
    case oper:
        if (ntokens && cmdtokens != NULL) {
            if (!strcmp("id", cmdtokens[0])) {
                TRACE("Forbidding 'id' for %s user", username);
                result = CONFD_ACCESS_RESULT_REJECT;
            }
        }
        break;
    case public:
        if (ntokens && cmdtokens != NULL) {
            if (!strcmp("config", cmdtokens[0])) {
                TRACE("Forbidding 'config' for %s user", username);
                result = CONFD_ACCESS_RESULT_REJECT;
            }
        }
        if (ntokens >= 3 && !strcmp("show", cmdtokens[0])
            && !strcmp("running-config", cmdtokens[1])
            && !strcmp("example-config", cmdtokens[2])
            ) {
            // this still allows to invoke 'show running-config` (need to solve
            // it in data callback)
            TRACE("Forbidding 'show running-config example-config' for %s user",
                  username);
            result = CONFD_ACCESS_RESULT_REJECT;
        }
        break;
    case private:
        if (ntokens && cmdtokens != NULL) {
            if (!strcmp("commit", cmdtokens[0])) {
                TRACE("Forbidding 'commit' for %s user", username);
                result = CONFD_ACCESS_RESULT_REJECT;
                break;
            }
            if (!strcmp("no", cmdtokens[0])) {
                TRACE("Forbidding 'no' for %s user", username);
                result = CONFD_ACCESS_RESULT_REJECT;
            }
            int do_shift = 0;
            if (!strcmp("do", cmdtokens[0])) {
                do_shift++;
            }
            if (ntokens >= (2 + do_shift)
                && !strcmp("show", cmdtokens[0 + do_shift])
                && !strcmp("example-state", cmdtokens[1 + do_shift])) {
                TRACE("Forbidding 'show example-state' for %s user", username);
                result = CONFD_ACCESS_RESULT_REJECT;
            }
        }
        break;
    default:
        WARN("Cannot map user with enum %d", user);
        break;
    }

    TRACE("result=%d", result);
    confd_access_reply_result(actx, result);

    TRACE_EXIT("rv %i", rv);
    return rv;
}

static int data_access_cb(struct confd_authorization_ctx *actx,
                          u_int32_t hashed_ns, confd_hkeypath_t *kp,
                          int dataop, int how)
{
    TRACE_ENTER("hashed_ns=%d dataop=%d how=%d kp->len=%d", hashed_ns, dataop,
                how, kp->len);
    trace_confd_kp("kp=", kp);
    int rv = CONFD_OK;
    char* username = actx->uinfo->username;
    TRACE("username=%s", username);
    int user = get_user_by_name(username);
    int result = CONFD_ACCESS_RESULT_CONTINUE;
    confd_value_t* val;
    const char *SECRET = "secret";
    const char *IMPORTANT = "important";

    switch (user) {
    case admin:
        break;
    case oper:
        if (kp->len == 3) {
            if (kp->v[1]->type == C_XMLTAG &&
                kp->v[1]->val.xmltag.tag == datamodel_items) {
                TRACE("item is modified for %s user", username);
                val = kp->v[0];
                trace_confd_val("kp->v[0]=", val);
                if (val->type == C_BUF) {
                    TRACE("C_BUF found");
                    char *item = CONFD_GET_CBUFPTR(val);
                    TRACE("item=%s", item);
                    if (dataop == CONFD_ACCESS_OP_CREATE) {
                        //configure/create without commit
                        TRACE("Item is configured.");
                        if (strncmp(SECRET, item, strlen(SECRET)) == 0) {
                            TRACE("Configured item starts with '%s'!", SECRET);
                            result = CONFD_ACCESS_RESULT_REJECT;
                        }
                    } else if (dataop == CONFD_ACCESS_OP_DELETE) { // delete
                        TRACE("Item is deleted.");
                        if (strncmp(IMPORTANT, item, strlen(IMPORTANT)) == 0) {
                            TRACE("Deleted item starts with '%s'!", IMPORTANT);
                            result = CONFD_ACCESS_RESULT_REJECT;
                        }
                    }
                }
            }
        }
        break;
    case public:
        val = kp->v[kp->len-1];
        trace_confd_val("kp->v[kp->len-1]=", val);
        if (val->type == C_XMLTAG && val->val.xmltag.tag
            == datamodel_example_config) {
            TRACE("Forbidding '/example-config' for %s user", username);
            result = CONFD_ACCESS_RESULT_REJECT;
        }

        break;
    case private:
        break;
    default:
        WARN("Cannot map user with enum %d", user);
        break;
    }

    TRACE("result=%d", result);
    confd_access_reply_result(actx, result);

    TRACE_EXIT("rv %i", rv);
    return rv;
}

/* Application */
int init_confd_daemon(void)
{
    INFO_ENTER("");
    int rv = CONFD_ERR;
    struct sockaddr_in addr;
    int debuglevel = CONFD_DEBUG;

    /* initialize confd library */
    confd_init(EXAMPLE_APP_NAME, stderr, debuglevel);

    addr.sin_addr.s_addr = inet_addr(CONFD_ADDR);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CONFD_PORT);

    if (CONFD_OK
        != confd_load_schemas((struct sockaddr*) &addr,
                              sizeof(struct sockaddr_in))) {
        FATAL("Failed to load schemas from confd!");
        goto term;
    }

    if (NULL == (dctx = confd_init_daemon(EXAMPLE_APP_NAME))) {
        FATAL("Failed to initialize confdlib!");
        goto term;
    }

    /* Create the first control socket, all requests to */
    /* create new transactions arrive here */

    if (0 > (ctlsock = socket(PF_INET, SOCK_STREAM, 0))) {
        FATAL("Failed to open ctlsock!");
        goto term;
    }
    if (0 > confd_connect(dctx, ctlsock, CONTROL_SOCKET,
                          (struct sockaddr*) &addr,
                          sizeof(struct sockaddr_in))) {
        FATAL("Failed to confd_connect() ctlsock to confd!");
        goto term;
    }

    struct confd_authorization_cbs auth;
    memset(&auth, 0, sizeof(struct confd_authorization_cbs));
    auth.chk_cmd_access = cmd_access_cb;
    auth.chk_data_access = data_access_cb;
    // filters specify for what not to use callbacks
    // (0x0 ... use for everything, 0xFF ... use for nothing/disable)
    auth.cmd_filter = CONFD_ACCESS_OP_READ;
    auth.data_filter = 0x0;
    if (CONFD_OK != confd_register_authorization_cb(dctx, &auth)) {
        FATAL("Failed to register auth cb!");
    }

    if (CONFD_OK != confd_register_done(dctx)) {
        FATAL("Failed to complete registration!");
        goto term;
    }

    rv = CONFD_OK;
term:
    INFO_EXIT("Initialization complete rv=%i", rv);
    return rv;
}

int confd_loop(void)
{
    INFO_ENTER("");
    int rv = CONFD_ERR;

    while (1) {
        struct pollfd set[1];
        int ret;

        set[0].fd = ctlsock;
        set[0].events = POLLIN;
        set[0].revents = 0;

        if (poll(set, sizeof(set) / sizeof(*set), -1) < 0) {
            perror("Poll failed:");
            continue;
        }

        /* Check for I/O */
        if (set[0].revents & POLLIN) {
            if ((ret = confd_fd_ready(dctx, ctlsock)) == CONFD_EOF) {
                FATAL("Control socket closed!");
                goto term;
            } else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
                FATAL("Error on control socket request: %s (%d): %s",
                      confd_strerror(confd_errno), confd_errno,
                      confd_lasterr());
                goto term;
            }
        }
    }

term:
    INFO_EXIT("rv %i", rv);
    return rv;
}

int main(int argc, char *argv[])
{
    INFO_ENTER("");
    int rv = CONFD_ERR;

    if (CONFD_OK != (rv = init_confd_daemon())) {
        FATAL("Failed to initialize confd! Exiting");
    } else {
        rv = confd_loop();
    }

    INFO_EXIT("rv=%i", rv);
    return rv;
}
