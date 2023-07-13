/*********************************************************************
 * ConfD DP API error formatting callback example
 *
 * This is ConfD Sample Code.
 *
 * (C) 2018 Tail-f Systems
 * Permission to use this code as a starting point hereby granted
 *
 * See the README file for more information
 ********************************************************************/

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <confd_lib.h>
#include <confd_dp.h>
#include <confd_errcode.h>

#include <traceh.h>

#include "error-formatting.h"

static int handled_error_types = CONFD_ERRTYPE_VALIDATION
                                 | CONFD_ERRTYPE_BAD_VALUE
                                 | CONFD_ERRTYPE_MISC;

// auxiliary printer functions
static char * printed_val(confd_value_t *val)
{
    static char buff[BUFSIZ];
    static const size_t buff_size = sizeof(buff);
    memset(buff, 0x00, buff_size);
    if (NULL != val) {
        confd_pp_value(buff, buff_size, val);
    }
    return buff;
}

static char * printed_path(confd_hkeypath_t *kp)
{
    static char buff[BUFSIZ];
    static const size_t buff_size = sizeof(buff);
    memset(buff, 0x00, buff_size);
    confd_pp_kpath(buff, buff_size, kp);
    return buff;
}

static char * printed_buffer(char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    static char buff[BUFSIZ];
    static const size_t buff_size = sizeof(buff);
    memset(buff, 0x00, buff_size);
    vsnprintf(buff, buff_size, fmt, args);
    va_end(args);

    return buff;
}

// expanded params allow usage for all of the "same" looking error structs
// that are named differently (CLI, BAD_VALUE, MISC)
static void trace_errinfo(
    int code,
    int n_params,
    struct confd_errinfo_param *params
) {
    TRACE("error code %d; params in total == %d", code, n_params);

    int i;
    for (i = 0; i < n_params; i++) {
        struct confd_errinfo_param *param = &params[i];

        char *output;
        if (CONFD_ERRINFO_KEYPATH == param->type) {
            output = printed_path(param->val.kp);
        } else if (CONFD_ERRINFO_STRING == param->type) {
            output = param->val.str;
        }
        TRACE("\tparam[%d] type == %d; value == %s", i, param->type, output);
    }
}

static void format_validat_err(
    struct confd_user_info *uinfo,
    struct confd_errinfo_validation *err_info,
    char *default_msg
) {
    int err_code = err_info->code;
    TRACE("VALIDATION error; code == %d", err_code);

    char *output = NULL;
    switch (err_code) {

        case CONFD_ERR_NOTSET:
            ;
            char *path_str = printed_path(err_info->info.notset.kp);
            output = printed_buffer("I definitely need: \"%s\"!", path_str);
            break;

        case CONFD_ERR_MUST_FAILED:
            ;
            confd_hkeypath_t *kp = err_info->info.must_failed.kp;
            TRACE("\tapp tag: %s", err_info->info.must_failed.error_app_tag);
            TRACE("\tmessage: %s", err_info->info.must_failed.error_message);
            TRACE("\t   expr: %s", err_info->info.must_failed.expr);
            TRACE("\tkeypath: %s", printed_path(kp));
            TRACE("\t  value: %s", printed_val(err_info->info.must_failed.val));

            // modify error only for indespensable-leaf's must statement
            unsigned int leaf_tag = CONFD_GET_XMLTAG(&kp->v[0][0]);
            if (error_formatting_indispensable_leaf == leaf_tag) {
                // get the name of affected list entry from keypath
                char *name = CONFD_GET_CBUFPTR(&kp->v[1][0]);
                output = printed_buffer("%s's MUST must NOT fail!", name);
                confd_error_seterr(uinfo, output);
            }
            break;

        default:
            TRACE("unimplemented VALIDATION error, use ConfD default...");
    }

    if (NULL != output) {
        confd_error_seterr(uinfo, output);
    }
}

static void format_bad_value_err(
    struct confd_user_info *uinfo,
    struct confd_errinfo_bad_value *err_info,
    char *default_msg
) {
    TRACE("BAD_VALUE error");
    trace_errinfo(err_info->code, err_info->n_params, err_info->params);

    // overload all/any BAD_VALUE errors - add custom prefix to default message
    char *output = printed_buffer("OOOPS! %s", default_msg);
    confd_error_seterr(uinfo, output);
}

static void format_misc_err(
    struct confd_user_info *uinfo,
    struct confd_errinfo_misc *err_info,
    char *default_msg
) {
    int err_code = err_info->code;
    TRACE("MISC error; code == %d", err_code);
    trace_errinfo(err_info->code, err_info->n_params, err_info->params);

    switch (err_code) {

        // overload the default "Error: application communication failure"
        case CONFD_MISC_EXTERNAL:
            ;
            char *output = printed_buffer("My data provider has problems!");
            confd_error_seterr(uinfo, output);
            break;

        default:
            TRACE("unimplemented MISC error, use ConfD default...");
    }
}

// main callback procedure invoked on error formatting request
static void custom_format_error(
    struct confd_user_info *uinfo,
    struct confd_errinfo *errinfo,
    char *default_msg
) {
    TRACE("default error msg == %s", default_msg);

    switch (errinfo->type) {

        case CONFD_ERRTYPE_VALIDATION:
            format_validat_err(uinfo, &errinfo->info.validation, default_msg);
            break;

        case CONFD_ERRTYPE_BAD_VALUE:
            format_bad_value_err(uinfo, &errinfo->info.bad_value, default_msg);
            break;

        case CONFD_ERRTYPE_MISC:
            format_misc_err(uinfo, &errinfo->info.misc, default_msg);
            break;

        default:
            TRACE("unimplemented error type (%d), use default ConfD message...",
                    errinfo->type);
    }
}

int register_error_callback(struct confd_daemon_ctx *dctx)
{
    struct confd_error_cb cbs_errors;
    cbs_errors.error_types = handled_error_types;
    cbs_errors.format_error = custom_format_error;

    int ret_code = confd_register_error_cb(dctx, &cbs_errors);
    if (CONFD_OK == ret_code) {
        printf("error formatting callback registered\n");
    }

    return ret_code;
};