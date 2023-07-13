/*********************************************************************
 * ConfD Transformation callpoint example
 *
 * This is ConfD Sample Code.
 *
 * (C) 2017 Tail-f Systems
 * Permission to use this code as a starting point hereby granted
 *
 * See the README file for more information
 ********************************************************************/

#include "cb_common.h"

// check if the content-type is present
static int check_folder_content_type(struct confd_trans_ctx *tctx,
                                     confd_hkeypath_t *kp)
{
    TRACE_ENTER("");

    int exists = 0;
    confd_value_t v_content_bits;
    if (get_content_bits(tctx, kp, &v_content_bits) == CONFD_OK) {
        exists = (CONFD_GET_BIT32(&v_content_bits) &
                  content_type_bit(&kp->v[0][0])) != 0;
    }

    TRACE_EXIT("(%d)", exists);
    return exists;
}

int cb_exists_optional(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    TRACE_ENTER("");
    print_path("EXISTS_OPTIONAL() request keypath", kp);

    int ret = CONFD_OK;

    int does_exist = 0;

    confd_value_t *username = &kp->v[kp->len-2][0];
    confd_value_t v_user_id;

    if (kp->v[0][0].type == C_XMLTAG &&
        CONFD_GET_XMLTAG(&kp->v[0][0]) == folders_auth_none) {
        get_user_id_by_username(tctx, username, &v_user_id);
        does_exist = (storage_at_none == get_ll_auth_type(tctx, &v_user_id));
    } else if (kp->v[1][0].type == C_XMLTAG &&
               CONFD_GET_XMLTAG(&kp->v[1][0]) == folders_content_type) {
        does_exist = check_folder_content_type(tctx, kp);
    } else {
        TRACE("Unsupported path!");
    }

    TRACE("does exist == %d", does_exist);
    if (does_exist) {
        confd_data_reply_found(tctx);
    } else {
        confd_data_reply_not_found(tctx);
    }

    TRACE_EXIT("(%d)", ret);
    return ret;
}
