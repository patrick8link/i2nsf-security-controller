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

// get the bit-mask ConfD value from the input ConfD leaf-list

int cb_set_elem(
    struct confd_trans_ctx *tctx,
    confd_hkeypath_t *kp,
    confd_value_t *newval
) {
    TRACE_ENTER("");
    print_path("SET_ELEM() request keypath", kp);
    print_val("new value", newval);

    int ret = CONFD_OK;

    int sock = glob.maapi_socket;
    int th = tctx->thandle;

    int32_t ns_tag = CONFD_GET_XML_NS(&kp->v[0][0]);
    int32_t leaf_tag = CONFD_GET_XMLTAG(&kp->v[0][0]);
    int32_t list_tag = CONFD_GET_XML(&kp->v[2][0]);

    confd_value_t *username = &kp->v[kp->len-2][0];
    confd_value_t *folder_id = (folders_managed_folder == list_tag) ?
                                    &kp->v[1][0] : NULL;

    confd_value_t v_user_id;
    get_user_id_by_username(tctx, username, &v_user_id);

    confd_value_t v_storage_id;
    get_ll_storage_id(tctx, username, folder_id, &v_storage_id);

    TRACE("leaf tag == %s", confd_xmltag2str(ns_tag, leaf_tag));

    switch (leaf_tag) {
        case folders_auth_key:
            ret = set_ll_auth_type(tctx, &v_user_id, storage_at_key);
            if (CONFD_OK == ret) {
                ret = maapi_set_elem(sock, th, newval,
                                     USER_PATH "{%x}/auth-info/auth-key",
                                     &v_user_id);
            }
            break;

        case folders_auth_password:
            ret = set_ll_auth_type(tctx, &v_user_id, storage_at_password);
            if (CONFD_OK == ret) {
                ret = maapi_set_elem(sock, th, newval,
                           USER_PATH "{%x}/auth-info/password", &v_user_id);
            }
            break;

        default:
            WARN("Unsupported tag!");
            ret = CONFD_ERR;
    }

    confd_free_value(&v_storage_id);

    TRACE_EXIT("(%d)", ret);
    return ret;
}
