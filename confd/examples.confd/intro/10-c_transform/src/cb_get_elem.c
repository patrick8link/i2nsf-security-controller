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

#include <stdlib.h>

int cb_get_elem(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    TRACE_ENTER("");
    print_path("GET_ELEM() request keypath", kp);

    int ret = CONFD_OK;

    int sock = glob.maapi_socket;
    int th = tctx->thandle;

    confd_value_t v_result;
    CONFD_SET_NOEXISTS(&v_result);

    uint32_t leaf_tag = CONFD_GET_XMLTAG(&kp->v[0][0]);
    uint32_t list_tag = CONFD_GET_XMLTAG(&kp->v[2][0]);

    confd_value_t *username = &kp->v[kp->len-2][0];
    confd_value_t *folder_id = (folders_managed_folder == list_tag) ?
                                    &kp->v[1][0] : NULL;

    confd_value_t v_user_id;
    get_user_id_by_username(tctx, username, &v_user_id);

    confd_value_t v_storage_id;
    get_ll_storage_id(tctx, username, folder_id, &v_storage_id);

    switch (leaf_tag) {
        case folders_username:
            if (C_NOEXISTS != v_user_id.type) {
                // user with specific username actually does exists - as we got
                // his user_id in the previous step via storage-id retrieval
                confd_value_dup_to(username, &v_result);
            }
            break;

        case folders_auth_password:
            if (storage_at_password == get_ll_auth_type(tctx, &v_user_id)) {
                ret = maapi_get_elem(sock, th, &v_result,
                        USER_PATH "{%x}/auth-info/password", &v_user_id);
            }
            break;

        case folders_auth_key:
            if (storage_at_key == get_ll_auth_type(tctx, &v_user_id)) {
                ret = maapi_get_elem(sock, th, &v_result,
                        USER_PATH "{%x}/auth-info/auth-key", &v_user_id);
            }
            break;

        case folders_folder_id:
            if (C_NOEXISTS != v_storage_id.type
                    && maapi_exists(sock, th, STORAGE_PATH "{%x}",
                            &v_storage_id)
            ) {
                // existence verified in low level, return the val from keypath
                // - it saves the need to extract storage-id substring again...
                confd_value_dup_to(folder_id, &v_result);
            }
            break;

        default:
            TRACE("Unsupported tag! (%s)",
                    confd_xmltag2str(storage__ns, leaf_tag));
            ret = CONFD_ERR;
    }

    if (CONFD_OK == ret) {
        // if we got a value in one of previous steps, forward it to ConfD
        if (C_NOEXISTS != v_result.type) {
            confd_data_reply_value(tctx, &v_result);
        } else {
            // else respond "not-exists"
            confd_data_reply_not_found(tctx);
        }
    }

    confd_free_value(&v_storage_id);
    confd_free_value(&v_result);

    TRACE_EXIT("(%d)", ret);
    return ret;
}
