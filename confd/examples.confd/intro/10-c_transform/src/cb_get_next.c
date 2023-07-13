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
#include <string.h>

// Placeholder for data required by GET_NEXT() implementation.
// We need to keep track of one cursor per list traversal.
struct get_next_data {
    int traversal_id;
    struct maapi_cursor mc;
    struct get_next_data *next;
};

void cb_get_next_free_opaque_data(void * ptr)
{
    struct get_next_data *nd, *tmp;
    nd = (struct get_next_data *)ptr;
    while (nd) {
        maapi_destroy_cursor(&nd->mc);
        tmp = nd;
        nd = nd->next;
        free(tmp);
    }
}

// find get_next_data structure associated with the current next
static struct get_next_data *find_get_next_data(struct confd_trans_ctx *tctx)
{
    struct get_next_data *p = (struct get_next_data *)tctx->t_opaque;
    while (p) {
        if (p->traversal_id == tctx->traversal_id) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

// delete the get_next_data structure associated with the current next
static void del_get_next_data(struct confd_trans_ctx *tctx)
{
    struct get_next_data **prev = (struct get_next_data **)&tctx->t_opaque;
    struct get_next_data *p = (struct get_next_data *)tctx->t_opaque;
    while (p) {
        if (p->traversal_id == tctx->traversal_id) {
            maapi_destroy_cursor(&p->mc);
            *prev = p->next;
            free(p);
            return;
        }
        prev = &p->next;
        p = p->next;
    }
}


// initialize the maapi cursor for iterating the yang list
// get the cursor in progress from opaque data,
// or create/init a new one...
static int get_maapi_cursor(
    struct confd_trans_ctx *tctx,
    char * yangpath,
    struct maapi_cursor **out_mc
) {
    TRACE_ENTER("");

    struct get_next_data *nd = (struct get_next_data *)tctx->t_opaque;

    if (!(nd = find_get_next_data(tctx))) {
        TRACE("allocating new cursor...");
        nd = malloc(sizeof(struct get_next_data));
        OK(maapi_init_cursor(glob.maapi_socket, tctx->thandle, &nd->mc,
                "%s", yangpath));
        nd->traversal_id = tctx->traversal_id;
        nd->next = (struct get_next_data *)tctx->t_opaque;
        tctx->t_opaque = (void *)nd;
    } else {
        TRACE("going on with cursor in progress...");
    }

    *out_mc = &nd->mc;
    TRACE_EXIT("(cursor ptr == %p)", *out_mc);
    return CONFD_OK;
}

// retrieve next "/folder-user{}" record from the "/user-storage/user{}" list
static int get_next_user(
    struct confd_trans_ctx *tctx,
    long next,
    confd_value_t *output
) {
    TRACE_ENTER("");
    int ret = CONFD_OK;

    struct maapi_cursor * mc = NULL;
    ret = get_maapi_cursor(tctx, USER_PATH, &mc);
    if (CONFD_OK != ret) {
        TRACE("Failed to get MAAPI cursor!");
        goto term;
    }

    ret = maapi_get_next(mc);
    if (CONFD_OK != ret) {
        TRACE("Failed to get next record! (confd_errno == %d)", confd_errno);
        goto term;
    }
    ret = CONFD_OK;

    if (mc->n > 0) {
        int32_t user_id = CONFD_GET_INT32(&(mc->keys[0]));
        TRACE("get the username for user-id == %d", user_id);

        ret = maapi_get_elem(glob.maapi_socket, tctx->thandle, output,
                "%s{%d}/username", USER_PATH, user_id);
    } else {
        CONFD_SET_NOEXISTS(output);
    }

term:
    TRACE_EXIT("(%d)", ret);
    return ret;
}

int is_users_storage(
    confd_value_t *user_id,
    confd_value_t *storage_id
) {
    TRACE_ENTER("");

    int ret = 0;

    char *storage_str = CONFD_GET_CBUFPTR(storage_id);

    int32_t user_id_num = CONFD_GET_INT32(user_id);

    char user_str[TRANSFORM_BUFF_LEN];
    snprintf(user_str, TRANSFORM_BUFF_LEN, "%d", user_id_num);
    size_t user_str_len = strnlen(user_str, TRANSFORM_BUFF_LEN);

    ret = (
            (strncmp(storage_str, user_str, user_str_len) == 0)
            && storage_str[user_str_len] == '|'
    );

    TRACE_EXIT("(%d)", ret);
    return ret;
}

// retrieve next "/folder-user{}/managed-folder{}" record from the
// "/user-storage/ownership{}" list that belongs to specified user
static int get_next_folder(
    struct confd_trans_ctx *tctx,
    confd_hkeypath_t *kp,
    long next,
    confd_value_t *output
) {
    int ret = CONFD_OK;

    confd_value_t *username = &(kp->v[kp->len-2][0]);

    confd_value_t v_user_id;
    get_user_id_by_username(tctx, username, &v_user_id);

    struct maapi_cursor * mc = NULL;
    ret = get_maapi_cursor(tctx, OWNER_PATH, &mc);
    if (CONFD_OK != ret) {
        TRACE("Failed to get MAAPI cursor!");
        goto term;
    }

    if (-1 == next) {
        ret = maapi_find_next(mc, CONFD_FIND_NEXT, &v_user_id, 1);
    } else {
        ret = maapi_get_next(mc);
    }

    if (CONFD_OK != ret) {
        TRACE("Failed to get next record!");
        ret = CONFD_ERR;
    }

    CONFD_SET_NOEXISTS(output);

    if (mc->n > 0) {
        // second key of the "ownership" list is our storage name
        confd_value_t *storage_id = &mc->keys[1];
        if (is_users_storage(&v_user_id, storage_id)) {
            extract_folder_id(storage_id, output);
        }
    }

term:
    TRACE_EXIT("(%d)", ret);
    return ret;
}

static int get_next_content_type(
    struct confd_trans_ctx *tctx,
    confd_hkeypath_t *kp,
    long next,
    confd_value_t *output)
{
    static int content_enums[] = {folders_media,
                                  folders_document,
                                  folders_archive};
    static int enums_length =
        sizeof(content_enums) / sizeof(content_enums[0]);
    confd_value_t v_content_bits;
    int ret;
    if ((ret = get_content_bits(tctx, kp, &v_content_bits)) == CONFD_OK) {
        u_int32_t bits = CONFD_GET_BIT32(&v_content_bits);
        int i;
        for (i = 0; i < enums_length; i++) {
            CONFD_SET_ENUM_VALUE(output, content_enums[i]);
            if ((bits & content_type_bit(output)) != 0 &&
                next-- < 0) {
                return CONFD_OK;
            }
        }
        CONFD_SET_NOEXISTS(output);
        return CONFD_OK;
    }
    return ret;
}

int cb_get_next(
    struct confd_trans_ctx *tctx,
    confd_hkeypath_t *kp,
    long next
) {
    TRACE_ENTER("next == %ld", next);
    print_path("GET_NEXT() request keypath", kp);

    int ret = CONFD_OK;

    uint32_t list_tag = CONFD_GET_XMLTAG(&kp->v[0][0]);
    TRACE("get keys for: %s", confd_xmltag2str(storage__ns, list_tag));

    // our transformed model has only one key in any of the lists,
    // thus no array here, only 1 item...
    confd_value_t next_key;
    CONFD_SET_NOEXISTS(&next_key);

    // set specific cursor
    switch (list_tag) {

        case folders_folder_user:
            ret = get_next_user(tctx, next, &next_key);
            break;

        case folders_managed_folder:
            ret = get_next_folder(tctx, kp, next, &next_key);
            break;

        case folders_content_type:
            ret = get_next_content_type(tctx, kp, next, &next_key);
            break;

        default:
            TRACE("Unsupported list! (%d == %s)", list_tag,
                    confd_xmltag2str(folders__ns, list_tag));
    }

    if (CONFD_OK == ret) {
        if (C_NOEXISTS == next_key.type) {
            del_get_next_data(tctx);
            confd_data_reply_next_key(tctx, NULL, -1, -1);
        } else {
            confd_data_reply_next_key(tctx, &next_key, 1, next+1);
            confd_free_value(&next_key);
        }
    }

    TRACE_EXIT("(%d)", ret);
    return ret;
}
