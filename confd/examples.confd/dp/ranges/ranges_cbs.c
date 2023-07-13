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

#include <stdlib.h>
#include <string.h>

#include <confd_lib.h>
#include <confd_dp.h>

#include "ranges.h"

// identifiers to be printed to console when specific range callback is invoked
#define ID_R1_HANDLER "rAAA"
#define ID_R2_HANDLER "rBBB"
#define ID_DEF_HANDLER "rDEFAULT"

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
// used as a return value for a "payload" leaf with a "str" text included to
// show which registered range the value comes from...
static confd_value_t * temp_payload_val_ptr(char * str, uint32_t node_id) {
    static char buff[BUFSIZ];
    snprintf(buff, BUFSIZ, "%s-payload-%u", str, node_id);
    static confd_value_t val;
    CONFD_SET_CBUF(&val, buff, strnlen(buff, BUFSIZ));
    return &val;
}

// ---- first range handler ---------------------------------------------------
// for the sake of example, we have some dummy values to be returned
// one after another with each subsequent get-next invocation
static const int r1_data[] = {10, 20, 100};
static const int r1_data_cnt = (sizeof(r1_data) / sizeof(r1_data[0]));

static int get_next_r1(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp,
                       long next)
{
    printf("%s get_next(%ld)\n", ID_R1_HANDLER, next);

    // range specific implementation would be here;

    int index = next + 1;
    if (index < r1_data_cnt) {
        confd_value_t val;
        CONFD_SET_UINT32(&val, r1_data[index]);
        confd_data_reply_next_key(tctx, &val, 1, index);
    } else {
        confd_data_reply_next_key(tctx, NULL, -1, -1);
    }

    return CONFD_OK;
}

static int get_elem_r1(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    // range specific implementation would be here;

    uint32_t leaf_tag = CONFD_GET_XML(&kp->v[0][0]);
    uint32_t node_id = CONFD_GET_UINT32(&kp->v[1][0]);

    char * leaf_name_str = confd_xmltag2str(ranges__ns, leaf_tag);
    printf("%s get_elem(\"%s\", %d)\n", ID_R1_HANDLER, leaf_name_str, node_id);

    // verify request is for list entry this callbacks returns via get_next;
    // (that it's "existing" data, not northbound request for non-existing data)
    if (!is_int_in_array(node_id, r1_data, r1_data_cnt)) {
        printf("node-id does not exist in example data (%u)!\n", node_id);
        confd_data_reply_not_found(tctx);
        return CONFD_OK;
    }

    int ret_code = CONFD_OK;

    switch (leaf_tag) {
        case ranges_node_id:
            confd_data_reply_value(tctx, &kp->v[1][0]);
            break;

        case ranges_payload: ;
            // return customized string to show which callback it comes from...
            confd_value_t * vptr = temp_payload_val_ptr(ID_R1_HANDLER, node_id);
            confd_data_reply_value(tctx, vptr);
            break;

        default:
            confd_trans_seterr(tctx, "Unsupported leaf \"%u\"!", leaf_tag);
            ret_code = CONFD_ERR;
    }

    return ret_code;
}

// ---- second range handler --------------------------------------------------
// for the sake of example, we have some dummy values to be returned
// one after another with each subsequent get-next invocation
static const int r2_data[] = {110, 200};
static const int r2_data_cnt = (sizeof(r2_data) / sizeof(r2_data[0]));

static int get_next_r2(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp,
                       long next)
{
    printf("%s get_next(%ld)\n", ID_R2_HANDLER, next);

    // range specific implementation would be here;

    int index = next + 1;
    if (index < r2_data_cnt) {
        confd_value_t val;
        CONFD_SET_UINT32(&val, r2_data[index]);
        confd_data_reply_next_key(tctx, &val, 1, index);
    } else {
        confd_data_reply_next_key(tctx, NULL, -1, -1);
    }

    return CONFD_OK;
}

static int get_elem_r2(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    // range specific implementation would be here;

    uint32_t leaf_tag = CONFD_GET_XML(&kp->v[0][0]);
    uint32_t node_id = CONFD_GET_UINT32(&kp->v[1][0]);

    char * leaf_name_str = confd_xmltag2str(ranges__ns, leaf_tag);
    printf("%s get_elem(\"%s\", %d)\n", ID_R2_HANDLER, leaf_name_str, node_id);

    // verify request is for list entry this callbacks returns via get_next;
    // (that it's "existing" data, not northbound request for non-existing data)
    if (!is_int_in_array(node_id, r2_data, r2_data_cnt)) {
        printf("node-id does not exist in example data (%u)!\n", node_id);
        confd_data_reply_not_found(tctx);
        return CONFD_OK;
    }

    int ret_code = CONFD_OK;

    switch (leaf_tag) {
        case ranges_node_id:
            confd_data_reply_value(tctx, &kp->v[1][0]);
            break;

        case ranges_payload: ;
            // return customized string to show which callback it comes from...
            confd_value_t * vptr = temp_payload_val_ptr(ID_R2_HANDLER, node_id);
            confd_data_reply_value(tctx, vptr);
            break;

        default:
            confd_trans_seterr(tctx, "Unsupported leaf \"%u\"!", leaf_tag);
            ret_code = CONFD_ERR;
    }

    return ret_code;
}

// ---- "default" range handler -----------------------------------------------
static int get_next_default(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp,
                            long next)
{
    printf("%s get_next(%ld)\n", ID_DEF_HANDLER, next);

    // our example implementation has no other records except for the ones
    // covered by the other registered ranges!
    confd_data_reply_next_key(tctx, NULL, -1, -1);
    return CONFD_OK;
}

static int get_elem_default(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    uint32_t leaf_tag = CONFD_GET_XML(&kp->v[0][0]);
    uint32_t node_id = CONFD_GET_UINT32(&kp->v[1][0]);
    char * leaf_name_str = confd_xmltag2str(ranges__ns, leaf_tag);
    printf("%s get_elem(\"%s\", %d)\n", ID_DEF_HANDLER, leaf_name_str, node_id);

    // our example implementation has no other records except for the ones
    // covered by the other registered ranges!
    confd_data_reply_not_found(tctx);
    return CONFD_OK;
}

// ---- register all the ranges -----------------------------------------------
int register_all_callbacks(struct confd_daemon_ctx *dctx)
{
    int ret_code = CONFD_OK;

    // our list has single key of type uint32
    const char * cp_name = ranges__callpointid_int_callpoint;
    const char * cp_path = "/ranges/nodes";
    const int num_keys = 1;

    // we'll define each registered range using these two variables
    confd_value_t range_low;
    confd_value_t range_high;

    // first data callback/range
    struct confd_data_cbs cbs_range_one;
    memset(&cbs_range_one, 0x00, sizeof(cbs_range_one));
    cbs_range_one.get_elem = get_elem_r1;
    cbs_range_one.get_next = get_next_r1;
    strncpy(cbs_range_one.callpoint, cp_name, MAX_CALLPOINT_LEN);

    // register for key range "0" to "100"
    CONFD_SET_UINT32(&range_low, 0);
    CONFD_SET_UINT32(&range_high, 100);

    ret_code = confd_register_range_data_cb(dctx, &cbs_range_one,
                                            &range_low, &range_high, num_keys,
                                            cp_path);
    if (CONFD_OK != ret_code) {
        printf("Failed to register range \"%s\"!\n", ID_R1_HANDLER);
        goto term;
    }

    printf("range registered - %s\n", ID_R1_HANDLER);

    // second data callback/range
    struct confd_data_cbs cbs_range_two;
    memset(&cbs_range_two, 0x00, sizeof(cbs_range_two));
    cbs_range_two.get_elem = get_elem_r2;
    cbs_range_two.get_next = get_next_r2;
    strncpy(cbs_range_two.callpoint, cp_name, MAX_CALLPOINT_LEN);

    // register for key range "101" to "200"
    CONFD_SET_UINT32(&range_low, 101);
    CONFD_SET_UINT32(&range_high, 200);

    ret_code = confd_register_range_data_cb(dctx, &cbs_range_two,
                                            &range_low, &range_high, num_keys,
                                            cp_path);
    if (CONFD_OK != ret_code) {
        printf("Failed to register range \"%s\"!\n", ID_R2_HANDLER);
        goto term;
    }

    printf("range registered - %s\n", ID_R2_HANDLER);

    // default handler for other key values not covered by previous range
    // registrations
    struct confd_data_cbs default_cbs;
    memset(&default_cbs, 0x00, sizeof(default_cbs));
    default_cbs.get_elem = get_elem_default;
    default_cbs.get_next = get_next_default;
    strncpy(default_cbs.callpoint, cp_name, MAX_CALLPOINT_LEN);

    ret_code = confd_register_range_data_cb(dctx, &default_cbs,
                                            NULL, NULL, num_keys,
                                            cp_path);
    if (CONFD_OK != ret_code) {
        printf("Failed to register range \"%s\"!\n", ID_DEF_HANDLER);
        goto term;
    }

    printf("range registered - %s\n", ID_DEF_HANDLER);

term:
    return ret_code;
};