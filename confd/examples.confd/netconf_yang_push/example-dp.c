#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stddef.h>

#include <confd_lib.h>
#include <confd_dp.h>

#include <time.h>
#include <sys/time.h>

#include "ietf-interfaces.h"
#include "iana-if-type.h"

char *progname = NULL;
int debuglevel = CONFD_SILENT;
int ctlsock    = -1;
int workersock = -1;

int opt_get_object       = 0;
int opt_get_next_object  = 0;
int opt_bulk_only        = 0;
int opt_foreground       = 0;
int opt_load_schemas     = 1;
int opt_accumulate       = 1;
int opt_leaf_list_leaf   = 0;
int opt_use_clist        = 0;
int opt_find_next        = 0;
int opt_find_next_object = 0;
int opt_reconnect        = 0;
int opt_honor_filter     = 1;
int opt_yang_push        = 0;

int daemon_flags = 0;

/* start YANG-Push example vaiables*/
int oper_status = 7;
int enabled = 0;
/* end YANG-Push example vaiables*/

struct cb_def {
    int idx;
    char *name;
};

#define CB_EXISTS_OPTIONAL 0
#define CB_GET_ELEM 1
#define CB_GET_NEXT 2
#define CB_GET_CASE 3
#define CB_GET_OBJECT 4
#define CB_GET_NEXT_OBJECT 5
#define CB_GET_NEXT_OBJECTS 6
#define CB_NUM_INSTANCES 7
#define CB_SET_ELEM 8
#define CB_CREATE 9
#define CB_REMOVE 10
#define CB_SET_CASE 11
#define CB_MOVE_AFTER 12
#define CB_GET_ATTRS 13
#define CB_SET_ATTR 14
#define CB_FIND_NEXT 15
#define CB_FIND_NEXT_OBJECT 16
#define CB_FIND_NEXT_OBJECTS 17


#define N_CB 18

static const char* cb_names[] = {
    "exists_optional",
    "get_elem",
    "get_next",
    "get_case",
    "get_object",
    "get_next_object",
    "get_next_objects",
    "num_instances",
    "set_elem",
    "create",
    "remove",
    "set_case",
    "move_after",
    "get_attrs",
    "set_attr",
    "find_next",
    "find_next_object",
    "find_next_objects"
};

struct cb_stat {
    char *callpoint;
    u_int32_t cb_counters[N_CB];
};
static char *callpoints[255];
static struct cb_stat *cb_stat;
static int n_cb_stat = 0;

static struct confd_push_on_change_ctx *push_ctx;

/* ------------------------------------------------------------------------ */

/* Incomplete cmp function in that it doesn't handle all types, nor
 * does it handle snmp sort-order. Also different integer types should
 * be coerced and compared as integers.
 */
int confd_val_cmp_strict(confd_value_t *v1, confd_value_t *v2)
{
    if (v1->type < v2->type) return -1;
    if (v1->type > v2->type) return 1;
    switch (v1->type) {
#define CMP(E) (v1->val.E < v2->val.E) ? -1 : !(v1->val.E == v2->val.E)
    case C_INT8:
        return CMP(i8);
    case C_INT16:
        return CMP(i16);
    case C_INT32:
        return CMP(i32);
    case C_INT64:
        return CMP(i64);
    case C_UINT8:
        return CMP(u8);
    case C_UINT16:
        return CMP(u16);
    case C_UINT32:
        return CMP(u32);
    case C_UINT64:
        return CMP(u64);
    case C_DOUBLE:
        return CMP(d);
    case C_DECIMAL64:
        return CMP(d64.value);
    case C_ENUM_HASH:
        return CMP(enumhash);
    case C_BOOL:
        return CMP(boolean);
    case C_IPV4:
    {
        u_int32_t ip1 = ntohl(v1->val.ip.s_addr);
        u_int32_t ip2 = ntohl(v2->val.ip.s_addr);
        return (ip1 < ip2) ? -1 : !(ip1 == ip2);
    }
#undef CMP
    case C_STR:
        return strcmp(v1->val.s, v2->val.s);
    case C_BUF:
    case C_BINARY:
    {
        int v1len = v1->val.buf.size;
        int v2len = v2->val.buf.size;
        int len = (v1len < v2len) ? v1len : v2len;
        int c = memcmp((char *)v1->val.buf.ptr,
                        (char *)v2->val.buf.ptr, len);
        if (c == 0) {
            return (v1len < v2len) ? -1 : !(v1len == v2len);
        }
        return c;
    }
    case C_NOEXISTS:
    case C_DEFAULT:
        return 0;
    case C_XMLTAG:
    case C_XMLBEGIN:
    case C_XMLEND:
        if (v1->val.xmltag.ns < v2->val.xmltag.ns) return -1;
        if (v1->val.xmltag.ns > v2->val.xmltag.ns) return 1;
        return (v1->val.xmltag.tag < v2->val.xmltag.tag) ?
            -1 : !(v1->val.xmltag.tag == v2->val.xmltag.tag);
    case C_MAXTYPE:     /* enum end marker */
        return 0;
    default:
        fprintf(stderr, "unhandled type in %s: %d\n", __FUNCTION__, v1->type);
        assert(0);
    }
    return 0;
}

typedef struct choice_node {
    struct confd_cs_choice *csc;
    struct confd_cs_case   *set;
    struct choice_node     *next;
    /* actual size of path (min 2) determined at creation */
    confd_value_t          path[1];
} choice_node_t;


struct attr {
    u_int32_t     attr;
    confd_value_t *val;
    struct attr   *next;
};

typedef struct node {
    struct confd_cs_node *cs;
    union {
        confd_value_t    *val;
        struct node      *key;
        struct node      **keys;
    } u;
    struct node          *next;
    struct node          *prev;
    struct attr          *attrs;
    choice_node_t        *choices;
    struct node          *children;
    u_int32_t            nchildren;
} node_t;

/* kept in tctx->t_opaque; one allocated per active get-next traversal
   (there can only be one per list) */
struct next_data {
    int traversal_id;
    int kc;
    struct confd_list_filter *f;
    node_t *listnode;
    struct next_data *next;
};

static node_t root;

static int do_pre_create_leaf_lists;

/* return 1 for leaf-list treated as list, otherwise 0 */
static inline int is_leaf_list(struct confd_cs_node *cs)
{
    return !opt_leaf_list_leaf && (cs->info.flags & CS_NODE_IS_LEAF_LIST);
}

static inline int container_is_p(struct confd_cs_node *cs) {
    return cs->info.minOccurs == 0;
}

static inline int container_is_np(struct confd_cs_node *cs) {
    return cs->info.minOccurs == 1;
}

static inline int keycount(struct confd_cs_node *cs)
{
    int c;
    u_int32_t *kt = cs->info.keys;
    if (kt == NULL) {
        if (is_leaf_list(cs))
            return 1;
        else
            return 0;
    }
    for (c=0; *kt; kt++, c++) ;
    //fprintf(stderr, "nkeys(%s)=%d\n", confd_hash2str(cs->tag), c);
    return c;
}

static node_t *new_node(struct confd_cs_node *cs)
{
    node_t *n = (node_t *)malloc(sizeof(node_t));
    assert(n);
    memset(n, 0, sizeof(node_t));
    n->cs = cs;
    //fprintf(stderr, "new_node(%d:%d) -> %p\n", cs->ns, cs->tag, n);
    return n;
}

static choice_node_t *new_choice_node(struct confd_cs_choice *csc,
                                      confd_value_t *path, int path_len)
{
    int sz = sizeof(choice_node_t) + path_len * sizeof(confd_value_t);
    choice_node_t *n = (choice_node_t *)malloc(sz);
    assert(n);
    memset(n, 0, sz);
    n->csc = csc;
    n->set = csc->default_case;
    memcpy(&n->path, path, (path_len + 1) * sizeof(confd_value_t));
    return n;
}

/* return # of actual path elements,
   i.e. excluding terminating C_NOEXISTS */
static int choice_path_len(confd_value_t *choice)
{
    int i = 0;
    while (choice[i].type != C_NOEXISTS)
        i++;
    return i;
}

static int choice_path_eq(confd_value_t *choice1, confd_value_t *choice2)
{
    int i = 0;
    while (choice1[i].type != C_NOEXISTS && choice2[i].type != C_NOEXISTS) {
        if (CONFD_GET_XMLTAG(&choice1[i]) != CONFD_GET_XMLTAG(&choice2[i]))
            return 0;
        if (CONFD_GET_XMLTAG_NS(&choice1[i]) !=
            CONFD_GET_XMLTAG_NS(&choice2[i]))
            return 0;
        i++;
    }
    /* paths are equal if both i'th elems are C_NOEXISTS */
    return choice1[i].type == choice2[i].type;
}

static struct confd_cs_choice *find_cs_choice(struct confd_cs_node *cs,
                                              confd_value_t *choice,
                                              int path_len)
{
    static struct confd_cs_choice *choices, *ch;
    static struct confd_cs_case *ca;
    u_int32_t tag, ns;
    int i = path_len - 1;

    choices = cs->info.choices;
    while (i >= 0) {
        tag = CONFD_GET_XMLTAG(&choice[i]);
        ns = CONFD_GET_XMLTAG_NS(&choice[i]);
        for (ch = choices; ch; ch = ch->next) {
            if ((ch->ns == ns) && (ch->tag == tag)) {
                break;
            }
        }
        assert(ch);
        if (--i >= 0) {
            /* nested choice, search cases of this choice*/
            tag = CONFD_GET_XMLTAG(&choice[i]);
            ns = CONFD_GET_XMLTAG_NS(&choice[i]);
            for (ca = ch->cases; ca; ca = ca->next) {
                if ((ca->ns == ns) && (ca->tag == tag)) {
                    break;
                }
            }
            assert(ca);
            choices = ca->choices;
            assert(--i >= 0);   /* must be another choice in the path */
       }
    }
    return ch;
}

static choice_node_t *choice_find_node(node_t *n, confd_value_t *choice)
{
    choice_node_t *c;

    if (n == NULL) return NULL;

    for (c = n->choices; c; c=c->next) {
        if (choice_path_eq(c->path, choice)) {
            return c;
        }
    }
    return NULL;
}

static choice_node_t *choice_find_or_create_node(node_t *n,
                                                 confd_value_t *choice)
{
    choice_node_t *c, *last;
    int path_len;
    struct confd_cs_choice *ch;

    for (last = NULL, c = n->choices; c; c=c->next) {
        if (choice_path_eq(c->path, choice)) {
            return c;
        }
        last = c;
    }
    /* need to create a new choice node */
    path_len = choice_path_len(choice);
    ch = find_cs_choice(n->cs, choice, path_len);
    c = new_choice_node(ch, choice, path_len);
    if (last) {
        last->next = c;
    } else {
        n->choices = c;
    }
    return c;
}

static void choice_delete_node(node_t *n, confd_value_t *choice)
{
    choice_node_t *c, *prev;

    if (n == NULL) return;

    for (prev = NULL, c = n->choices; c; c = c->next) {
        if (choice_path_eq(c->path, choice)) {
            if (prev) {
                prev->next = c->next;
            } else {
                n->choices = c->next;
            }
            free(c);
            return;
        }
        prev = c;
    }
    return;
}

static void del_all_node_attr(node_t *n);

static void delete_node(node_t *n)
{
    choice_node_t *c;

    del_all_node_attr(n);
    if (n->cs->info.type && n->u.val && !n->children) {
        confd_free_dup_value(n->u.val);
        n->u.val = NULL;
    } else {
        if (keycount(n->cs) > 1) {
            free(n->u.keys);
            n->u.keys = NULL;
        }
    }
    for (c = n->choices; c;) {
        choice_node_t *tmp = c;
        c=c->next;
        free(tmp);
    }
    free(n);
}

/* ------------------------------------------------------------------------ */

static node_t *cl_find_next(node_t *parent, node_t **prev, void *key,
                            int (cmp)(node_t *, void *))
{
    int cmp_is_eq = (parent->cs != NULL) ?
                     ((parent->cs->info.cmp == CS_NODE_CMP_USER) ? 1 : 0) : 0;
    int c;
    node_t *n = parent->children;
    *prev = NULL;
    if (n == NULL) return NULL;

    if ((c = cmp(n->prev, key)) == 0) {
        *prev = n->prev;
        return NULL;
    }
    if (!cmp_is_eq && (c < 0)) return NULL;

    for (;; n=n->next) {
        int c = cmp(n, key);
        if (c == 0) {
            *prev = n;
            return (n->next == parent->children) ? NULL : n->next;
        }
        if (!cmp_is_eq && (c > 0)) return n;
        if (n->next == parent->children) return NULL;
    }
}

static node_t *cl_find(node_t *parent, void *key, int (cmp)(node_t *, void *))
{
    node_t *ret;
    cl_find_next(parent, &ret, key, cmp);
    return ret;
}


static node_t *cl_append(node_t *parent, node_t *new)
{
    if (parent->children == NULL) {
        parent->children = new;
        new->next = new->prev = new;
    } else {
        new->next = parent->children;
        new->prev = parent->children->prev;
        parent->children->prev = new;
        new->prev->next = new;
    }
    return new;
}

static node_t *cl_prepend(node_t *parent, node_t *new)
{
    cl_append(parent, new);
    parent->children = new;
    return new;
}

static node_t *cl_insert(node_t *parent, node_t *before, node_t *new)
{
    parent->nchildren++;
    if (before == NULL) {
        return cl_append(parent, new);
    }
    if (parent->children == before) {
        return cl_prepend(parent, new);
    }
    new->next = before;
    new->prev = before->prev;
    before->prev->next = new;
    before->prev = new;
    return new;
}

static void cl_recursive_delete(node_t *n)
{
    if (n->children) {
        node_t *nxt, *tmp;
        for (tmp = n->children;;) {
            nxt = tmp->next;
            cl_recursive_delete(tmp);
            if (nxt == n->children) break;
            tmp = nxt;
        }
    }
    delete_node(n);
}

static void cl_unlink(node_t *parent, node_t *n)
{
    parent->nchildren--;
    if (parent->children == n) {
        if (n->next == n) {
            parent->children = NULL;
        } else {
            parent->children = n->next;
            n->next->prev = n->prev;
            n->prev->next = n->next;
        }
    } else {
        n->next->prev = n->prev;
        n->prev->next = n->next;
    }
}

static void cl_move(node_t *parent, node_t *n, node_t *after)
{
    node_t *before = (after == NULL) ? parent->children :
        (after->next == parent->children) ? NULL : after->next;
    cl_unlink(parent, n);
    cl_insert(parent, before, n);
}

static void cl_delete(node_t *parent, node_t *n)
{
    cl_unlink(parent, n);
    cl_recursive_delete(n);
}


/* ------------------------------------------------------------------------ */

static char *print_choice_path(FILE *f, confd_value_t *path)
{
    if (path[0].type != C_NOEXISTS) {
        char *sep = print_choice_path(f, &path[1]);
        fprintf(f, "%s%s", sep, confd_hash2str(CONFD_GET_XMLTAG(&path[0])));
        return "/";
    } else {
        return "";
    }
}

static void print(FILE *f, node_t *n, int lvl)
{
    char *tag;
    int kc;
    node_t *tmp = n;
    if (tmp == NULL) return;

    do {
        tag = confd_hash2str(tmp->cs->tag);
        kc = keycount(tmp->cs);
        if (tag == NULL) tag = "?";

        fprintf(f, "%*s%s (%d)", lvl, "", tag, tmp->cs->tag);
        if (debuglevel > 1) {
            fprintf(f, " <%p> <%p,%p>",
                    (void *)tmp, (void *)tmp->next, (void *)tmp->prev);
            if (tmp->children) {
                fprintf(f, " c=<%p>", (void *)tmp->children);
            }
            if ((kc == 1) && (tmp->u.key)) {
                fprintf(f, " key=<%p>", (void *)tmp->u.key);
            }
            if ((kc > 1) && (tmp->u.keys)) {
                int i;
                node_t **ks = tmp->u.keys;
                fprintf(f, " keys=<");
                for (i=0; i<kc; i++, ks++) {
                    fprintf(f, "%p", (void *)*ks);
                    if (i<(kc-1)) { fprintf(f, ","); }
                }
                fprintf(f, ">");
            }
        }
        if (tmp->nchildren > 0) { fprintf(f, " n=%d", tmp->nchildren); }
        if (tmp->cs->info.type && tmp->u.val && !tmp->children) {
            struct confd_type *tp;
            char val[256];
            if (is_leaf_list(tmp->cs)) {
                tp = confd_get_leaf_list_type(tmp->cs);
            } else {
                tp = tmp->cs->info.type;
            }
            confd_val2str(tp, tmp->u.val, val, 256);
            fprintf(f, " val=%s", val);
        }
        fprintf(f, "\n");
        if (tmp->choices) {
            choice_node_t *c;
            fprintf(f, "%*s choices:", lvl, "");
            for (c=tmp->choices; c; c=c->next) {
                fputs(" ", f);
                print_choice_path(f, c->path);
                fprintf(f, "=%s",
                        (c->set ? confd_hash2str(c->set->tag) : "unset"));
            }
            fputs("\n", f);
        }
        print(f, tmp->children, lvl+2);
        tmp = tmp->next;
    } while (tmp != n);
}

/* ------------------------------------------------------------------------ */

static int compare_xml_tag(node_t *node, void *x0)
{
    struct xml_tag *x = (struct xml_tag *)x0;
//    fprintf(stderr, "compare_xml_tag(%p (%d:%d) %p (%d:%d))\n",
//          node, node->cs->ns, node->cs->tag, x0, x->ns, x->tag);
    if (node->cs->ns == x->ns) {
        if (node->cs->tag == x->tag)
            return 0;
        return (node->cs->tag > x->tag) ? 1 : -1;
    }
    return (node->cs->ns > x->ns) ? 1 : -1;
}

static int compare_single_key(node_t *node, void *v0)
{
    confd_value_t *v2 = (confd_value_t *)v0;
    if (node->cs->info.cmp == CS_NODE_CMP_USER) {
        return (confd_val_eq(node->u.key->u.val, v2) == 0) ? 1 : 0;
    } else {
        return confd_val_cmp_strict(node->u.key->u.val, v2);
    }
}

static int compare_multi_key(node_t *node, void *vs0)
{
    confd_value_t *vs = (confd_value_t *)vs0;
    node_t **keynodes = node->u.keys;
    int kc = keycount(node->cs);
    int i;
    for (i=0; i<kc; i++, vs++, keynodes++) {
        int c;
        if (node->cs->info.cmp == CS_NODE_CMP_USER) {
            c = (confd_val_eq((*keynodes)->u.val, vs) == 0) ? 1 : 0;
        } else {
            c = confd_val_cmp_strict((*keynodes)->u.val, vs);
        }
        if (c != 0) return c;
    }
    return 0;
}

static int eq_single_key(node_t *node, void *v0, int nkeys)
{
    confd_value_t *v2 = (confd_value_t *)v0;
    if (node->cs->info.cmp == CS_NODE_CMP_USER) {
        return confd_val_eq(node->u.key->u.val, v2);
    } else {
        return (confd_val_cmp_strict(node->u.key->u.val, v2) == 0);
    }
}

static int eq_multi_key(node_t *node, void *vs0, int nkeys)
{
    confd_value_t *vs = (confd_value_t *)vs0;
    node_t **keynodes = node->u.keys;
    int i;
    for (i=0; i<nkeys; i++, vs++, keynodes++) {
        int c;
        if (node->cs->info.cmp == CS_NODE_CMP_USER) {
            c = confd_val_eq((*keynodes)->u.val, vs);
        } else {
            c = (confd_val_cmp_strict((*keynodes)->u.val, vs) == 0);
        }
        if (c == 0) return c;
    }
    return 1;
}

static node_t *node_add_child_leaf(node_t *parent, node_t *child)
{
    struct xml_tag xt = { .ns = child->cs->ns, .tag = child->cs->tag };
    node_t *p;
    node_t *nxt = cl_find_next(parent, &p, &xt, compare_xml_tag);
    return cl_insert(parent, nxt, child);
}

static node_t *kp_find_node(node_t *start, confd_hkeypath_t *kp,
                            node_t **parent)
{
    int pos = kp->len - 1;
    node_t *n = start, *p = NULL;

    for (; n && (pos >= 0); pos--) {
        p = n;
        if (kp->v[pos][0].type == C_XMLTAG) {
            n = cl_find(n, &(kp->v[pos][0].val.xmltag), compare_xml_tag);
        } else {
            assert(p && p->cs);
            int kc = keycount(p->cs);
            if (kc == 1) {
                n = cl_find(n, &(kp->v[pos][0]), compare_single_key);
            } else {
                n = cl_find(n, &(kp->v[pos][0]), compare_multi_key);
            }
        }
    }
    if (parent) { *parent = p; }
    return n;
}

static node_t *kp_find_or_create_node(node_t *parent, confd_hkeypath_t *kp)
{
    int pos = kp->len - 1;
    node_t *n, *n1;

    for (n = parent; pos >= 0; pos--) {
//      printf("pos=%d tag=%d n=%p\n", pos, kp->v[pos][0].val.xmltag.tag, n);
        if (kp->v[pos][0].type == C_XMLTAG) {
            node_t *nxt;
            nxt = cl_find_next(n, &n1,
                               &(kp->v[pos][0].val.xmltag), compare_xml_tag);
            if (n1 == NULL) {
                struct confd_cs_node *cs = (n->cs) ?
                    confd_find_cs_node_child(n->cs, kp->v[pos][0].val.xmltag) :
                    confd_find_cs_node(kp, kp->len-pos);
                n1 = cl_insert(n, nxt, new_node(cs));
            }
        } else {
            assert(n && n->cs);
            int kc = keycount(n->cs);
            if (kc == 1) {
                node_t *nxt;
                nxt = cl_find_next(n, &n1,
                                   &(kp->v[pos][0]), compare_single_key);
                if (n1 == NULL) {
                    node_t *keynode;
                    if (is_leaf_list(n->cs)) {
                        keynode = new_node(n->cs);
                    } else {
                        struct xml_tag key_xmlt;
                        key_xmlt.ns = n->cs->ns; /* ??? */
                        key_xmlt.tag = *(n->cs->info.keys);
                        keynode = new_node(
                            confd_find_cs_node_child(n->cs, key_xmlt));
                    }
                    keynode->u.val = confd_value_dup(&(kp->v[pos][0]));
                    n1 = cl_insert(n, nxt, new_node(n->cs));
                    cl_insert(n1, NULL, keynode);
                    n1->u.key = keynode;
                }
            } else {
                node_t *nxt;
                nxt = cl_find_next(n, &n1, &(kp->v[pos][0]), compare_multi_key);
                if (n1 == NULL) {
                    u_int32_t *kt = n->cs->info.keys;
                    node_t **keyleafs = malloc(sizeof(node_t*)*kc);
                    int i;
                    n1 = new_node(n->cs);
                    assert(keyleafs);
                    n1->u.keys = keyleafs;
                    for (i=0; i<kc; i++, keyleafs++, kt++) {
                        struct xml_tag key_xmlt =
                            { .ns = n->cs->ns, .tag = *kt };
                        node_t *keynode = new_node(
                            confd_find_cs_node_child(n->cs, key_xmlt));
                        keynode->u.val = confd_value_dup(&(kp->v[pos][i]));
                        *keyleafs = keynode;
                        node_add_child_leaf(n1, keynode);
                    }
                    cl_insert(n, nxt, n1);
                    //print(stderr, n1, 0);
                }
            }
        }
        n = n1;
//      printf("pos=%d tag=%d n=%p\n", pos, kp->v[pos][0].val.xmltag.tag, n);
    }
    return n;
}

static node_t *kp_set_node_value(node_t *parent, confd_hkeypath_t *kp,
                                 confd_value_t *val)
{
    node_t *n = kp_find_or_create_node(parent, kp);
    assert(n);
    if (n->u.val) {
        confd_free_dup_value(n->u.val);
    }
    n->u.val = confd_value_dup(val);
    return n;
}

static void kp_set_node_attr(node_t *parent, confd_hkeypath_t *kp,
                             u_int32_t attr, confd_value_t *val)
{
    node_t *n = kp_find_or_create_node(parent, kp);
    struct attr *a, *new;

    assert(n);

    a = n->attrs;
    while (a) {
        if (a->attr == attr) {
            confd_free_dup_value(a->val);
            a->val = confd_value_dup(val);
            return;
        } else {
            a = a->next;
        }
    }
    new = (struct attr *)malloc(sizeof(struct attr));
    new->attr = attr;
    new->val = confd_value_dup(val);
    new->next = n->attrs;
    n->attrs = new;
}

static void kp_del_node_attr(node_t *parent, confd_hkeypath_t *kp,
                             u_int32_t attr)
{
    node_t *n = kp_find_node(parent, kp, NULL);
    struct attr *a, **p;

    if (!n) {
        return;
    }
    a = n->attrs;
    p = &n->attrs;
    while (a) {
        if (a->attr == attr) {
            *p = a->next;
            confd_free_dup_value(a->val);
            free(a);
            return;
        } else {
            p = &a->next;
            a = a->next;
        }
    }
}

static void del_all_node_attr(node_t *n)
{
    struct attr *a = n->attrs, *an;

    while (a) {
        an = a->next;
        confd_free_dup_value(a->val);
        free(a);
        a = an;
    }
}

/* maybe pre-create empty leaf-lists to make it possible to
   return empty leaf-lists "as leafs" in bulk replies */

static void pre_create_leaf_lists(node_t *parent,
                                  struct confd_cs_node *children)
{
    struct confd_cs_node *child;
    struct xml_tag tag;
    node_t *nxt, *n;

    assert(parent);
    for (child = children; child != NULL; child = child->next) {
        /* need to create leaf-list or np-container with leaf-list descendant */
        if ((child->info.flags & CS_NODE_IS_LEAF_LIST) ||
            ((child->info.flags & CS_NODE_IS_CONTAINER) &&
             container_is_np(child) && child->children != NULL)) {
            tag.tag = child->tag;
            tag.ns = child->ns;
            nxt = cl_find_next(parent, &n, &tag, compare_xml_tag);
            if (n == NULL) {
                n = cl_insert(parent, nxt, new_node(child));
                if (child->info.flags & CS_NODE_IS_CONTAINER) {
                    /* recurse */
                    pre_create_leaf_lists(n, n->cs->children);
                    if (n->nchildren == 0) {
                        /* no leaf-list descendant, delete */
                        cl_delete(parent, n);
                    }
                }
            }
        }
    }
}

static void maybe_init_pre_create_leaf_lists()
{
    if (do_pre_create_leaf_lists) {
        int n, i;
        struct confd_nsinfo *nslist;
        struct confd_cs_node *cs_root;

        n = confd_get_nslist(&nslist);
        for (i = 0; i < n; i++) {
            if ((cs_root = confd_find_cs_root(nslist[i].hash)) != NULL) {
                pre_create_leaf_lists(&root, cs_root);
            }
        }
    }
}

static void maybe_pre_create_leaf_lists(node_t *parent)
{
    if (do_pre_create_leaf_lists) {
        pre_create_leaf_lists(parent, parent->cs->children);
    }
}

/* ------------------------------------------------------------------------ */

static void dbgprint()
{
    fputs("\n", stderr);
    print(stderr, root.children, 0);
    fputs("\n", stderr);
}

static void cb_inc(struct confd_trans_ctx *tctx, int idx)
{
    struct cb_stat *s = (struct cb_stat *)tctx->cb_opaque;

    s->cb_counters[idx]++;
}

static int cb_get_elem(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    /*Alter get_elem for YANG_PUSH Example*/
    char buf[BUFSIZ];
    confd_pp_value(buf, BUFSIZ, &(kp->v[0][0]));
    if (strcmp(buf, "oper-status") == 0) {
        confd_value_t v;
        oper_status = (oper_status % 7) + 1;
        CONFD_SET_ENUM_VALUE(&v, oper_status);
        kp_set_node_value(&root, kp, &v);
    }
    if (strcmp(buf, "enabled") == 0) {
        confd_value_t v;
        enabled = (enabled + 1) % 2;
        CONFD_SET_BOOL(&v, enabled);
        kp_set_node_value(&root, kp, &v);
    }
    /*End Alter code*/

    node_t *n = kp_find_node(&root, kp, NULL);

    cb_inc(tctx, CB_GET_ELEM);

    if (n && n->u.val) {
        confd_data_reply_value(tctx, n->u.val);
    } else {
        confd_data_reply_not_found(tctx);
    }
    return CONFD_OK;
}

static int filter_origin(struct confd_trans_ctx *tctx, u_int32_t attr)
{
    return attr == CONFD_ATTR_ORIGIN && tctx->dbname != CONFD_OPERATIONAL;
}

static int cb_get_attrs(struct confd_trans_ctx *tctx,
                        confd_hkeypath_t *kp,
                        u_int32_t *attrs, int num_attrs)
{
    node_t *n = kp_find_node(&root, kp, NULL);
    confd_attr_value_t res[num_attrs ? num_attrs : 32];
    struct attr *a;
    int i, j=0;

    cb_inc(tctx, CB_GET_ATTRS);

    if (n) {
        if (num_attrs > 0) {
            for (i = 0; i < num_attrs; i++) {
                if (!filter_origin(tctx, attrs[i])) {
                    a = n->attrs;
                    while (a) {
                        if (a->attr == attrs[i]) {
                            res[j].attr = a->attr;
                            res[j].v = *a->val;
                            j++;
                            break;
                        } else {
                            a = a->next;
                        }
                     }
                 }
             }
        } else {
            /* return *all* attrs */
            a = n->attrs;
            while (a && j < 32) {
                if (!filter_origin(tctx, a->attr)) {
                    res[j].attr = a->attr;
                    res[j].v = *a->val;
                    j++;
                }
                a = a->next;
            }
        }
        confd_data_reply_attrs(tctx, res, j);
    } else {
        confd_data_reply_not_found(tctx);
    }
    return CONFD_OK;
}

/* find next_data structure associated with the current next */
static struct next_data *find_next_data(struct confd_trans_ctx *tctx)
{
    struct next_data *p = (struct next_data *)tctx->t_opaque;
    while (p) {
        if (p->traversal_id == tctx->traversal_id) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

/* delete the next_data structure associated with the current next */
static void del_next_data(struct confd_trans_ctx *tctx)
{
    struct next_data **prev = (struct next_data **)&tctx->t_opaque;
    struct next_data *p = (struct next_data *)tctx->t_opaque;
    while (p) {
        if (p->traversal_id == tctx->traversal_id) {
            *prev = p->next;
            confd_free_list_filter(p->f);
            free(p);
            return;
        }
        prev = &p->next;
        p = p->next;
    }
}
static int cmp(enum confd_expr_op op, struct confd_type *tp,
               confd_value_t *nodev, confd_value_t *filterv)
{
    char nstr[256];
    char fstr[256];
    long long int ni, fi;
    char *endn, *endf;

    /* convert the node's value to a string; we know that
       the node's value matches the cs-node */
    if (confd_val2str(tp, nodev, nstr, 256) == CONFD_ERR) {
        return 1; /* internal error */
    }
    /* convert the given filter value to a string; it is either
       already a string, or an identityref, but we don't know if it
       matches the type for the leaf. */
    if (confd_pp_value(fstr, 256, filterv) == 0) {
        return 1; /* internal error */
    }
    switch (op) {
    case CONFD_CMP_EQ:
        return (strncmp(nstr, fstr, 256) == 0);
    case CONFD_CMP_NEQ:
        return (strncmp(nstr, fstr, 256) != 0);
    case CONFD_CMP_LT:
    case CONFD_CMP_LTE:
    case CONFD_CMP_GT:
    case CONFD_CMP_GTE:
        /* number comparison op */
        ni = strtoll(nstr, &endn, 10);
        fi = strtoll(fstr, &endf, 10);
        if (*endn == '\0' && *endf == '\0') {
            /* both converted to integers ok */
            switch (op) {
            case CONFD_CMP_LT:
                return ni < fi;
            case CONFD_CMP_LTE:
                return ni <= fi;
            case CONFD_CMP_GT:
                return ni > fi;
            case CONFD_CMP_GTE:
                return ni >= fi;
            default:
                break;
            }
        } else {
            double nd, fd;
            nd = strtod(nstr, &endn);
            fd = strtod(fstr, &endf);
            if (*endn == '\0' && *endf == '\0') {
                /* both converted to floats ok */
                switch (op) {
                case CONFD_CMP_LT:
                    return nd < fd;
                case CONFD_CMP_LTE:
                    return nd <= fd;
                case CONFD_CMP_GT:
                    return nd > fd;
                case CONFD_CMP_GTE:
                    return nd >= fd;
                default:
                    break;
                }
            }
        }
    case CONFD_EXEC_STARTS_WITH:
        return (strncmp(nstr, fstr, strlen(fstr)) == 0);
    default:
        return 1;
    }
    return 0;
}

static int match_origin(confd_value_t *filterv, struct attr *attrs)
{
    while (attrs) {
        if ((attrs->attr == CONFD_ATTR_ORIGIN) &&
            confd_val_eq(filterv, attrs->val)){
            return 1;
        }
        attrs = attrs->next;
    }
    return 0;
}

static int search_origin(node_t *n, confd_value_t *filterv)
{
    node_t *n2;
    if (!n) return 0;
    n2 = n->children;
    do {
        if (match_origin(filterv, n->attrs) ||
            (n2->nchildren > 0 && search_origin(n2, filterv))) {
            return 1;
        }
        n2 = n2->next;
    } while (n2 != n->children);
    return 0;
}

static node_t *find_node(node_t *n, struct xml_tag *node, int nodelen)
{
    int i = 0;
    node_t *p = n;
    while (i < nodelen) {
        node_t *c = p->children;
        int found = 0;
        while (c && !found) {
            if (c->cs->ns == node[i].ns && c->cs->tag == node[i].tag) {
                p = c;
                i++;
                found = 1;
            } else {
                c = c->next;
            }
        }
        if (!found) {
            return NULL;
        }
    }
    return p;
}

static int match_filter(node_t *n, struct confd_list_filter *f)
{
    node_t *n2, *n3;
    struct confd_type *tp;

    if (!f) {
        return 1;
    }

    switch (f->type) {
    case CONFD_LF_OR:
        return match_filter(n, f->expr1) || match_filter(n, f->expr2);
    case CONFD_LF_AND:
        return match_filter(n, f->expr1) && match_filter(n, f->expr2);
    case CONFD_LF_NOT:
        return !match_filter(n, f->expr1);
    case CONFD_LF_CMP:
    case CONFD_LF_EXEC:
        n2 = find_node(n, f->node, f->nodelen);
        if (!n2) return 0;
        if (n2->cs->info.flags & CS_NODE_IS_LEAF_LIST) {
            tp = confd_get_leaf_list_type(n2->cs);
        } else {
            tp = n2->cs->info.type;
        }

        if (!(n2->cs->info.flags & CS_NODE_IS_LEAF_LIST)) {
            /* normal leaf */
            return cmp(f->op, tp, n2->u.val, f->val);
        } else if (is_leaf_list(n2->cs)) {
            /* leaf list as list */
            n3 = n2->children;
            do {
                if (cmp(f->op, tp, n3->u.key->u.val, f->val)) {
                    return 1;
                }
                n3 = n3->next;
            } while (n3 != n2->children);
            return 0;
        } else {
            /* leaf list as array */
            int i;
            for (i = 0; i < n2->u.val->val.list.size; i++) {
                if (cmp(f->op, tp, &n2->u.val->val.list.ptr[i], f->val)) {
                    return 1;
                }
            }
            return 0;
        }
    case CONFD_LF_EXISTS:
        return (find_node(n, f->node, f->nodelen) != 0);
    case CONFD_LF_ORIGIN:
        return search_origin(n, f->val);
    }
    return 1;
}

/* search for next list entry that matches the filter (if any) */
static void search_next(node_t **res, node_t *n, struct next_data *nd)
{
    do {
        if (match_filter(n, nd->f)) {
            *res = n;
            return;
        }
        n = n->next;
    } while (n != nd->listnode->children);
    *res = NULL;
    return;
}

static int fully_support_filter(struct confd_list_filter *f)
{
    /* we support everything except derived-from* and and re-match */
    if (f->op == CONFD_EXEC_DERIVED_FROM ||
        f->op == CONFD_EXEC_DERIVED_FROM_OR_SELF ||
        f->op == CONFD_EXEC_RE_MATCH) {
        return 0;
    } else {
        if (f->expr1 && !fully_support_filter(f->expr1)) {
            return 0;
        }
        if (f->expr2 && !fully_support_filter(f->expr2)) {
            return 0;
        }
    }
    return 1;
}

/* generic get_next helper.  returns 0 if no more entries exist.
   The struct next_data (per kp) contains constant data per next traversal.
   The long next points to the next entry in the list. */
static int gen_get_next(struct confd_trans_ctx *tctx,
                        struct next_data **ndp, node_t **np,
                        node_t *first,
                        confd_hkeypath_t *kp, long next)
{
    struct next_data *nd;
    node_t *found, *nxt;
    nd = find_next_data(tctx);

    if (next == -1) {
        if (!nd) {
            /* there is no ongoing next for this list */
            node_t *n = kp_find_node(&root, kp, NULL);
            if ((n == NULL) || (n->children == NULL)) {
                return 0;
            }
            nd = malloc(sizeof(struct next_data));
            nd->traversal_id = tctx->traversal_id;
            nd->listnode = n;
            nd->kc = keycount(n->cs);
            nd->next = (struct next_data *)tctx->t_opaque;
            tctx->t_opaque = (void *)nd;
        } else {
            /* this is a restarted get-next for this list, resuse
               the next_data structure but free the filter */
            confd_free_list_filter(nd->f);
        }
        if(opt_honor_filter) {
            confd_data_get_list_filter(tctx, &nd->f);
        } else {
            nd->f = NULL;
        }
        if (nd->f && fully_support_filter(nd->f)) {
            /* tell ConfD that we honor the filter */
            tctx->cb_flags |= CONFD_TRANS_CB_FLAG_FILTERED;
        }
        if (first) {
            nxt = first;
        } else {
            nxt = nd->listnode->children;
        }
    } else {
        nxt = (node_t *)next;
        if (nxt == nd->listnode->children) {
            /* end of list */
            del_next_data(tctx);
            return 0;
        }
    }
    search_next(&found, nxt, nd);
    if (!found) {
        /* no more entries match the filter */
        del_next_data(tctx);
        return 0;
    }
    *ndp = nd;
    *np = found;
    return 1;
}

static int cb_get_next(struct confd_trans_ctx *tctx,
                       confd_hkeypath_t *kp, long next)
{
    struct next_data *nd;
    node_t *nxt;
    cb_inc(tctx, CB_GET_NEXT);
    if (!gen_get_next(tctx, &nd, &nxt, NULL, kp, next)) {
        /* no list entries exist */
        confd_data_reply_next_key(tctx, NULL, 0, 0);
        return CONFD_OK;
    } else {
        long nnext = (long)nxt->next;
        if (nd->kc == 1) {
            confd_data_reply_next_key(tctx, nxt->u.key->u.val, 1, nnext);
        } else {
            int i;
            node_t **keynodes = nxt->u.keys;
            confd_value_t kv[nd->kc];
            for (i=0; i<nd->kc; i++, keynodes++) {
                kv[i] = *(*keynodes)->u.val;
            }
            confd_data_reply_next_key(tctx, &kv[0], nd->kc, nnext);
        }
    }
    return CONFD_OK;
}

static int gen_find_next(struct confd_trans_ctx *tctx,
                         confd_hkeypath_t *kp,
                         enum confd_find_next_type type,
                         confd_value_t *keys, int nkeys,
                         struct next_data **ndp, node_t **np)
{
    node_t *n, *nxt, *first;
    int kc;
    int (*eq)(node_t *, void *, int);
    int found;

    n = kp_find_node(&root, kp, NULL);
    if ((n == NULL) || (n->children == NULL)) {
        return 0;
    }
    kc = keycount(n->cs);
    if (kc == 1) {
        eq = eq_single_key;
    } else {
        eq = eq_multi_key;
    }

    found = 0;
    first = n->children;
    nxt = n->children;

    do {
        if (eq(nxt, keys, nkeys)) {
            found = 1;
            break;
        }
        nxt = nxt->next;
    } while (nxt != first);

    if (!found) {
        return 0;
    }

    if (type == CONFD_FIND_NEXT) {
        nxt = nxt->next;
    }
    if (nxt == first) {
        return 0;
    }
    if (!gen_get_next(tctx, ndp, np, nxt, kp, -1)) {
        return 0;
    } else {
        return 1;
    }
}

static int cb_find_next(struct confd_trans_ctx *tctx,
                        confd_hkeypath_t *kp,
                        enum confd_find_next_type type,
                        confd_value_t *keys, int nkeys)
{
    struct next_data *nd;
    node_t *nxt;
    cb_inc(tctx, CB_FIND_NEXT);
    if (!gen_find_next(tctx, kp, type, keys, nkeys, &nd, &nxt)) {
        confd_data_reply_next_key(tctx, NULL, 0, 0);
        return CONFD_OK;
    } else {
        long nnext = (long)nxt->next;
        if (nd->kc == 1) {
            confd_data_reply_next_key(tctx, nxt->u.key->u.val, 1, nnext);
        } else {
            int i;
            node_t **keynodes = nxt->u.keys;
            confd_value_t kv[nd->kc];
            for (i=0; i<nd->kc; i++, keynodes++) {
                kv[i] = *(*keynodes)->u.val;
            }
            confd_data_reply_next_key(tctx, &kv[0], nd->kc, nnext);
        }
    }
    return CONFD_OK;
}

static int cb_accumulate1(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    return CONFD_ACCUMULATE;
}

static int cb_accumulate2(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp,
                          confd_value_t *v1)
{
    return CONFD_ACCUMULATE;
}

static int cb_accumulate3(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp,
                           confd_value_t *v1, confd_value_t *v2)
{
    return CONFD_ACCUMULATE;
}

static int cb_accumulate4(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp,
                          u_int32_t attr, confd_value_t *v)
{
    return CONFD_ACCUMULATE;
}

static int cb_set_elem(struct confd_trans_ctx *tctx,
                       confd_hkeypath_t *kp, confd_value_t *newval)
{
    cb_inc(tctx, CB_SET_ELEM);
    kp_set_node_value(&root, kp, newval);
    return CONFD_OK;
}

static int cb_set_attr(struct confd_trans_ctx *tctx,
                       confd_hkeypath_t *kp,
                       u_int32_t attr, confd_value_t *v)
{
    cb_inc(tctx, CB_SET_ATTR);
    if (v) {
        kp_set_node_attr(&root, kp, attr, v);
    } else {
        kp_del_node_attr(&root, kp, attr);
    }
    return CONFD_OK;
}


static int cb_create(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    cb_inc(tctx, CB_CREATE);
    maybe_pre_create_leaf_lists(kp_find_or_create_node(&root, kp));
    return CONFD_OK;
}

static int cb_remove(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    node_t *p = NULL;
    node_t *n = kp_find_node(&root, kp, &p);
    cb_inc(tctx, CB_REMOVE);
    if (p && n) {
        cl_delete(p, n);
    }
    return CONFD_OK;
}

static int cb_exists_optional(struct confd_trans_ctx *tctx,
                              confd_hkeypath_t *kp)
{
    node_t *n = kp_find_node(&root, kp, NULL);
    cb_inc(tctx, CB_EXISTS_OPTIONAL);

    if (n) {
        confd_data_reply_found(tctx);
    } else {
        confd_data_reply_not_found(tctx);
    }
    return CONFD_OK;
}

static int cb_num_instances(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    node_t *n = kp_find_node(&root, kp, NULL);
    confd_value_t v;
    cb_inc(tctx, CB_NUM_INSTANCES);
    if (n) {
        CONFD_SET_INT32(&v, n->nchildren);
        confd_data_reply_value(tctx, &v);
    } else {
        // For a list under something that exists (for example a
        // top-level list, or a list under a top-level container et.c.)
        // returning not_found is a protocol error...
//      confd_data_reply_not_found(tctx);
        CONFD_SET_INT32(&v, 0);
        confd_data_reply_value(tctx, &v);
    }
    return CONFD_OK;
}


static inline int is_key(struct confd_cs_node *list, node_t *leaf)
{
    u_int32_t *kt;
    if (!(daemon_flags & CONFD_DAEMON_FLAG_BULK_GET_CONTAINER) ||
        list->info.keys) {
        for (kt = list->info.keys; *kt; kt++) {
            if (*kt == leaf->cs->tag) return 1;
        }
    }
    return 0;
}

static int object_size(struct confd_cs_node *list, node_t *l, int include_keys)
{
    node_t *tmp = l;
    int sz = 0;
    if (tmp == NULL) return 0;
    if (is_leaf_list(list)) return include_keys != 0;
    do {
        if (tmp->cs->info.keys == NULL) {
            if (tmp->cs->info.flags & CS_NODE_IS_CONTAINER) {
                if (tmp->nchildren == 0 && container_is_p(tmp->cs)) {
                    /* Empty presence container, +2 for BEGIN and END Tags */
                    sz += 2;
                } else if (tmp->nchildren > 0) {
                    /* Non-empty container */
                    sz += 2;
                    sz += object_size(list, tmp->children, 1);
                }
            } else if (include_keys || !is_key(list, tmp)) {
                sz++;
            }
        }
        tmp = tmp->next;
    } while (tmp != l);
    return sz;
}

static void leaf_list_to_c_list(node_t *n, confd_value_t *c_list) {
    node_t *tmp = n;
    confd_value_t *item = c_list;
    do {
        *item = *(tmp->children->u.val);
        ++item;
        tmp = tmp->next;
    } while (tmp != n);
}

static confd_tag_value_t *object_fill(struct confd_cs_node *list,
                                      node_t *n, confd_tag_value_t *tvs)
{
    node_t *tmp = n;
    if (tmp == NULL) return tvs;
    do {
        if (tmp->cs->info.keys == NULL &&
            ((list == NULL) || !is_key(list, tmp))) {
            tvs->tag.ns  = tmp->cs->ns;
            tvs->tag.tag = tmp->cs->tag;
            if (tmp->cs->info.flags & CS_NODE_IS_CONTAINER) {
                CONFD_SET_XMLBEGIN(&(tvs->v), tmp->cs->tag, tmp->cs->ns);
                tvs++;
                confd_tag_value_t *check_empty = tvs;
                tvs = object_fill(NULL, tmp->children, tvs);
                if (check_empty == tvs && container_is_np(tmp->cs)) {
                    /* empty np-container; step back to overwrite XMLBEGIN*/
                    tvs--;
                } else {
                    tvs->tag.ns  = tmp->cs->ns;
                    tvs->tag.tag = tmp->cs->tag;
                    CONFD_SET_XMLEND(&(tvs->v), tmp->cs->tag, tmp->cs->ns);
                    tvs++;
                }
            } else {
                if (tmp->u.val && !is_leaf_list(tmp->cs)) {
                    tvs->v = *(tmp->u.val);
                    tvs++;
                } else if (is_leaf_list(tmp->cs) && opt_use_clist) {
                    if (tmp->nchildren > 0) {
                        /* pass as a single array element with type C_LIST */
                        u_int32_t sz = tmp->nchildren;
                        confd_value_t *c_list =
                            malloc((size_t) sz * sizeof(confd_value_t));
                        leaf_list_to_c_list(tmp->children, c_list);
                        CONFD_SET_LIST(&(tvs->v), c_list, sz);
                        tvs++;
                    } else {
                        /* the leaf-list does not exist
                         * pass a C_LIST with size 0 in the array */
                        CONFD_SET_LIST(&(tvs->v), NULL, 0);
                        tvs++;
                    }
                }
            }
        }
        tmp = tmp->next;
    } while (tmp != n);
    return tvs;
}

static confd_tag_value_t *object_fill_keys(node_t *list, confd_tag_value_t *tvs)
{
    int kc = keycount(list->cs);
    if (kc == 1) {
        if (is_leaf_list(list->cs)) {
            tvs->tag.ns = tvs->tag.tag = 0;
            tvs->v = *(list->u.key->u.val);
            return ++tvs;
        }
        tvs->tag.ns  = list->u.key->cs->ns;
        tvs->tag.tag = list->u.key->cs->tag;
        tvs->v = *(list->u.key->u.val);
        tvs++;
    } else {
        int i;
        node_t **keynodes = list->u.keys;
        for (i=0; i<kc; i++, keynodes++, tvs++) {
            tvs->tag.ns  = (*keynodes)->cs->ns;
            tvs->tag.tag = (*keynodes)->cs->tag;
            tvs->v       = *(*keynodes)->u.val;
        }
    }
    return object_fill(list->cs, list->children, tvs);
}

static void free_leaf_lists(confd_tag_value_t *tvs,int len) {
    /* It seems deep object structures are flattened,
     * No need for recursion (not possible either) */
    if ( opt_use_clist ) {
        confd_tag_value_t *tmp = tvs;
        int i;
        for (i=0; i < len; i++) {
            if (tmp && tmp->v.type == C_LIST)
            {
                free(tmp->v.val.list.ptr);
            }
            tmp++;
        }
    }
}

static int cb_get_object(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp)
{
    node_t *n = kp_find_node(&root, kp, NULL);
    cb_inc(tctx, CB_GET_OBJECT);
    if (n) {
        int sz = object_size(n->cs, n->children, 0);
        confd_tag_value_t tvs[sz];
        confd_tag_value_t *tv = object_fill(n->cs, n->children, &tvs[0]);
        int len = tv - &tvs[0];
        assert(len <= sz);
        confd_data_reply_tag_value_array(tctx, &tvs[0], len);
        free_leaf_lists(&tvs[0], len);
    } else {
        confd_data_reply_not_found(tctx);
    }
    return CONFD_OK;
}

static int cb_get_next_object(struct confd_trans_ctx *tctx,
                              confd_hkeypath_t *kp, long next)
{
    struct next_data *nd;
    node_t *nxt;
    cb_inc(tctx, CB_GET_NEXT_OBJECT);
    if (!gen_get_next(tctx, &nd, &nxt, NULL, kp, next)) {
        /* no list entries exist */
        confd_data_reply_next_object_tag_value_array(tctx, NULL, 0, 0);
    } else {
        long nnext = (long)nxt->next;
        int sz = object_size(nxt->cs, nxt->children, 1);
        confd_tag_value_t tvs[sz];
        confd_tag_value_t *tv = object_fill_keys(nxt, &tvs[0]);
        int len = tv - &tvs[0];
        assert(len <= sz);
        confd_data_reply_next_object_tag_value_array(
                tctx, &tvs[0], len, nnext);
        free_leaf_lists(&tvs[0], len);
    }
    return CONFD_OK;
}

static int cb_get_next_objects(struct confd_trans_ctx *tctx,
                               confd_hkeypath_t *kp, long next)
{
    struct next_data *nd;
    node_t *nxt, *found;
    cb_inc(tctx, CB_GET_NEXT_OBJECTS);
    if (!gen_get_next(tctx, &nd, &nxt, NULL, kp, next)) {
        /* no list entries exist */
        confd_data_reply_next_object_tag_value_array(tctx, NULL, 0, 0);
    } else {
        struct confd_tag_next_object tobj[opt_get_next_object + 1];
        int nobj;
        for (nobj = 0; nobj < opt_get_next_object; nobj++) {
            int sz = object_size(nxt->cs, nxt->children, 1);
            confd_tag_value_t *tvs = malloc(sz * sizeof(confd_tag_value_t));
            confd_tag_value_t *tv;
            assert(tvs);
            tv = object_fill_keys(nxt, tvs);
            assert((tv - tvs) <= sz);
            tobj[nobj].tv   = tvs;
            tobj[nobj].n    = tv - tvs;
            tobj[nobj].next = (long)nxt->next;
            if (nxt->next == nd->listnode->children) {
                found = NULL;
            } else {
                search_next(&found, nxt->next, nd);
            }
            if (!found) {
                nobj++;
                tobj[nobj].tv = NULL;
                tobj[nobj].n  = 0;
                tobj[nobj].next = (long)0;
                nobj++;
                break;
            }
            nxt = found;
        }
        confd_data_reply_next_object_tag_value_arrays(tctx, tobj,
                                                      nobj, 0);
        for (nobj--; nobj >= 0; nobj--) {
            if (tobj[nobj].tv) {
                free_leaf_lists(tobj[nobj].tv, tobj[nobj].n);
                free(tobj[nobj].tv);
            }
        }
    }
    return CONFD_OK;
}

static int cb_find_next_object(struct confd_trans_ctx *tctx,
                        confd_hkeypath_t *kp,
                        enum confd_find_next_type type,
                        confd_value_t *keys, int nkeys)
{
    struct next_data *nd;
    node_t *nxt;
    cb_inc(tctx, CB_FIND_NEXT_OBJECT);
    if (!gen_find_next(tctx, kp, type, keys, nkeys, &nd, &nxt)) {
        /* no list entries exist */
        confd_data_reply_next_object_tag_value_array(tctx, NULL, 0, 0);
    } else {
        long nnext = (long)nxt->next;
        int sz = object_size(nxt->cs, nxt->children, 1);
        confd_tag_value_t tvs[sz];
        confd_tag_value_t *tv = object_fill_keys(nxt, &tvs[0]);
        int len = tv - &tvs[0];
        assert(len <= sz);
        confd_data_reply_next_object_tag_value_array(
            tctx, &tvs[0], len, nnext);
        free_leaf_lists(&tvs[0], len);
    }
    return CONFD_OK;
}

static int cb_find_next_objects(struct confd_trans_ctx *tctx,
                        confd_hkeypath_t *kp,
                        enum confd_find_next_type type,
                        confd_value_t *keys, int nkeys)
{
    struct next_data *nd;
    node_t *nxt, *found;
    cb_inc(tctx, CB_FIND_NEXT_OBJECTS);
    if (!gen_find_next(tctx, kp, type, keys, nkeys, &nd, &nxt)) {
        /* no list entries exist */
        confd_data_reply_next_object_tag_value_array(tctx, NULL, 0, 0);
    } else {
        struct confd_tag_next_object tobj[opt_find_next_object + 1];
        int nobj;
        for (nobj = 0; nobj < opt_find_next_object; nobj++) {
            int sz = object_size(nxt->cs, nxt->children, 1);
            confd_tag_value_t *tvs = malloc(sz * sizeof(confd_tag_value_t));
            confd_tag_value_t *tv;
            assert(tvs);
            tv = object_fill_keys(nxt, tvs);
            assert((tv - tvs) <= sz);
            tobj[nobj].tv   = tvs;
            tobj[nobj].n    = tv - tvs;
            tobj[nobj].next = (long)nxt->next;
            if (nxt->next == nd->listnode->children) {
                found = NULL;
            } else {
                search_next(&found, nxt->next, nd);
            }
            if (!found) {
                nobj++;
                tobj[nobj].tv = NULL;
                tobj[nobj].n  = 0;
                tobj[nobj].next = (long)0;
                nobj++;
                break;
            }
            nxt = found;
        }
        confd_data_reply_next_object_tag_value_arrays(tctx, tobj,
                                                      nobj, 0);
        for (nobj--; nobj >= 0; nobj--) {
            if (tobj[nobj].tv) {
                free_leaf_lists(tobj[nobj].tv, tobj[nobj].n);
                free(tobj[nobj].tv);
            }
        }
    }
    return CONFD_OK;
}

static int cb_get_case(struct confd_trans_ctx *tctx,
                       confd_hkeypath_t *kp, confd_value_t *choice)
{
    node_t *n = kp_find_node(&root, kp, NULL);
    choice_node_t *c = choice_find_node(n, choice);

    cb_inc(tctx, CB_GET_CASE);
    if (c) {
        confd_value_t v;
        CONFD_SET_XMLTAG(&v, c->set->tag, c->set->ns);
        confd_data_reply_value(tctx, &v);
    } else {
        confd_data_reply_not_found(tctx);
    }

    return CONFD_OK;
}

static int cb_set_case(struct confd_trans_ctx *tctx, confd_hkeypath_t *kp,
                       confd_value_t *choice, confd_value_t *caseval)
{
    cb_inc(tctx, CB_SET_CASE);
    if ((caseval == NULL) || (caseval->type == C_NOEXISTS)) {
        node_t *n = kp_find_node(&root, kp, NULL);
        choice_delete_node(n, choice);
    } else {
        node_t *n = kp_find_or_create_node(&root, kp);
        choice_node_t *c = choice_find_or_create_node(n, choice);
        u_int32_t tag = CONFD_GET_XMLTAG(caseval);
        u_int32_t ns = CONFD_GET_XMLTAG_NS(caseval);
        struct confd_cs_case *tmp;

        for (tmp = c->csc->cases; tmp; tmp=tmp->next) {
            if ((tmp->ns == ns) && (tmp->tag == tag)) {
                c->set = tmp;
                break;
            }
        }
    }

    return CONFD_OK;
}

static int cb_move_after(struct confd_trans_ctx *tctx,
                         confd_hkeypath_t *kp, confd_value_t *prevkeys)
{
    node_t *parent = NULL;
    node_t *n = kp_find_node(&root, kp, &parent);
    node_t *after = NULL;

    cb_inc(tctx, CB_MOVE_AFTER);
    if (n && parent) {
        if (prevkeys) {
            int kc = keycount(parent->cs);
            after = cl_find(parent, prevkeys, (kc == 1) ? compare_single_key :
                            compare_multi_key);
        }
        cl_move(parent, n, after);
    }
    return CONFD_OK;
}

/* start YANG-Push example PUSH ON-CALLBACKS*/
static int cb_subscribe_on_change(struct confd_push_on_change_ctx *pctx) {
    if(push_ctx) {
        fprintf(stderr,
                "\ngeneric-dp: multiple subscriptions are not supported.");
        return CONFD_ERR;
    }
    fprintf(stderr, "\ngeneric-dp: subscribe subid: %d, usid: %d, "
            "xpath_filter: %s, num_hkpaths: %d, dampening_period: %d, "
            "excluded_changes: %d\n", pctx->subid, pctx->usid,
            pctx->xpath_filter, pctx->npaths, pctx->dampening_period,
            pctx->excluded_changes);
    push_ctx = pctx;
    return CONFD_OK;
}

static int cb_unsubscribe_on_change(struct confd_push_on_change_ctx *pctx) {
    fprintf(stderr, "\ngeneric-dp: unsubscribe subid: %d\n", pctx->subid);
    push_ctx = NULL;
    return CONFD_OK;
}

static void getdatetime(struct confd_datetime *datetime)
{
    struct tm tm;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tm);

    memset(datetime, 0, sizeof(*datetime));
    datetime->year = 1900 + tm.tm_year;
    datetime->month = tm.tm_mon + 1;
    datetime->day = tm.tm_mday;
    datetime->sec = tm.tm_sec;
    datetime->micro = tv.tv_usec;
    datetime->timezone = 0;
    datetime->timezone_minutes = 0;
    datetime->hour = tm.tm_hour;
    datetime->min = tm.tm_min;
}

static void cb_push_on_change() {
    if(!push_ctx)
        return;

    fprintf(stderr, "generic-dp: pushing subid: %d\n", push_ctx->subid);
    struct confd_datetime time;
    confd_tag_value_t tv1[1], tv2[1];
    getdatetime(&time);
    struct confd_data_edit edits[2];

    // Allocate and initialize an edit
    struct confd_data_edit *ed1 =
        (struct confd_data_edit *) malloc(sizeof(struct confd_data_edit));
    *ed1 = CONFD_DATA_EDIT();
    ed1->edit_id = "dp-edit-1";
    ed1->op = CONFD_DATA_REPLACE;
    CONFD_DATA_EDIT_SET_PATH(ed1, target,
        "/if:interfaces/interface{eth%d}/enabled", 0);
    int i = 0;
    /* Replace the enabled value of eth0 */
    /*   <enabled>true</enabled> */
    CONFD_SET_TAG_BOOL(&tv1[i++], if_interface_enabled, 1);
    ed1->data = tv1;
    ed1->ndata = i;
    edits[0] = *ed1;

    struct confd_data_edit ed2 = CONFD_DATA_EDIT();
    ed2.edit_id = "dp-edit-2";
    ed2.op = CONFD_DATA_REPLACE;
    CONFD_DATA_EDIT_SET_PATH((&ed2), target,
        "/if:interfaces/interface{eth%d}/oper-status", 1);
    i = 0;
    /* Replace the oper-status value of eth1 */
    /*   <oper_status>dormant</oper_status> */
    CONFD_SET_TAG_ENUM_VALUE(&tv2[i++], if_oper_status, if_dormant);
    ed2.data = tv2;
    ed2.ndata = i;
    edits[1] = ed2;

    struct confd_data_patch *patch =
        (struct confd_data_patch *) malloc(sizeof(struct confd_data_patch));
    *patch = CONFD_DATA_PATCH(), /* Init patch with zeroes */
    patch->patch_id = "first-patch";
    patch->comment = "An example patch from data provider.";
    patch->edits = edits;
    patch->nedits = 2;
    /* Patch is incomplete and
     * we want ConfdD to buffer dampened patches to be sent after
     * dampening period */
    patch->flags = CONFD_PATCH_FLAG_INCOMPLETE |
        CONFD_PATCH_FLAG_BUFFER_DAMPENED;
    confd_push_on_change(push_ctx, &time, patch);
    free(ed1);
    free(patch);
}
/* end YANG-Push example PUSH ON-CALLBACKS*/
/* ------------------------------------------------------------------------ */


void register_data_cb(struct confd_daemon_ctx *dctx, char **callpoints)
{
    struct confd_data_cbs dcb;
    char **cp;
    int i;

    assert(dctx);
    memset(&dcb, 0, sizeof(dcb));
    dcb.flags |= CONFD_DATA_WANT_FILTER;
    dcb.exists_optional = cb_exists_optional;
    if (!opt_bulk_only) {
        dcb.get_elem = cb_get_elem;
        dcb.get_next = cb_get_next;
    }
    if (opt_find_next) {
        dcb.find_next = cb_find_next;
    }
    dcb.get_case = cb_get_case;
    dcb.get_attrs = cb_get_attrs;
    if (opt_accumulate) {
        dcb.set_elem = cb_accumulate2;
        dcb.create = cb_accumulate1;
        dcb.remove = cb_accumulate1;
        dcb.set_case = cb_accumulate3;
        dcb.move_after = cb_accumulate2;
        dcb.set_attr = cb_accumulate4;
    } else {
        dcb.set_elem = cb_set_elem;
        dcb.create = cb_create;
        dcb.remove = cb_remove;
        dcb.set_case = cb_set_case;
        dcb.move_after = cb_move_after;
        dcb.set_attr = cb_set_attr;
    }
    dcb.num_instances = cb_num_instances;
    if (opt_get_object) {
        dcb.get_object = cb_get_object;
    }
    if (opt_get_next_object == 1) {
        dcb.get_next_object = cb_get_next_object;
    }
    if (opt_get_next_object > 1) {
        dcb.get_next_object = cb_get_next_objects;
    }
    if (opt_find_next_object == 1) {
        dcb.find_next_object = cb_find_next_object;
    }
    if (opt_find_next_object > 1) {
        dcb.find_next_object = cb_find_next_objects;
    }

    for (cp = callpoints, i = 0; *cp; cp++, i++) {
        strcpy(dcb.callpoint, *cp);
        dcb.cb_opaque = &cb_stat[i];
        cb_stat[i].callpoint = *cp;
        confd_register_data_cb(dctx, &dcb);
        if (debuglevel > CONFD_SILENT)
            fprintf(stderr, "%s: registered %s\n", progname, *cp);
    }
}

void register_yang_push_cb(struct confd_daemon_ctx *dctx, char **callpoints)
{
    struct confd_push_on_change_cbs pcb;
    char **cp;
    int i;

    assert(dctx);
    memset(&pcb, 0, sizeof(pcb));

    pcb.fd = workersock;
    pcb.subscribe_on_change = cb_subscribe_on_change;
    pcb.unsubscribe_on_change = cb_unsubscribe_on_change;
    pcb.cb_opaque = NULL;

    for (cp = callpoints, i = 0; *cp; cp++, i++) {
        strcpy(pcb.callpoint, *cp);

        if (confd_register_push_on_change(dctx, &pcb) != CONFD_OK) {
            confd_fatal("Couldn't register push on change %s\n", pcb.callpoint);
        }

        if (debuglevel > CONFD_SILENT)
            fprintf(stderr, "%s: registered push on %s\n", progname, *cp);
    }
}

/* ------------------------------------------------------------------------ */

static int tr_commit(struct confd_trans_ctx *tctx)
{
    struct confd_tr_item *item = tctx->accumulated;
    while (opt_accumulate && item) {
        switch (item->op) {
        case C_SET_ELEM:
            kp_set_node_value(&root, item->hkp, item->val);
            break;
        case C_CREATE:
            maybe_pre_create_leaf_lists(
                kp_find_or_create_node(&root, item->hkp));
            break;
        case C_REMOVE:
        {
            node_t *p = NULL;
            node_t *n = kp_find_node(&root, item->hkp, &p);
            if (p && n) { cl_delete(p, n); }
            break;
        }
        case C_SET_CASE:
            cb_set_case(tctx, item->hkp, item->choice, item->val);
            break;
        case C_MOVE_AFTER:
            cb_move_after(tctx, item->hkp, item->val);
            break;
        case C_SET_ATTR:
            cb_set_attr(tctx, item->hkp, item->attr, item->val);
            break;
        default:
            assert(0);
        }
        item = item->next;
    }
    if (debuglevel > CONFD_SILENT) { dbgprint(); }
    return CONFD_OK;
}

static int tr_init(struct confd_trans_ctx *tctx)
{
    confd_trans_set_fd(tctx, workersock);
    return CONFD_OK;
}

static int tr_ok(struct confd_trans_ctx *tctx)
{
    return CONFD_OK;
}

static int tr_finish(struct confd_trans_ctx *tctx)
{
    struct next_data *tmp;
    struct next_data *nd = (struct next_data *) tctx->t_opaque;
    while (nd) {
        confd_free_list_filter(nd->f);
        tmp = nd;
        nd = nd->next;
        free(tmp);
    }
    return CONFD_OK;
}

void register_trans_callback(struct confd_daemon_ctx *dctx)
{
    struct confd_trans_cbs tcb;
    assert(dctx);
    memset(&tcb, 0, sizeof(tcb));
    tcb.init = tr_init;
    if (getenv("NO_TRANS_CBS") == NULL) {
        tcb.write_start = tr_ok;
        tcb.prepare = tr_ok;
        tcb.abort = tr_ok;
        tcb.commit = tr_commit;
        tcb.finish = tr_finish;
    }

    confd_register_trans_cb(dctx, &tcb);
}


/* ------------------------------------------------------------------------ */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>

static struct confd_daemon_ctx *dctx = NULL;

static int connect_confd(struct sockaddr_in *addr)
{
    dctx = confd_init_daemon(progname);

    if (daemon_flags != 0)
        confd_set_daemon_flags(dctx, daemon_flags);

    if ((ctlsock = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
        fprintf(stderr, "Failed to open ctlsocket\n");
        return -1;
    }
    if (confd_connect(dctx, ctlsock, CONTROL_SOCKET, (struct sockaddr*)addr,
                      sizeof (struct sockaddr_in)) < 0) {
        close(ctlsock);
        fprintf(stderr, "Failed to confd_connect() to confd \n");
        return -1;
    }

    if ((workersock = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
        close(ctlsock);
        fprintf(stderr, "Failed to open workersocket\n");
        return -1;
    }
    if (confd_connect(dctx, workersock, WORKER_SOCKET,(struct sockaddr*)addr,
                      sizeof (struct sockaddr_in)) < 0) {
        close(ctlsock);
        close(workersock);
        fprintf(stderr, "Failed to confd_connect() to confd \n");
        return -1;
    }

    register_trans_callback(dctx);
    register_data_cb(dctx, callpoints);

    if (opt_yang_push == 1) {
        register_yang_push_cb(dctx, callpoints);
    }

    if (confd_register_done(dctx) != CONFD_OK) {
        fprintf(stderr, "Failed to complete registration \n");
        close(ctlsock);
        close(workersock);
        return -1;
    }

    return 1;
}

static void reconnect_confd(struct sockaddr_in *addr)
{
    int i;

    close(workersock);
    close(ctlsock);
    confd_release_daemon(dctx);
    for (i = 0; i < opt_reconnect && connect_confd(addr) < 0; i++) {
        confd_release_daemon(dctx);
        sleep(1);
    }
    if (i == opt_reconnect) {
        confd_fatal("Giving up on reconnect after %d attempts\n", i);
    }
}

int main(int argc, char *argv[])
{
    int o;
    struct sockaddr_in addr;
    struct sockaddr_in myname;
    int lsock;
    int on = 1;

    /* Setup progname (without path component) */
    if ((progname = strrchr(argv[0], (int)'/')) == NULL)
        progname = argv[0];
    else
        progname++;

    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    {
        char *port = getenv("CONFD_IPC_PORT");
        if (port) {
            addr.sin_port = htons(atoi(port));
        } else {
            addr.sin_port = htons(CONFD_PORT);
        }
    }

    while ((o = getopt(argc, argv, "dfmp:oO:hbFG:lLBCHr:Y")) != -1) {
        switch (o) {
        case 'd':
            debuglevel++;
            break;
        case 'o':
            opt_get_object = 1;
            break;
        case 'O':
            opt_get_next_object = atoi(optarg);
            break;
        case 'b':
            opt_bulk_only = 1;
            break;
        case 'F':
            opt_find_next = 1;
            break;
        case 'G':
            opt_find_next_object = atoi(optarg);
            break;
        case 'f':
            opt_foreground = 1;
            break;
        case 'L':
            opt_leaf_list_leaf = 1;
            daemon_flags |= CONFD_DAEMON_FLAG_LEAF_LIST_AS_LEAF;
            break;
        case 'l':
            opt_use_clist = 1;
            break;
        case 'B':
            daemon_flags |= CONFD_DAEMON_FLAG_PREFER_BULK_GET;
            break;
        case 'C':
            daemon_flags |= CONFD_DAEMON_FLAG_BULK_GET_CONTAINER;
            break;
        case 'm':
            opt_load_schemas = !(opt_load_schemas);
            break;
        case 'p':
            addr.sin_port = htons(atoi(optarg));
            break;
        case 'r':
            opt_reconnect = atoi(optarg);
            if (opt_reconnect == 0) {
                /* interpreted as "infinite" (almost) */
                opt_reconnect = 999999999;
            }
            break;
        case 'H':
            opt_honor_filter = !(opt_honor_filter);
            break;
        case 'Y':
            opt_yang_push = !(opt_yang_push);
            break;
        case 'h':
            printf("usage: generic-dp [options] callpoint...\n");
            exit(0);
        default:
            printf("-h for usage\n");
            exit(1);
        }
    }
    if (opt_bulk_only && !opt_get_object && opt_get_next_object == 0) {
        printf("need -o and -O with -b\n");
        printf("-h for usage\n");
        exit(1);
    }
    if (opt_leaf_list_leaf && opt_use_clist) {
        fprintf(stderr, "Options L and l are mutually exclusive. Aborting!\n");
        printf("-h for usage\n");
        exit(1);
    }

    do_pre_create_leaf_lists =
        opt_use_clist &&
        (opt_get_object || opt_get_next_object > 0 || opt_find_next_object > 0);

    argc -= optind;
    argv += optind;

    confd_init(progname, stderr, debuglevel);

    if (argc > 0) {
        int i;
        for (i=0; i<argc; i++) {
            callpoints[i] = argv[i];
        }
        cb_stat = (struct cb_stat *)calloc(i, sizeof(struct cb_stat));
        n_cb_stat = i;
        callpoints[i] = NULL;
    } else {
        fprintf(stderr, "callpoints?\n");
        exit(1);
    }

    if (opt_load_schemas) {
        if (confd_load_schemas((struct sockaddr*)&addr,
                               sizeof (struct sockaddr_in)) != CONFD_OK) {
            fprintf(stderr, "Failed to load schemas from confd\n");
            return -1;
        }
    }

    if (connect_confd(&addr) < 0) {
        confd_fatal("Failed to connect to confd\n");
    }

    maybe_init_pre_create_leaf_lists();

    if (!opt_foreground) {
        if (fork()) {
            exit(0);
        }
    } else {
        printf("%s: started\n", progname);
    }

    // Now setup our socket to control this dp

    if ((lsock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
        confd_fatal("Failed to open listen socket\n");

    memset(&myname, 0, sizeof(myname));
    myname.sin_family = AF_INET;
    myname.sin_port = htons(9999);
    myname.sin_addr.s_addr = inet_addr("127.0.0.1");
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if (bind(lsock, (struct sockaddr*)&myname, sizeof(myname) ) < 0 )
        confd_fatal("Failed to bind listen socket\n");

    listen(lsock, 5);

    for (;;) {
        struct pollfd pfds[3];
        int ret;

        pfds[0].fd = ctlsock;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = workersock;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;
        pfds[2].fd = lsock;
        pfds[2].events = POLLIN;
        pfds[2].revents = 0;

        poll(pfds, 3, -1);

        if (pfds[0].revents & POLLIN) {
            if ((ret = confd_fd_ready(dctx, ctlsock)) == CONFD_EOF) {
                if (opt_reconnect) {
                    reconnect_confd(&addr);
                    continue;
                } else {
                    confd_fatal("%s: Control socket closed\n", progname);
                }
            } else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
                if (opt_reconnect) {
                    reconnect_confd(&addr);
                    continue;
                } else {
                    confd_fatal("%s: Error on control socket request: "
                                "%s (%d): %s\n", progname,
                                confd_strerror(confd_errno), confd_errno,
                                confd_lasterr());
                }
            }
        }
        if (pfds[1].revents & POLLIN) {
            if ((ret = confd_fd_ready(dctx, workersock)) == CONFD_EOF) {
                if (opt_reconnect) {
                    reconnect_confd(&addr);
                    continue;
                } else {
                    confd_fatal("%s: Worker socket closed\n", progname);
                }
            } else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
                if (opt_reconnect) {
                    reconnect_confd(&addr);
                    continue;
                } else {
                    confd_fatal(
                        "%s: Error on worker socket request: %s (%d): %s\n",
                        progname, confd_strerror(confd_errno),
                        confd_errno, confd_lasterr());
                }
            }
        }
        if (pfds[2].revents & POLLIN) { // someone is connecting to us
            int asock = accept(lsock, 0,  0);
            char buf[BUFSIZ];
            char *startbuf = "BEGIN\n";

            // write a welcome message
            write(asock, startbuf, strlen(startbuf));

            if (read (asock, buf, BUFSIZ)  <= 0) {
                fprintf(stderr, "bad ctl read");
                exit(1);
            }
            fprintf(stderr, "generic-dp: received nc call: %c\n", buf[0]);
            switch (buf[0]) {
            case 'g': { // get counters
                int i, j, n;
                struct cb_stat *s;

                for (i = 0; i < n_cb_stat; i++) {
                    s = &cb_stat[i];
                    for (j = 0; j < N_CB; j++) {
                        n = snprintf(buf, BUFSIZ, "%s %s %d\n",
                                     s->callpoint,
                                     cb_names[j],
                                     s->cb_counters[j]);
                        write(asock, buf, n);
                    }
                }
                close(asock);
                break;
            }
            case 'c': { // clear counters
                int i, j;
                struct cb_stat *s;

                for (i = 0; i < n_cb_stat; i++) {
                    s = &cb_stat[i];
                    for (j = 0; j < N_CB; j++) {
                        s->cb_counters[j] = 0;
                    }
                }
                close(asock);
                break;
            }
            case 'p': {
                cb_push_on_change();
                close(asock);
                break;
            }
            }
        }


    }
}
