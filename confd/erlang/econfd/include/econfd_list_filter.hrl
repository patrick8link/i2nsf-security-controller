-ifndef(CS_LIST_FILTER_PROTO_HRL).
-define(CS_LIST_FILTER_PROTO_HRL, true).

%% keep in sync with confd_lib.h.in enum confd_list_filter_type
-define(CONFD_LF_OR,     0).
-define(CONFD_LF_AND,    1).
-define(CONFD_LF_NOT,    2).
-define(CONFD_LF_CMP,    3).
-define(CONFD_LF_EXISTS, 4).
-define(CONFD_LF_EXEC,   5).
-define(CONFD_LF_ORIGIN, 6).
-define(CONFD_LF_CMP_LL, 7).

%% keep in sync with otts_nif_node.c not exported to capi
-define(CONFD_LF_CMP_KEY_INDEX, 101).
-define(CONFD_LF_EXEC_KEY_INDEX, 102).

%% keep in sync with confd_lib.h.in enum confd_expr_op
-define(CONFD_CMP_NOP,                   0).
-define(CONFD_CMP_EQ,                    1).
-define(CONFD_CMP_NEQ,                   2).
-define(CONFD_CMP_GT,                    3).
-define(CONFD_CMP_GTE,                   4).
-define(CONFD_CMP_LT,                    5).
-define(CONFD_CMP_LTE,                   6).
%% functions below
-define(CONFD_EXEC_STARTS_WITH,           7).
-define(CONFD_EXEC_RE_MATCH,              8).
-define(CONFD_EXEC_DERIVED_FROM,          9).
-define(CONFD_EXEC_DERIVED_FROM_OR_SELF, 10).

-define(CONFD_INTERNAL_UFLAG_SET,        1000).
-define(CONFD_INTERNAL_UFLAG_CLR,        1001).
-define(CONFD_INTERNAL_HAS_VALUE,        1002).
-define(CONFD_INTERNAL_NOT_EXISTS,       1003).

-endif.
