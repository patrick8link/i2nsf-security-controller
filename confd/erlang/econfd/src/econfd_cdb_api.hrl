%%%-------------------------------------------------------------------
%%% @copyright 2005 Tail-F Systems AB
%%% @version {$Id$}
%%% @doc CDB external api definitions
%%%-------------------------------------------------------------------

%% OP is a 32-bit word, leftmost bit is a flag which, if set, means that any
%% keypath in the argument is *relative* to current keypath position.
%%
%%     +-------------------------------------+
%%     | F | OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO |
%%     +-------------------------------------+
%%

%%- COMMON START

-define(OP_MASK, 16#7fffffff).

-define(OP_CLIENT_NAME,   0).
-define(OP_NEW_SESSION,   1).
-define(OP_END_SESSION,   2).
-define(OP_SET_NAMESPACE, 3).
-define(OP_GET,           4).
-define(OP_CD,            5).
-define(OP_PUSHD,         6).
-define(OP_POPD,          7).
-define(OP_EXISTS,        8).
-define(OP_NUM_INSTANCES, 9).
-define(OP_GETCWD,       10).
-define(OP_GET2,         11).
-define(OP_GET_OBJECT,   12).
-define(OP_GET_OBJECTS,  13).
-define(OP_GET_VALUES,   14).
-define(OP_KEY_INDEX,    15).
-define(OP_NXT_INDEX,    16).
-define(OP_GET_CASE,     17).
-define(OP_IS_DEFAULT,   18).
-define(OP_CLIENT_INFO,   19).

-define(OP_SUBSCRIBE,      32).
-define(OP_SUB_EVENT,      33).
-define(OP_SYNC_SUB,       34).
-define(OP_UNSUBSCRIBE,    35).
-define(OP_SUB_ITERATE,    36).
-define(OP_SUBSCRIBE_DONE, 37).
-define(OP_OPER_SUBSCRIBE, 38).
-define(OP_SUB_PROGRESS,   39).
-define(OP_GET_MODIFICATIONS, 40).
-define(OP_GET_CLI,        41).

-define(OP_SET_ELEM,      48).
-define(OP_SET_ELEM2,     49).
-define(OP_CREATE,        50).
-define(OP_DELETE,        51).
-define(OP_SET_OBJECT,    52).
-define(OP_SET_VALUES,    53).
-define(OP_SET_CASE,      54).

-define(OP_WAIT_START,    64).
-define(OP_GET_PHASE,     65).
-define(OP_GET_TXID,      66).
-define(OP_GET_USER_SESSION, 67).
-define(OP_TRIGGER_SUBS,  68).
%% removed from server
%% -define(OP_LOAD_FILE,     69).
-define(OP_GET_TRANS_TID, 70).
-define(OP_REPLAY_SUBS,   71).
-define(OP_GET_REPLAY_TXID, 72).
-define(OP_SET_TIMEOUT,   73).
-define(OP_MANDATORY_SUBSCRIBER,   74).
-define(OP_TRIGGER_OPER_SUBS, 75).
-define(OP_INITIATE_COMPACTION, 76).
%% removed from server
%% -define(OP_LOAD_STRING,   77).
-define(OP_GET_MOUNT_ID,  78).
-define(OP_GET_ATTRS, 79).
-define(OP_SET_ATTR, 80).


-define(REL_FLAG_MASK,  16#80000000).
-define(ERROR_FLAG_MASK, ?REL_FLAG_MASK).

-define(OP(I), ((I) band ?OP_MASK)).
-define(IS_REL(I), (((I) band ?REL_FLAG_MASK) == ?REL_FLAG_MASK)).
-define(IS_WOP(O), ((?OP(O) >= ?OP_SET_ELEM) and (?OP(O) =< ?OP_SET_VALUES))).

-define(REPLY_IS_ERROR(I), (((I) band ?ERROR_FLAG_MASK) == ?ERROR_FLAG_MASK)).
%%- COMMON END

-define(SYNC_DONE_PRIORITY,    1).
-define(SYNC_DONE_SOCKET,      2).
-define(SYNC_DONE_TRANSACTION, 3).
-define(SYNC_DONE_OPERATIONAL, 4).
-define(SYNC_ABORT,            5).

%% keep in sync with confd_lib.h.in
-define(ITER_WANT_PREV,            (1 bsl 0)).
-define(ITER_WANT_ANCESTOR_DELETE, (1 bsl 1)).
-define(ITER_WANT_CLI_STR,         (1 bsl 3)).
-define(ITER_WANT_SCHEMA_ORDER,    (1 bsl 4)).
-define(ITER_WANT_LEAF_FIRST_ORDER,(1 bsl 5)).
-define(ITER_WANT_LEAF_LAST_ORDER, (1 bsl 6)).
-define(ITER_WANT_REVERSE,         (1 bsl 7)).
-define(ITER_WANT_LEAF_LIST_AS_LEAF,(1 bsl 9)).
-define(ITER_WANT_CLI_ORDER,       (1 bsl 10)).

%% flags for cdb_subscribe(), keep in sync with confd_cdb.h
-define(CDB_SUB_WANT_ABORT_ON_ABORT, (1 bsl 0)).

%% keep in sync with confd_cdb.h
-define(CDB_SUB_FLAG_IS_LAST, (1 bsl 0)).
-define(CDB_SUB_FLAG_TRIGGER, (1 bsl 1)).
-define(CDB_SUB_FLAG_REVERT,  (1 bsl 2)).
-define(CDB_SUB_FLAG_HA_SYNC, (1 bsl 3)).
-define(CDB_SUB_FLAG_HA_IS_SECONDARY, (1 bsl 4)).

%% keep in sync with confd_cdb.h
-define(CDB_GET_MODS_INCLUDE_LISTS,         (1 bsl 0)).
-define(CDB_GET_MODS_REVERSE,               (1 bsl 1)).
-define(CDB_GET_MODS_SUPPRESS_DEFAULTS,     (1 bsl 2)).
-define(CDB_GET_MODS_CLI_NO_BACKQUOTES,     (1 bsl 3)).
-define(CDB_GET_MODS_INCLUDE_MOVES,         (1 bsl 4)).
-define(CDB_GET_MODS_WANT_ANCESTOR_DELETE,  (1 bsl 5)).

%% keep in sync with confd_cdb.h
-define(CDB_LOCK_WAIT,     (1 bsl 0)).
-define(CDB_LOCK_SESSION,  (1 bsl 1)).
-define(CDB_LOCK_REQUEST,  (1 bsl 2)).
-define(CDB_LOCK_PARTIAL,  (1 bsl 3)).

-record(cdb_agent, {id :: pid()
                        | %% OTP registration support
                          {via, module(), atom()}
                   }).
-type cdb_agent() :: #cdb_agent{}.

%% current db we want to access
-record(cdb_access,
        {db     :: cdb:db_name(),
         method :: cdb_agent()
                 | cdb_capi:trans_db()
                 | cdb_capi:mix_db()
        }).

-define(AGENTS_TABLE, cdb_agent_list).

%%% test for nmda operational data in cdb-oper
-define(CS_IS_NMDA_OPER(Cs),
        ((Cs#cs.dbm == cdb andalso Cs#cs.dba /= [])
         orelse
         (Cs#cs.oper_dbm == cdb andalso Cs#cs.oper_dba /= []))).
%%% test for nmda operational config false data in cdb-oper
-define(CS_IS_NMDA_OPER_CONFIG_FALSE(Cs),
        (Cs#cs.dbm == cdb andalso Cs#cs.dba /= [])).
%%% test for nmda operational config true data in cdb-oper
-define(CS_IS_NMDA_OPER_CONFIG(Cs),
        (Cs#cs.oper_dbm == cdb andalso Cs#cs.oper_dba /= [])).
