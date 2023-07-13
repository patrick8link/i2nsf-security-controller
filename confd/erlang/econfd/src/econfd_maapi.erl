%%%-------------------------------------------------------------------
%%% @copyright 2006 Tail-F Systems AB
%%% @version {$Id$}
%%% @doc A n Erlang interface equivalent to the MAAPI C-API
%%%
%%% This modules implements the Management Agent API. All functions in
%%% this module have an equivalent function in the C library.  The
%%% actual semantics of each of the API functions described here is
%%% better described in the man page confd_lib_maapi(3).
%%% @end
%%%-------------------------------------------------------------------

-module(econfd_maapi).

-include("econfd_cdb_api.hrl").
-include("econfd_internal.hrl").
-include("../include/econfd.hrl").
-include("../include/econfd_errors.hrl").
-undef(MAAPI_UPGRADE_KILL_ON_TIMEOUT).
-undef(MAAPI_FLAG_HINT_BULK).
-undef(MAAPI_FLAG_NO_DEFAULTS).
-undef(MAAPI_FLAG_CONFIG_ONLY).
-undef(MAAPI_FLAG_HIDE_INACTIVE).
-undef(MAAPI_FLAG_DELAYED_WHEN).
-undef(MAAPI_FLAG_RUN_SET_HOOKS).
-include("econfd_maapi_proto.hrl").

-import(econfd_cdb, [parse_keystring/1]).


-export([connect/2,
         start_user_session/6,
         start_user_session/7,
         start_user_session/8,
         close/1,
         end_user_session/1,
         get_running_db_status/1,
         set_running_db_status/2,
         kill_user_session/2,
         get_my_user_session_id/1,
         install_crypto_keys/1,
         attach/3,
         attach2/4,
         attach_init/1,
         detach/2,
         authenticate/4,
         authenticate2/8,
         get_user_sessions/1,
         set_user_session/2,
         get_user_session/2,
         get_authorization_info/2,
         lock/2,
         unlock/2,
         is_lock_set/2,
         lock_partial/3,
         unlock_partial/2,
         candidate_validate/1,
         delete_config/2,
         candidate_commit/1,
         candidate_commit/2,
         candidate_commit_info/3,
         candidate_commit_info/4,
         candidate_abort_commit/1,
         candidate_abort_commit/2,
         confirmed_commit_in_progress/1,
         candidate_confirmed_commit/2,
         candidate_confirmed_commit/4,
         candidate_confirmed_commit_info/4,
         candidate_confirmed_commit_info/6,
         candidate_reset/1,
         copy_running_to_startup/1,
         is_running_modified/1,
         is_candidate_modified/1,
         start_trans/3,
         start_trans/4,
         start_trans/5,
         start_trans_in_trans/4,
         start_trans_in_trans/5,
         set_flags/3,
         set_delayed_when/3,
         set_label/3,
         set_comment/3,
         finish_trans/2,
         apply_trans/3,
         apply_trans/4,
         ncs_apply_trans_params/4,
         ncs_get_trans_params/2,
         validate_trans/4,
         prepare_trans/2,
         prepare_trans/3,
         abort_trans/2,
         commit_trans/2,
         get_rollback_id/2,
         list_rollbacks/1,
         load_rollback/3,
         copy/3,
         exists/3,
         num_instances/3,
         create/3,
         shared_create/3,
         delete/3,
         get_elem/3,
         get_object/3,
         get_objects/2,
         get_values/4,
         get_elem_no_defaults/3,
         set_elem/4,
         set_elem2/4,
         shared_set_elem/4,
         shared_set_elem2/4,
         set_object/4,
         set_values/4,
         shared_set_values/4,
         insert/3,
         move/4,
         move_ordered/4,
         copy_tree/4,
         init_cursor/3,
         init_cursor/4,
         get_next/1,
         all_keys/3,
         find_next/3,
         get_case/4,
         get_attrs/4,
         set_attr/5,
         revert/2,
         diff_iterate/4,
         diff_iterate/5,
         keypath_diff_iterate/5,
         keypath_diff_iterate/6,
         iterate/6,
         xpath_eval/7,
         xpath_eval/6,
         xpath_eval_expr/5,
         xpath_eval_expr/4,
         hkeypath2ikeypath/2,
         request_action/3,
         set_readonly_mode/2,
         init_upgrade/3,
         perform_upgrade/2,
         commit_upgrade/1,
         abort_upgrade/1,
         aaa_reload/2,
         snmpa_reload/2,
         start_phase/3,
         wait_start/1,
         wait_start/2,
         reload_config/1,
         netconf_ssh_call_home/3,
         netconf_ssh_call_home_opaque/4,
         stop/1,
         stop/2,
         ncs_apply_template/7,
         ncs_templates/1,
         ncs_template_variables/3,
         ncs_write_service_log_entry/5
        ]).

-export([cli_prompt/4, cli_prompt/5,
         cli_read_eof/3, cli_read_eof/4,
         cli_prompt_oneof/4, cli_prompt_oneof/5,
         cli_write/3]).

-export([sys_message/3, prio_message/3, user_message/4]).

%%% Internal exports
-export([iterate_loop/3]).       % Used by econfd_cdb:diff_iter/5

%%% types

-type err() :: {'error', {integer(), binary()}} | {'error', 'closed'}.
%% Errors can be either
%% <ul><li> {error, Ecode::integer(), Reason::binary()} where Ecode is
%% one of the error codes defined in econfd_errors.hrl, and Reason is
%% (possibly empty) textual description </li>
%% <li> {error, closed} if the socket gets closed </li></ul>

%% Keep this in sync with econfd.hrl
-type proto() :: ?CONFD_PROTO_UNKNOWN |
                 ?CONFD_PROTO_TCP |
                 ?CONFD_PROTO_SSH |
                 ?CONFD_PROTO_SYSTEM |
                 ?CONFD_PROTO_CONSOLE |
                 ?CONFD_PROTO_SSL |
                 ?CONFD_PROTO_HTTP |
                 ?CONFD_PROTO_HTTPS |
                 ?CONFD_PROTO_UDP |
                 ?CONFD_PROTO_TLS.
%% The protocol to start user session can be either<ul>
%% <li> 0 = CONFD_PROTO_UNKNOWN </li>
%% <li> 1 = CONFD_PROTO_TCP </li>
%% <li> 2 = CONFD_PROTO_SSH </li>
%% <li> 3 = CONFD_PROTO_SYSTEM </li>
%% <li> 4 = CONFD_PROTO_CONSOLE </li>
%% <li> 5 = CONFD_PROTO_SSL </li>
%% <li> 6 = CONFD_PROTO_HTTP </li>
%% <li> 7 = CONFD_PROTO_HTTPS </li>
%% <li> 8 = CONFD_PROTO_UDP </li>
%% <li> 9 = CONFD_PROTO_TLS </li></ul>

%% Keep this in sync with econfd.hrl
-type dbname() :: ?CONFD_NO_DB |
                  ?CONFD_CANDIDATE |
                  ?CONFD_RUNNING |
                  ?CONFD_STARTUP |
                  ?CONFD_OPERATIONAL |
                  ?CONFD_PRE_COMMIT_RUNNING |
                  ?CONFD_INTENDED.
%% The DB name can be either<ul>
%% <li> 0 = CONFD_NO_DB </li>
%% <li> 1 = CONFD_CANDIDATE </li>
%% <li> 2 = CONFD_RUNNING </li>
%% <li> 3 = CONFD_STARTUP </li>
%% <li> 4 = CONFD_OPERATIONAL </li>
%% <li> 6 = CONFD_PRE_COMMIT_RUNNING </li>
%% <li> 7 = CONFD_INTENDED </li></ul>
%% Check `maapi_start_trans()' in confd_lib_maapi(3) for detailed information.

%% Keep this in sync with econfd.hrl
-type find_next_type() :: ?CONFD_FIND_NEXT |
                          ?CONFD_FIND_SAME_OR_NEXT.
%% The type is used in {@link find_next/3} can be either<ul>
%% <li> 0 = CONFD_FIND_NEXT </li>
%% <li> 1 = CONFD_FIND_SAME_OR_NEXT </li></ul>
%% Check `maapi_find_next()' in confd_lib_maapi(3) for detailed information.

-type xpath_eval_option() ::
        {'tracefun', term()} |
        {'context', econfd:ikeypath()} |
        {'varbindings', [{Name::string(), ValueExpr::string() | binary()}]} |
        {'root', econfd:ikeypath()}.

-type read_ret() :: 'ok' | {'ok', term()} |
                    {'error', {ErrorCode :: non_neg_integer(),
                               Info :: binary()}} |
                    {'error', econfd:transport_error()}.

-type confd_user_identification() :: #confd_user_identification{}.
-type confd_trans_ctx() :: #confd_trans_ctx{}.
-type confd_user_info() :: #confd_user_info{}.
-type maapi_rollback() :: #maapi_rollback{}.
-type maapi_cursor() :: #maapi_cursor{}.

%%%--------------------------------------------------------------------
%%% External functions
%%%--------------------------------------------------------------------

%% @doc Connect a maapi socket to ConfD.
-spec connect(Address, Port) -> econfd:connect_result() when
      Address :: econfd:ip(),
      Port :: non_neg_integer().
connect(Address, Port) ->
    case econfd_internal:connect(Address, Port, ?CLIENT_MAAPI, []) of
        {ok, Socket} ->
            {ok, Socket};
        Error ->
            Error
    end.

%% @equiv start_user_session(Socket, UserName, Context, Groups, SrcIp, 0, Proto)
-spec start_user_session(Socket, UserName, Context, Groups, SrcIp, Proto) ->
          'ok' | err() when
      Socket :: econfd:socket(),
      UserName :: binary(),
      Context :: binary(),
      Groups :: [binary()],
      SrcIp :: econfd:ip(),
      Proto :: proto().
start_user_session(Socket, UserName, Context, Groups, Ip, Proto) ->
    start_user_session(Socket, UserName, Context, Groups, Ip, 0, Proto).

%% @equiv start_user_session(Socket, UserName, Context, Groups, SrcIp,
%%                           0, Proto, undefined)
-spec start_user_session(Socket, UserName, Context, Groups,
                         SrcIp, SrcPort, Proto) ->
          'ok' | err() when
      Socket :: econfd:socket(),
      UserName :: binary(),
      Context :: binary(),
      Groups :: [binary()],
      SrcIp :: econfd:ip(),
      SrcPort :: non_neg_integer(),
      Proto :: proto().
start_user_session(Socket, UserName, Context, Groups, Ip, Port, Proto) ->
    R = [UserName, {Ip, Port}, ?b2a(Context), Proto, 1 | Groups],
    intcall(Socket, ?MAAPI_START_USER_SESSION, -1, R).

%% @doc Initiate a new maapi user session.
%%
%% returns a maapi session id. Before we can execute any maapi functions
%% we must always have an associated user session.
-spec start_user_session(Socket, UserName, Context, Groups,
                         SrcIp, SrcPort, Proto, UId) ->
          'ok' | err() when
      Socket :: econfd:socket(),
      UserName :: binary(),
      Context :: binary(),
      Groups :: [binary()],
      SrcIp :: econfd:ip(),
      SrcPort :: non_neg_integer(),
      Proto :: proto(),
      UId :: confd_user_identification() | 'undefined'.
start_user_session(Socket, UserName, Context, Groups, Ip, Port, Proto, UId) ->
    R = {UserName, {Ip, Port}, ?b2a(Context), Proto, _UseIKp = true, Groups,
         mk_uident(UId)},
    intcall(Socket, ?MAAPI_START_USER_SESSION, -1, R).

%% @doc Close socket.
-spec close(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
close(Socket) ->
    %% Don't end the user session here, it might be one we got via
    %% attach()/set_user_session()/start_trans()
    %% end_user_session(Socket),
    econfd_internal:close(Socket).

%% @doc Ends a user session.
-spec end_user_session(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
end_user_session(Sock) ->
    intcall(Sock, ?MAAPI_END_USER_SESSION, -1, <<>>).

%% @doc Get the "running status".
-spec get_running_db_status(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: {'ok', Status} | err(),
      Status :: Valid | Invalid,
      Valid :: 1,
      Invalid :: 0.
get_running_db_status(Sock) ->
    intcall(Sock, ?MAAPI_GET_RUNNING_DB_STATUS, -1, <<>>).

%% @doc Set the "running status".
-spec set_running_db_status(Socket, Status) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Status :: Valid | InValid,
      Valid :: 1,
      InValid :: 0.
set_running_db_status(Sock, Status) when is_integer(Status) ->
    intcall(Sock, ?MAAPI_SET_RUNNING_DB_STATUS, -1, Status).

%% @doc Kill a user session.
-spec kill_user_session(Socket, USid) -> 'ok' | err() when
      Socket :: econfd:socket(),
      USid :: integer().
kill_user_session(Sock, UsessID) ->
    intcall(Sock, ?MAAPI_KILL_USER_SESSION, -1, UsessID).

%% @doc Get my user session id.
-spec get_my_user_session_id(Socket) -> Result when
      Socket ::econfd:socket(),
      Result :: {'ok', USid} | err(),
      USid :: integer().
get_my_user_session_id(Sock) ->
    intcall(Sock, ?MAAPI_GET_MY_USER_SESSION, -1, <<>>).

%% @doc Fetch keys for the encrypted data types from the server.
%%
%% Encrypted data type can be tailf:des3-cbc-encrypted-string,
%% tailf:aes-cfb-128-encrypted-string and
%% tailf:aes-256-cfb-128-encrypted-string.
-spec install_crypto_keys(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
install_crypto_keys(Sock) ->
    case intcall(Sock, ?MAAPI_GET_CRYPTO_KEYS, -1, <<>>) of
        {ok, {DesKey1, DesKey2, DesKey3, DesIVec, AesKey, AesIVec}} ->
            des_key(DesKey1, DesKey2, DesKey3, DesIVec),
            aes_key(AesKey, AesIVec),
            ok;
        {ok, {DesKey1, DesKey2, DesKey3, DesIVec, AesKey, AesIVec,Aes256Key}} ->
            des_key(DesKey1, DesKey2, DesKey3, DesIVec),
            aes_key(AesKey, AesIVec),
            aes256_key(Aes256Key),
            ok;
        Err ->
            Err
    end.

des_key(DesKey1, DesKey2, DesKey3, DesIVec) ->
    if is_binary(DesKey1) ->
            ets:insert(confd_installed_crypto_keys,
                       {des3, DesKey1, DesKey2, DesKey3, DesIVec});
       true ->
            ok
    end.

aes_key(AesKey, AesIVec) ->
    if is_binary(AesKey) ->
            ets:insert(confd_installed_crypto_keys,
                       {aes128, AesKey, AesIVec});
       true ->
            ok
    end.

aes256_key(Aes256Key) ->
    if is_binary(Aes256Key) ->
            ets:insert(confd_installed_crypto_keys,
                       {aes256, Aes256Key});
       true ->
            ok
    end.

%% @doc Attach to a running transaction.
%%
%% Give NameSpace as 0 if
%% it doesn't matter (-1 works too but is deprecated).
-spec attach(Socket, Ns, Tctx) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Ns :: econfd:namespace() | 0,
      Tctx :: confd_trans_ctx().
attach(Sock, NameSpace, Tctx) ->
    attach2(Sock, NameSpace, (Tctx#confd_trans_ctx.uinfo)#confd_user_info.usid,
            Tctx#confd_trans_ctx.thandle).

%% @doc Attach to a running transaction. Give NameSpace as 0 if
%% it doesn't matter (-1 works too but is deprecated).
-spec attach2(Socket, Ns, USid, Thandle) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Ns :: econfd:namespace() | 0,
      USid :: integer(),
      Thandle :: integer().
attach2(_Sock, _NameSpace, _Usid, -1) ->
    {error, {?CONFD_ERR_NOEXISTS, <<"-1 is an invalid transaction handle">>}};
attach2(Sock, NameSpace, Usid, Thandle) ->
    R = {NameSpace, Usid, useikp},
    intcall(Sock, ?MAAPI_ATTACH, Thandle, R).

%% @doc Attach to the CDB init/upgrade transaction in phase0.
%%
%% Returns the transaction handle to use in subsequent maapi calls on success.
-spec attach_init(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: {'ok', Thandle} | err(),
      Thandle :: integer().
attach_init(Sock) ->
    InitTh = -2,
    case attach2(Sock, 0, -2, InitTh) of
        ok -> {ok, InitTh};
        Error -> Error
    end.

%% @doc Detach from the transaction.
-spec detach(Socket, Thandle) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Thandle :: integer().
detach(Sock, Thandle) ->
    intcall(Sock, ?MAAPI_DETACH, Thandle, <<>>).

%% @doc Autenticate a user using ConfD AAA.
-spec authenticate(Socket, User, Pass, Groups) -> 'ok' | err() when
      Socket :: econfd:socket(),
      User :: binary(),
      Pass :: binary(),
      Groups :: [binary()].
authenticate(Sock, User, Pass, _Groups) ->
    R = {User, Pass},
    intcall(Sock, ? MAAPI_AUTHENTICATE,-1, R).

%% @doc Autenticate a user using ConfD AAA.
-spec authenticate2(Socket, User, Pass, SrcIp, SrcPort,
                    Context, Proto, Groups) -> 'ok' | err() when
      Socket :: econfd:socket(),
      User :: binary(),
      Pass :: binary(),
      SrcIp :: econfd:ip(),
      SrcPort :: non_neg_integer(),
      Context :: binary(),
      Proto :: integer(),
      Groups :: [binary()].
authenticate2(Sock, User, Pass, SrcAddr, SrcPort, Context, Proto, _Groups) ->
    R = {User, Pass, SrcAddr, SrcPort, Context, Proto},
    intcall(Sock, ? MAAPI_AUTHENTICATE,-1, R).

%% @doc Get all user sessions.
-spec get_user_sessions(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: {'ok', [USid]} | err(),
      USid :: integer().
get_user_sessions(Sock) ->
    intcall(Sock, ?MAAPI_GET_USER_SESSIONS, -1, <<>>).

%% @doc Assign a user session.
-spec set_user_session(Socket, USid) -> 'ok' | err() when
      Socket :: econfd:socket(),
      USid :: integer().
set_user_session(Sock, USid) ->
    intcall(Sock, ?MAAPI_SET_USER_SESSION, -1, {USid, useikp}).

%% @doc Get session info for a user session.
-spec get_user_session(Socket, USid) -> Result when
      Socket :: econfd:socket(),
      USid :: integer(),
      Result :: {'ok', confd_user_info()} | err().
get_user_session(Sock, UsessId) ->
    case intcall(Sock, ?MAAPI_GET_USER_SESSION, -1, UsessId) of
        {ok, {Utuple, LockMode}} ->
            U = econfd:mk_uinfo(Utuple),
            {ok, U#confd_user_info{lockmode = LockMode}};
        Err ->
            Err
    end.

%% @doc Get authorization info for a user session.
-spec get_authorization_info(Socket, USid) -> Result when
      Socket :: econfd:socket(),
      USid :: integer(),
      Result :: {'ok', Info} | err(),
      Info :: {[Group]},
      Group :: binary().
get_authorization_info(Sock, UsessId) ->
    intcall(Sock, ?MAAPI_GET_AUTHORIZATION_INFO, -1, UsessId).

%% @doc Lock a database.
-spec lock(Socket, DbName) -> 'ok' | err() when
      Socket :: econfd:socket(),
      DbName :: dbname().
lock(Sock, DbName) ->
    intcall(Sock, ?MAAPI_LOCK, -1, DbName).

%% @doc Unlock a database.
-spec unlock(Socket, DbName) -> 'ok' | err() when
      Socket :: econfd:socket(),
      DbName :: dbname().
unlock(Sock, DbName) ->
    intcall(Sock, ?MAAPI_UNLOCK, -1, DbName).

%% @doc Check if a db is locked or not.
%%
%% Return 0 or the Usid of the lock owner.
-spec is_lock_set(Socket, DbName) -> Result when
      Socket :: econfd:socket(),
      DbName :: dbname(),
      Result :: {'ok', integer()} | err().
is_lock_set(Sock, DbName) ->
    intcall(Sock, ?MAAPI_IS_LOCK_SET, -1, DbName).

%% @doc Request a partial lock on a database.
%%
%% The set of nodes to lock is specified as a list of XPath expressions.
-spec lock_partial(Socket, DbName, XPath) -> Result when
      Socket :: econfd:socket(),
      DbName :: dbname(),
      XPath :: [binary()],
      Result :: {'ok', LockId} | err(),
      LockId :: integer().
lock_partial(Sock, DbName, XPathList) ->
    intcall(Sock, ?MAAPI_LOCK_PARTIAL, -1, {DbName, XPathList}).

%% @doc Remove the partial lock identified by LockId.
-spec unlock_partial(Socket, LockId) -> 'ok' | err() when
      Socket :: econfd:socket(),
      LockId :: integer().
unlock_partial(Sock, LockId) ->
    intcall(Sock, ?MAAPI_UNLOCK_PARTIAL, -1, LockId).

%% @doc Validate the candidate config.
-spec candidate_validate(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
candidate_validate(Sock) ->
    intcall(Sock, ?MAAPI_CANDIDATE_VALIDATE, -1, <<>>).

%% @doc Delete all data from a data store.
-spec delete_config(Socket, DbName) -> 'ok' | err() when
      Socket :: econfd:socket(),
      DbName :: dbname().
delete_config(Sock, DbName) ->
    intcall(Sock, ?MAAPI_DELETE_CONFIG, -1, DbName).

%% @doc Copies candidate to running or confirms a confirmed commit.
%%
%% @equiv candidate_commit_info(Socket, undefined, <<>>, <<>>)
-spec candidate_commit(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
candidate_commit(Sock) ->
    candidate_commit_info(Sock, undefined, <<>>, <<>>).

%% @doc Confirms persistent confirmed commit.
%%
%% @equiv candidate_commit_info(Socket, PersistId, <<>>, <<>>)
-spec candidate_commit(Socket, PersistId) -> 'ok' | err() when
      Socket :: econfd:socket(),
      PersistId :: binary().
candidate_commit(Sock, PersistId) ->
    candidate_commit_info(Sock, PersistId, <<>>, <<>>).

%% @doc Like {@link candidate_commit/1}, but set the "Label" and/or "Comment"
%% that is stored in the rollback file when the candidate is committed
%% to running.
%%
%% To set only the "Label", give Comment as an empty binary,
%% and to set only the "Comment", give Label as an empty binary.
%%
%% Note: To ensure that the "Label" and/or "Comment" are stored
%% in the rollback file in all cases when doing a confirmed commit,
%% they must be given both with the confirmed commit (using
%% {@link candidate_confirmed_commit_info/4}) and
%% with the confirming commit (using this function).
%%
%% @equiv candidate_commit_info(Socket, undefined, Label, Comment)
-spec candidate_commit_info(Socket, Label, Comment) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Label :: binary(),
      Comment :: binary().
candidate_commit_info(Sock, Label, Comment) ->
    candidate_commit_info(Sock, undefined, Label, Comment).


%% @doc Combines {@link candidate_commit/2} and {@link candidate_commit_info/3}
%% - set "Label" and/or "Comment" when confirming a persistent confirmed commit.
%%
%% Note: To ensure that the "Label" and/or "Comment" are stored
%% in the rollback file in all cases when doing a confirmed commit,
%% they must be given both with the confirmed commit (using
%% {@link candidate_confirmed_commit_info/6}) and
%% with the confirming commit (using this function).
-spec candidate_commit_info(Socket, PersistId, Label, Comment) ->
          'ok' | err() when
      Socket :: econfd:socket(),
      PersistId :: binary() | 'undefined',
      Label :: binary(),
      Comment :: binary().
candidate_commit_info(Sock, PersistId, Label, Comment) ->
    intcall(Sock,  ?MAAPI_CANDIDATE_COMMIT, -1, {PersistId, Label, Comment}).

%% @doc Copy candidate into running, but rollback if not confirmed by a
%% call of {@link candidate_commit/1}.
%%
%% @equiv candidate_confirmed_commit_info(Socket, TimeoutSecs,
%%                                        undefined, undefined, <<>>, <<>>)
-spec candidate_confirmed_commit(Socket, TimeoutSecs) -> 'ok' | err() when
      Socket :: econfd:socket(),
      TimeoutSecs::integer().
candidate_confirmed_commit(Sock, TimeoutSecs) ->
    candidate_confirmed_commit_info(Sock, TimeoutSecs, undefined, undefined,
                                    <<>>, <<>>).

%% @doc Starts or extends persistent confirmed commit.
%%
%% @equiv candidate_confirmed_commit_info(Socket, TimeoutSecs,
%%                                        Persist, PersistId, <<>>, <<>>)
-spec candidate_confirmed_commit(Socket, TimeoutSecs, Persist, PersistId) ->
          'ok' | err() when
      Socket :: econfd:socket(),
      TimeoutSecs :: integer(),
      Persist :: binary() | 'undefined',
      PersistId :: binary() | 'undefined'.
candidate_confirmed_commit(Sock, TimeoutSecs, Persist, PersistId) ->
    candidate_confirmed_commit_info(Sock, TimeoutSecs, Persist, PersistId,
                                    <<>>, <<>>).

%% @doc Like {@link candidate_confirmed_commit/2}, but set the "Label"
%% and/or "Comment" that is stored in the rollback file when the
%% candidate is committed to running.
%%
%% To set only the "Label", give
%% Comment as an empty binary, and to set only the "Comment", give Label
%% as an empty binary.
%%
%% Note: To ensure that the "Label" and/or "Comment" are stored in the
%% rollback file in all cases when doing a confirmed commit, they must
%% be given both with the confirmed commit (using this function) and
%% with the confirming commit (using {@link candidate_commit_info/3}).
%%
%% @equiv candidate_confirmed_commit_info(Socket, TimeoutSecs,
%%                                        undefined, undefined, Label, Comment)
-spec candidate_confirmed_commit_info(Socket, TimeoutSecs, Label, Comment) ->
          'ok' | err() when
      Socket :: econfd:socket(),
      TimeoutSecs :: integer(),
      Label :: binary(),
      Comment :: binary().
candidate_confirmed_commit_info(Sock, TimeoutSecs, Label, Comment) ->
    candidate_confirmed_commit_info(Sock, TimeoutSecs, undefined, undefined,
                                    Label, Comment).

%% @doc Combines {@link candidate_confirmed_commit/4} and {@link
%% candidate_confirmed_commit_info/4} - set "Label" and/or "Comment"
%% when starting or extending a persistent confirmed commit.
%%
%% Note: To ensure that the "Label" and/or "Comment" are stored
%% in the rollback file in all cases when doing a confirmed commit,
%% they must be given both with the confirmed commit (using this function)
%% and with the confirming commit (using {@link candidate_commit_info/4}).
-spec candidate_confirmed_commit_info(Socket, TimeoutSecs, Persist, PersistId,
                                      Label, Comment) ->
          'ok' | err() when
      Socket :: econfd:socket(),
      TimeoutSecs :: integer(),
      Persist :: binary() | 'undefined',
      PersistId :: binary() | 'undefined',
      Label :: binary(),
      Comment :: binary().
candidate_confirmed_commit_info(Sock, TimeoutSecs, Persist, PersistId,
                                Label, Comment) ->
    intcall(Sock, ?MAAPI_CANDIDATE_CONFIRMED_COMMIT,  -1,
            {TimeoutSecs, Persist, PersistId, Label, Comment}).

%% @equiv candidate_abort_commit(Socket, <<>>)
-spec candidate_abort_commit(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
candidate_abort_commit(Sock) ->
    intcall(Sock,  ?MAAPI_CANDIDATE_ABORT_COMMIT, -1, <<>>).

%% @doc Cancel persistent confirmed commit.
-spec candidate_abort_commit(Socket, PersistId) -> 'ok' | err() when
      Socket :: econfd:socket(),
      PersistId :: binary().
candidate_abort_commit(Sock, PersistId) ->
    intcall(Sock,  ?MAAPI_CANDIDATE_ABORT_COMMIT, -1, PersistId).

%% @doc Is a confirmed commit in progress.
-spec confirmed_commit_in_progress(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: {'ok', boolean()} | err().
confirmed_commit_in_progress(Sock) ->
    ibool(intcall(Sock,  ?MAAPI_CONFIRMED_COMMIT_IN_PROGRESS, -1, <<>>)).

%% @doc Copy running into candidate.
-spec candidate_reset(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
candidate_reset(Sock) ->
    intcall(Sock, ?MAAPI_CANDIDATE_RESET, -1, <<>>).

%% @doc Copy running to startup.
-spec copy_running_to_startup(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
copy_running_to_startup(Sock) ->
    intcall(Sock, ?MAAPI_COPY_RUNNING_TO_STARTUP, -1, <<>>).

%% @doc Check if running has been modified since
%% the last copy to startup was done.
-spec is_running_modified(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: {'ok', boolean()} | err().
is_running_modified(Sock) ->
    ibool(intcall(Sock, ?MAAPI_IS_RUNNING_MODIFIED, -1, <<>>)).

%% @doc Check if candidate has been modified.
-spec is_candidate_modified(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: {'ok', boolean()} | err().
is_candidate_modified(Sock) ->
    ibool(intcall(Sock, ?MAAPI_IS_CANDIDATE_MODIFIED, -1, <<>>)).

%% @doc Start a new transaction.
-spec start_trans(Socket, DbName, RwMode) -> Result when
      Socket :: econfd:socket(),
      DbName :: dbname(),
      RwMode :: integer(),
      Result :: {'ok', integer()} | err().
start_trans(Sock, DbName, RwMode) ->
    start_trans(Sock, DbName, RwMode, 0, 0, undefined).

%% @doc Start a new transaction within an existing user session.
-spec start_trans(Socket, DbName, RwMode, USid) -> Result when
      Socket :: econfd:socket(),
      DbName :: dbname(),
      RwMode :: integer(),
      USid :: integer(),
      Result :: {'ok', integer()} | err().
start_trans(Sock, DbName, RwMode, Usid) ->
    start_trans(Sock, DbName, RwMode, Usid, 0, undefined).

%% @doc Start a new transaction within an existing user session and/or
%% with flags.
%%
%% See ?MAAPI_FLAG_XXX in econfd.hrl for the available flags.
%% To use the existing user session of the socket, give Usid = 0.
-spec start_trans(Socket, DbName, RwMode, USid, Flags) -> Result when
      Socket :: econfd:socket(),
      DbName :: dbname(),
      RwMode :: integer(),
      USid :: integer(),
      Flags :: non_neg_integer(),
      Result :: {'ok', integer()} | err().
start_trans(Sock, DbName, RwMode, Usid, Flags) ->
    start_trans(Sock, DbName, RwMode, Usid, Flags, undefined).

start_trans(Sock, DbName, RwMode, Usid, Flags, UId) ->
    intcall(Sock, ?MAAPI_START_TRANS, -1,
            {DbName, RwMode, Usid, 1, Flags, mk_uident(UId)}).

%% @doc Start a new transaction with an existing transaction as backend.
%%
%% To use the existing user session of the socket, give Usid = 0.
-spec start_trans_in_trans(Socket, RwMode, USid, Tid) -> Result when
      Socket :: econfd:socket(),
      RwMode :: integer(),
      USid :: integer(),
      Tid :: integer(),
      Result :: {'ok', integer()} | err().
start_trans_in_trans(Sock, RwMode, Usid, Tid) ->
    intcall(Sock, ?MAAPI_START_TRANS, -1,
            {trintr, RwMode, Usid, 1, Tid}).

%% @doc Start a new transaction with an existing transaction as backend.
%%
%% To use the existing user session of the socket, give Usid = 0.
-spec start_trans_in_trans(Socket, RwMode, USid, Tid, Flags) -> Result when
      Socket :: econfd:socket(),
      RwMode :: integer(),
      USid :: integer(),
      Tid :: integer(),
      Flags :: non_neg_integer(),
      Result :: {'ok', integer()} | err().
start_trans_in_trans(Sock, RwMode, Usid, Tid, Flags) ->
    intcall(Sock, ?MAAPI_START_TRANS, -1,
            {trintr, RwMode, Usid, 1, Tid, Flags}).

%% @doc Change flag settings for a transaction.
%%
%% See ?MAAPI_FLAG_XXX in
%% econfd.hrl for the available flags, however ?MAAPI_FLAG_HIDE_INACTIVE
%% and ?MAAPI_FLAG_DELAYED_WHEN cannot be changed after transaction start
%% (but see {@link set_delayed_when/3}).
-spec set_flags(Socket, Tid, Flags) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Flags :: non_neg_integer().
set_flags(Sock, Tid, Flags) ->
    intcall(Sock, ?MAAPI_SET_FLAGS, Tid, Flags).

%% @doc Enable/disable the "delayed when" mode for a transaction.
%%
%% Returns the old setting on success.
-spec set_delayed_when(Socket, Tid, Value) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Value :: boolean(),
      Result :: {'ok', OldValue} | err(),
      OldValue :: boolean().
set_delayed_when(Sock, Tid, Value) ->
    ibool(intcall(Sock, ?MAAPI_SET_DELAYED_WHEN, Tid, bool2int(Value))).

%% @doc Set the "Label" that is stored in the rollback file when a
%% transaction towards running is committed.
-spec set_label(Socket, Tid, Label) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Label :: binary().
set_label(Sock, Tid, Label) ->
    intcall(Sock, ?MAAPI_SET_LABEL, Tid, Label).

%% @doc Set the "Comment" that is stored in the rollback file when a
%% transaction towards running is committed.
-spec set_comment(Socket, Tid, Comment) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Comment :: binary().
set_comment(Sock, Tid, Comment) ->
    intcall(Sock, ?MAAPI_SET_COMMENT, Tid, Comment).

%% @doc Finish a transaction.
-spec finish_trans(Socket, Tid) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer().
finish_trans(Sock, Tid) ->
    intcall(Sock, ?MAAPI_STOP_TRANS, Tid, <<>>).


%% @equiv apply_trans(Socket, Tid, KeepOpen, 0)
-spec apply_trans(Socket, Tid, KeepOpen) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      KeepOpen :: boolean().
apply_trans(Sock, Tid, KeepOpen) ->
    apply_trans(Sock, Tid, KeepOpen, 0).

%% @doc Apply all in the transaction.
%%
%% This is the combination of validate/prepare/commit done in the
%% right order.
-spec apply_trans(Socket, Tid, KeepOpen, Flags) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      KeepOpen :: boolean(),
      Flags :: non_neg_integer().
apply_trans(Sock, Tid, KeepOpen, Flags) ->
    intcall(Sock, ?MAAPI_APPLY_TRANS, Tid, {KeepOpen, Flags}).

%% @doc Apply transaction with commit parameters.
%%
%% This is a version of apply_trans that takes commit parameters in form of
%% a list of tagged values according to the input parameters for
%% rpc prepare-transaction as defined in tailf-netconf-ncs.yang module.
%% The result of this function may include a list of tagged values according to
%% the output parameters of rpc prepare-transaction or output parameters of rpc
%% commit-transaction as defined in tailf-netconf-ncs.yang module.
-spec ncs_apply_trans_params(Socket, Tid, KeepOpen, Params) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      KeepOpen :: boolean(),
      Params :: [econfd:tagval()],
      Result :: 'ok' | {'ok', [econfd:tagval()]} | err().
ncs_apply_trans_params(Sock, Tid, KeepOpen, Params) ->
    intcall(Sock, ?MAAPI_NCS_APPLY_TRANS_PARAMS, Tid, {KeepOpen, Params}).

%% @doc Get transaction commit parameters.
-spec ncs_get_trans_params(Socket, Tid) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Result :: {'ok', [econfd:tagval()]} | err().
ncs_get_trans_params(Sock, Tid) ->
    intcall(Sock, ?MAAPI_NCS_GET_TRANS_PARAMS, Tid, <<>>).

%% @doc Validate the transaction.
-spec validate_trans(Socket, Tid, UnLock, ForceValidation) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      UnLock :: boolean(),
      ForceValidation :: boolean().
validate_trans(Sock, Tid, UnLock, ForceValidation) ->
    intcall(Sock, ?MAAPI_VALIDATE_TRANS,Tid, {UnLock, ForceValidation}).

%% @equiv prepare_trans(Socket, Tid, 0)
-spec prepare_trans(Socket, Tid) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer().
prepare_trans(Sock, Tid) ->
    prepare_trans(Sock, Tid, 0).

%% @doc Prepare for commit.
-spec prepare_trans(Socket, Tid, Flags) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Flags :: non_neg_integer().
prepare_trans(Sock, Tid, Flags) ->
    intcall(Sock, ?MAAPI_PREPARE_TRANS, Tid, Flags).

%% @doc Abort transaction.
-spec abort_trans(Socket, Tid) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer().
abort_trans(Sock, Tid) ->
    intcall(Sock, ?MAAPI_ABORT_TRANS, Tid,<<>>).

%% @doc Commit a transaction.
-spec commit_trans(Socket, Tid) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer().
commit_trans(Sock, Tid) ->
    intcall(Sock, ?MAAPI_COMMIT_TRANS, Tid,<<>>).

%% @doc Get rollback id of commited transaction.
-spec get_rollback_id(Socket, Tid) -> non_neg_integer() | -1 when
      Socket :: econfd:socket(),
      Tid :: integer().
get_rollback_id(Sock, Tid) ->
    case intcall(Sock, ?MAAPI_GET_ROLLBACK_ID, Tid, <<>>) of
        {ok, {_Type, FixedNr}} ->
            FixedNr;
        _ ->
            -1
    end.

%% @doc Get a list of available rollback files.
-spec list_rollbacks(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: {'ok', [maapi_rollback()]} | err().
list_rollbacks(Sock) ->
    case intcall(Sock, ?MAAPI_LIST_ROLLBACK, -1, <<>>) of
        {ok, Rollbacks} ->
            F = fun ({Nr, Creator, Date, Via, FixedNr, Label, Comment}) ->
                        #maapi_rollback{nr = Nr, creator = Creator, date = Date,
                                        via = Via, fixed_nr = FixedNr,
                                        label = Label, comment = Comment};
                    ({Nr, Creator, Date, Via, FixedNr}) ->
                        %% old-style
                        #maapi_rollback{nr = Nr, creator = Creator, date = Date,
                                        via = Via, fixed_nr = FixedNr,
                                        label = <<>>, comment = <<>>}
                end,
            {ok, [F(Rollback) || Rollback <- Rollbacks]};
        Err ->
            Err
    end.

%% @doc Load a rollback file.
-spec load_rollback(Socket, Tid, Id) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Id :: integer() | {'fixed', integer()}.
load_rollback(Sock, Tid, Id)
  when is_integer(Id);
       (element(1, Id) == fixed andalso is_integer(element(2, Id))) ->
    intcall(Sock, ?MAAPI_LOAD_ROLLBACK, Tid, Id).

%% @doc Copy data from one transaction to another.
-spec copy(Socket, FromTH, ToTH) -> 'ok' | err() when
      Socket :: econfd:socket(),
      FromTH :: integer(),
      ToTH :: integer().
copy(Sock, FromTH, ToTH) ->
    intcall(Sock, ?MAAPI_COPY, FromTH, ToTH).

%% @doc  Check if an element exists.
-spec exists(Socket, Tid, IKeypath) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', boolean()} | err().
exists(Sock, Tid, IKP) ->
    ibool(intcall(Sock, ?MAAPI_EXISTS, Tid, reverse(IKP))).

%% @doc  Find the number of entries in a list.
-spec num_instances(Socket, Tid, IKeypath) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', integer()} | err().
num_instances(Sock, Tid, IKP) ->
    intcall(Sock, ?MAAPI_NUM_INSTANCES, Tid, reverse(IKP)).

%% @doc Create a new element.
-spec create(Socket, Tid, IKeypath) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath().
create(Sock, Tid, IKP) ->
    intcall(Sock, ?MAAPI_CREATE, Tid, reverse(IKP)).

%% @doc Create a new element, and also set an attribute indicating
%% how many times this element has been created.
-spec shared_create(Socket, Tid, IKeypath) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath().
shared_create(Sock, Tid, IKP) ->
    intcall(Sock, ?MAAPI_NCS_SHARED_CREATE, Tid, {_BackP = true, reverse(IKP)}).

%% @doc  Delete an element.
-spec delete(Socket, Tid, IKeypath) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath().
delete(Sock, Tid, IKP) ->
    intcall(Sock, ?MAAPI_DELETE, Tid, reverse(IKP)).

%% @doc Read an element.
-spec get_elem(Socket, Tid, IKeypath) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', econfd:value()} | err().
get_elem(Sock, Tid, IKP) ->
    intcall(Sock, ?MAAPI_GET_ELEM, Tid, reverse(IKP)).

%% @doc Read all the values in a container or list entry.
-spec get_object(Socket, Tid, IKeypath) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', [econfd:value()]} | err().
get_object(Sock, Tid, IKP) ->
    intcall(Sock, ?MAAPI_GET_OBJECT, Tid, reverse(IKP)).

%% @doc Read all the values for NumEntries list entries,
%% starting at the point given by the cursor C.
%%
%% The return value has one
%% Erlang list for each YANG list entry, i.e. it is a list of at most
%% NumEntries lists. If we reached the end of the YANG list,
%% {done, Values} is returned, and there will be fewer than NumEntries
%% lists in Values - otherwise {ok, C2, Values} is returned, where C2
%% can be used to continue the traversal.
-spec get_objects(Cursor, NumEntries) -> Result when
      Cursor :: maapi_cursor(),
      NumEntries :: integer(),
      Result :: {'ok', Cursor, Values} | {'done', Values} | err(),
      Values :: [[econfd:value()]].
get_objects(C, NumEntries) ->
    R = {C#maapi_cursor.prevterm, C#maapi_cursor.ikp,
         C#maapi_cursor.cursor_id, C#maapi_cursor.secondary_index, NumEntries},
    case intcall(C#maapi_cursor.socket, ?MAAPI_GET_OBJECTS,
                 C#maapi_cursor.thandle, R) of
        {ok, {false, Values}} ->
            %% we're done
            {done, Values};
        {ok, {Res, Values}} ->
            {ok, C#maapi_cursor{prevterm = Res}, Values};
        Err ->
            Err
    end.

%% @doc Read the values for the leafs that have the "value" 'not_found'
%% in the Values list.
%%
%% This can be used to read an arbitrary set of
%% sub-elements of a container or list entry. The return value is a list
%% of the same length as Values, i.e. the requested leafs are in the same
%% position in the returned list as in the Values argument. The elements
%% in the returned list are always "canonical" though, i.e. of the form
%% {@link econfd:tagval()}.
-spec get_values(Socket, Tid, IKeypath, Values) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Values :: [econfd:tagval()],
      Result :: {'ok', [econfd:tagval()]} | err().
get_values(Sock, Tid, IKP, Values) ->
    intcall(Sock, ?MAAPI_GET_VALUES, Tid, {Values, reverse(IKP)}).

%% @doc Read an element, but return 'default' instead of the value if
%% the default value is in effect.
%%
%% @deprecated Use set_flags/3 with ?MAAPI_FLAG_NO_DEFAULTS instead - this
%% will take effect for all the functions that read values.
-spec get_elem_no_defaults(Socket, Tid, IKeypath) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', Value} | err(),
      Value :: econfd:value() | 'default'.
get_elem_no_defaults(Sock, Tid, IKP) ->
    intcall(Sock, ?MAAPI_GET_ELEM_NO_DEFAULT, Tid, reverse(IKP)).

%% @doc Write an element.
-spec set_elem(Socket, Tid, IKeypath, Value) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Value :: econfd:value().
set_elem(Sock, Tid, IKP, Val) ->
    intcall(Sock, ?MAAPI_SET_ELEM, Tid, {Val,reverse(IKP)}).

%% @doc Write an element using the textual value representation.
-spec set_elem2(Socket, Tid, IKeypath, BinValue) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      BinValue :: binary().
set_elem2(Sock, Tid, IKP, Val) ->
    intcall(Sock, ?MAAPI_SET_ELEM2, Tid, {Val,reverse(IKP)}).

%% @doc Write an element from NCS FastMap.
-spec shared_set_elem(Socket, Tid, IKeypath, Value) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Value :: econfd:value().
shared_set_elem(Sock, Tid, IKP, Val) ->
    intcall(Sock, ?MAAPI_SHARED_SET_ELEM, Tid, {Val,reverse(IKP)}).

%% @doc Write an element using the textual value representation
%%  from NCS fastmap.
-spec shared_set_elem2(Socket, Tid, IKeypath, BinValue) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      BinValue :: binary().
shared_set_elem2(Sock, Tid, IKP, Val) ->
    intcall(Sock, ?MAAPI_SHARED_SET_ELEM2, Tid, {Val,reverse(IKP)}).

%% @doc Write an entire object, i.e. YANG list entry or container.
-spec set_object(Socket, Tid, IKeypath, ValueList) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      ValueList :: [econfd:value()].
set_object(Sock, Tid, IKP, ValueList) ->
    intcall(Sock, ?MAAPI_SET_OBJECT, Tid, {ValueList, reverse(IKP)}).

%% @doc Write a list of tagged values.
%%
%% This function is an alternative to
%% {@link set_object/4}, and allows for writing more complex structures
%% (e.g. multiple entries in a list).
-spec set_values(Socket, Tid, IKeypath, ValueList) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      ValueList :: [econfd:tagval()].
set_values(Sock, Tid, IKP, ValueList) ->
    intcall(Sock, ?MAAPI_SET_VALUES, Tid, {ValueList, reverse(IKP)}).

%% @doc Write a list of tagged values from NCS FastMap.
-spec shared_set_values(Socket, Tid, IKeypath, ValueList) ->
          'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      ValueList :: [econfd:tagval()].
shared_set_values(Sock, Tid, IKP, ValueList) ->
    intcall(Sock, ?MAAPI_SHARED_SET_VALUES, Tid,
            {{ValueList, _BackP = true}, reverse(IKP)}).

%% @doc Get the current case for a choice.
-spec get_case(Socket, Tid, IKeypath, Choice) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Choice :: econfd:qtag() | [econfd:qtag()],
      Result :: {'ok', Case} | err(),
      Case :: econfd:qtag().
get_case(Sock, Tid, IKP, Choice) ->
    intcall(Sock, ?MAAPI_GET_CASE, Tid,
            {econfd_cdb:choice_path(Choice), reverse(IKP)}).

%% @doc Get the selected attributes for an element.
%%
%% Calling with an empty attribute list returns all attributes.
-spec get_attrs(Socket, Tid, IKeypath, AttrList) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      AttrList :: [Attr],
      Attr :: integer(),
      Result :: {'ok', [{Attr, Value}]} | err(),
      Value :: econfd:value().
get_attrs(Sock, Tid, IKP, AttrL) ->
    intcall(Sock, ?MAAPI_GET_ATTRS, Tid, {AttrL, reverse(IKP)}).

%% @doc Set the an attribute for an element. Value == undefined means
%% that the attribute should be deleted.
-spec set_attr(Socket, Tid, IKeypath, Attr, Value) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Attr :: integer(),
      Value :: econfd:value() | 'undefined'.
set_attr(Sock, Tid, IKP, Attr, Value) ->
    intcall(Sock, ?MAAPI_SET_ATTR, Tid, {{Attr, Value}, reverse(IKP)}).

%% @doc Insert an entry in an integer-keyed list.
-spec insert(Socket, Tid, IKeypath) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath().
insert(Sock, Tid, IKP) ->
    intcall(Sock, ?MAAPI_INSERT, Tid, reverse(IKP)).

%% @doc Move (rename) an entry in a list.
-spec move(Socket, Tid, IKeypath, ToKey) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      ToKey :: econfd:key().
move(Sock, Tid, IKP, ToKey) ->
    intcall(Sock, ?MAAPI_MOVE, Tid, {reverse(IKP),ToKey}).

%% @doc Move an entry in an "ordered-by user" list.
-spec move_ordered(Socket, Tid, IKeypath, To) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      To :: 'first' | 'last' | {'before' | 'after', econfd:key()}.
move_ordered(Sock, Tid, IKP, To) ->
    intcall(Sock, ?MAAPI_MOVE_ORDERED, Tid, {reverse(IKP),To}).

%% @doc Remove all changes in the transaction.
-spec revert(Socket, Tid) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer().
revert(Sock, Tid) ->
    intcall(Sock, ?MAAPI_REVERT, Tid, <<>>).

%% @doc Copy an entire subtree in the configuration from one point to another.
-spec copy_tree(Socket, Tid, FromIKeypath, ToIKeypath) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      FromIKeypath :: econfd:ikeypath(),
      ToIKeypath :: econfd:ikeypath().
copy_tree(Sock, Tid,  From, To) ->
    intcall(Sock, ?MAAPI_COPY_TREE, Tid, {false, reverse(From), reverse(To)}).

%% @doc Utility function. Return all keys in a list.
-spec all_keys(Socket, Tid, IKeypath) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', [econfd:key()]} | err().
all_keys(MaapiSock, Th, IKP) ->
    Cursor = econfd_maapi:init_cursor(MaapiSock, Th, IKP),
    all_keys(Cursor, []).
all_keys(Cursor, Acc) ->
    case econfd_maapi:get_next(Cursor) of
        {ok, Key, C2} ->
            all_keys(C2, [Key | Acc]);
        done ->
            {ok, Acc};
        Err ->
            Err
    end.

%% @equiv init_cursor(Socket, Tik, IKeypath, undefined)
-spec init_cursor(Socket, Tid, IKeypath) -> maapi_cursor() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath().
init_cursor(Sock, Tid, IKP) ->
    init_cursor(Sock, Tid, IKP, undefined).

%% @doc Initalize a get_next() cursor.
-spec init_cursor(Socket, Tid, IKeypath, XPath) -> maapi_cursor() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      XPath :: 'undefined' | binary() | string().
init_cursor(Sock, Tid, IKP, XPath) when is_binary(XPath) ->
    init_cursor(Sock, Tid, IKP, erlang:binary_to_list(XPath));
init_cursor(Sock, Tid, IKP, XPath) ->
    PrevTerm = if XPath == undefined ->
                       first;
                  true ->
                       {first, XPath}
               end,
    #maapi_cursor{ikp = reverse(IKP), isrel = false,
                  socket = Sock, thandle = Tid, prevterm = PrevTerm,
                  cursor_id =  erlang:phash2(make_ref(), 16#10000000)}.

%% @doc iterate through the entries of a list.
-spec get_next(Cursor) -> Result when
      Cursor :: maapi_cursor(),
      Result :: {'ok', econfd:key(), Cursor} | 'done' | err().
get_next(C) ->
    BulkHint = 0,
    R = {C#maapi_cursor.prevterm, C#maapi_cursor.ikp,
         C#maapi_cursor.cursor_id, BulkHint, C#maapi_cursor.secondary_index},
    case intcall(C#maapi_cursor.socket, ?MAAPI_GET_NEXT,
                 C#maapi_cursor.thandle, R) of
        {ok, false} ->
            %% we're done
            done;
        {ok, Res} ->
            Keys = element(2, Res),
            {ok, Keys, C#maapi_cursor{prevterm = Res}};
        Err ->
            Err
    end.

%% @doc find the list entry matching Type and Key.
-spec find_next(Cursor, Type, Key) -> Result when
      Cursor :: maapi_cursor(),
      Type :: find_next_type(),
      Key :: econfd:key(),
      Result :: {'ok', econfd:key(), Cursor} | 'done' | err().
find_next(C, Type, Key) when Type == ?CONFD_FIND_NEXT;
                             Type == ?CONFD_FIND_SAME_OR_NEXT ->
    BulkHint = 0,
    R = {Key, C#maapi_cursor.ikp, C#maapi_cursor.cursor_id,
         Type, BulkHint, C#maapi_cursor.secondary_index},
    case intcall(C#maapi_cursor.socket, ?MAAPI_FIND_NEXT,
                 C#maapi_cursor.thandle, R) of
        {ok, false} ->
            %% we're done
            done;
        {ok, Res} ->
            Keys = element(2, Res),
            {ok, Keys, C#maapi_cursor{prevterm = Res}};
        Err ->
            Err
    end.


%% @equiv diff_iterate(Sock, Tid, Fun, 0, InitState)
diff_iterate(Sock, Tid, Fun, InitState) ->
    diff_iterate(Sock, Tid, Fun, 0, InitState).

%% @doc Iterate through a diff.
%%
%% This function is used in combination with the notifications API
%% where we get a chance to iterate through the diff of a transaction
%% just before it gets commited. The transaction hangs until we have called
%% {@link econfd_notif:notification_done/2}.
%% The function can also be called from within validate() callbacks to
%% traverse a diff while validating.
%% Currently OldValue is always the atom 'undefined'.
%% When Op == ?MOP_MOVED_AFTER (only for "ordered-by user" list entry),
%% Value == {} means that the entry was moved first in the list, otherwise
%% Value is a econfd:key() tuple that identifies the entry it was moved after.
-spec diff_iterate(Socket, Tid, Fun, Flags, State) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Fun :: fun((IKeypath, Op, OldValue, Value, State) ->
                        {ok, Ret, State} | {'error', term()}),
      IKeypath :: econfd:ikeypath(),
      Op :: integer(),
      OldValue :: econfd:value() | 'undefined',
      Value :: econfd:value() | 'undefined' | econfd:key() | {},
      State :: term(),
      Ret :: integer(),
      Flags :: non_neg_integer(),
      Result :: {'ok', State} | {'error', term()}.
diff_iterate(Sock, Tid, Fun, Flags, InitState) ->
    econfd_internal:bin_write(Sock,
                              <<?MAAPI_DIFF_ITER:32, Tid:32, 1:32, Flags:32>>),
    iterate_loop(Sock, Fun, InitState).

%% @doc Iterate through a diff.
%%
%% This function behaves like {@link diff_iterate/5} with the exception that
%% the provided keypath IKP, prunes the tree and only diffs below that
%% path are considered.
-spec keypath_diff_iterate(Socket, Tid, IKeypath, Fun, State) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Fun :: fun((IKeypath, Op, OldValue, Value, State) ->
                        {ok, Ret, State} | {'error', term()}),
      Op :: integer(),
      OldValue :: econfd:value(),
      Value :: econfd:value() | econfd:key(),
      State :: term(),
      Ret :: integer(),
      Result :: {'ok', State} | {'error', term()}.
keypath_diff_iterate(Sock, Tid, IKP, Fun, InitState) ->
    keypath_diff_iterate(Sock, Tid, IKP, Fun, 0, InitState).
keypath_diff_iterate(Sock, Tid, IKP, Fun, Flags, InitState) ->
    Term = {1, Flags, reverse(IKP)},
    B = ?t2b(Term),
    econfd_internal:bin_write(Sock,
                              <<?MAAPI_DIFF_IKP_ITER:32, Tid:32, B/binary>>),
    iterate_loop(Sock, Fun, InitState).

%% @doc Iterate over all the data in the transaction and the underlying
%% data store.
%%
%% Flags can be given as ?MAAPI_ITER_WANT_ATTR to request that
%% attributes (if any) are passed to the Fun, otherwise it should be 0.
%% The possible values for Ret in the return value for Fun are the same
%% as for {@link diff_iterate/5}.
-spec iterate(Socket, Tid, IKeypath, Fun, Flags, State) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      IKeypath :: econfd:ikeypath(),
      Fun :: fun((IKeypath, Value, Attrs, State) ->
                        {ok, Ret, State} | {'error', term()}),
      Value :: econfd:value() | 'undefined',
      Attrs :: [{Attr, Value}] | 'undefined',
      Attr :: integer(),
      State :: term(),
      Ret :: integer(),
      Flags :: non_neg_integer(),
      Result :: {'ok', State} | {'error', term()}.
iterate(Sock, Tid, IKP, Fun, Flags, InitState) ->
    Term = {1, Flags, reverse(IKP)},
    B = ?t2b(Term),
    econfd_internal:bin_write(Sock,
                              <<?MAAPI_ITERATE:32, Tid:32, B/binary>>),
    iterate_loop(Sock, Fun, InitState).

%% @private
iterate_loop(Sock, Fun, State) ->
    case econfd_internal:term_read(Sock, infinity) of
        {ok, {return}} -> {ok, State};
        {ok, {error}} -> {error, noexists};
        {ok, {error, Reason}} -> {error, Reason};
        {ok, {badstate}} -> {error, badstate};
        {ok, {badstate, Reason}} -> {error, {badstate, Reason}};
        {ok, {IKP, Op, OldValue, Value}} ->     % diff_iterate
            Res = try
                      Fun(IKP, Op, OldValue, Value, State)
                  catch
                      Class:Reason:Stacktrace ->
                          econfd_internal:bin_write(Sock, <<?ITER_STOP:32>>),
                          erlang:raise(Class, Reason, Stacktrace)
                  end,
            iterate_result(Sock, Fun, Res);
        {ok, {IKP, Value, Attrs}} ->     % iterate
            Res = try
                      Fun(IKP, Value, Attrs, State)
                  catch
                      Class:Reason:Stacktrace ->
                          econfd_internal:bin_write(Sock, <<?ITER_STOP:32>>),
                          erlang:raise(Class, Reason, Stacktrace)
                  end,
            iterate_result(Sock, Fun, Res);
        Err ->
            Err
    end.

iterate_result(Sock, _Fun, {ok, ?ITER_STOP, State}) ->
    econfd_internal:bin_write(Sock, <<?ITER_STOP:32>>),
    {ok, State};
iterate_result(Sock, Fun, {ok, RetVal, State}) when RetVal == ?ITER_RECURSE;
                                                    RetVal == ?ITER_CONTINUE ->
    econfd_internal:bin_write(Sock, <<RetVal:32>>),
    iterate_loop(Sock, Fun, State);
iterate_result(Sock, _Fun, {error, Reason}) ->
    econfd_internal:bin_write(Sock, <<?ITER_STOP:32>>),
    {error, Reason}.

%% @doc Evaluate the XPath expression Expr, invoking ResultFun for each node
%% in the resulting node set.
%%
%% The possible values for Ret in the
%% return value for ResultFun are ?ITER_CONTINUE and ?ITER_STOP.
%% @deprecated This function is kept for backwards compatibility,
%% use {@link xpath_eval/6}.
-spec xpath_eval(Socket, Tid, Expr, ResultFun, TraceFun, State, Context) ->
          Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Expr :: binary(),
      ResultFun :: fun((IKeypath, Value, State) -> {Ret, State}),
      IKeypath :: econfd:ikeypath(),
      Value :: econfd:value() | 'undefined',
      State :: term(),
      Ret :: integer(),
      TraceFun :: fun((binary()) -> none()) | 'undefined',
      Context :: econfd:ikeypath() | [],
      Result :: {'ok', State} | {'error', term()}.
xpath_eval(Sock, Tid, Expr, ResultFun, TraceFun, InitState, Context) ->
    xpath_eval(Sock, Tid, Expr, ResultFun, InitState,
               [{tracefun,TraceFun},{initstate,InitState},{context, Context}]).

%% @doc Evaluate the XPath expression Expr, invoking ResultFun for each node
%% in the resulting node set.
%%
%% The possible values for Ret in the
%% return value for ResultFun are ?ITER_CONTINUE and ?ITER_STOP.
-spec xpath_eval(Socket, Tid, Expr, ResultFun, State, Options) ->
          Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Expr :: binary() | {'compiled', Source, Compiled},
      Source :: binary(),
      Compiled :: [binary() | tuple()],
      ResultFun :: fun((IKeypath, Value, State) -> {Ret, State}),
      IKeypath :: econfd:ikeypath(),
      Value :: term(),
      State :: term(),
      Ret :: integer(),
      Options :: [xpath_eval_option()],
      Result :: {'ok', State} | err().
xpath_eval(Sock, Tid, Expr, ResultFun, InitState, Options) ->
    TraceFun = proplists:get_value(tracefun,    Options, undefined),
    Context  = proplists:get_value(context,     Options, []),
    LLPos    = proplists:get_value('leaf-list-pos', Options, 0),
    VarBinds = proplists:get_value(varbindings, Options, []),
    Root     = proplists:get_value(root,        Options, undefined),

    R = {Expr, TraceFun /= undefined, reverse(Context), LLPos, VarBinds, Root},
    case intcall(Sock, ?MAAPI_XPATH_EVAL, Tid, R) of
        ok ->
            xpath_eval_loop(Sock, ResultFun, TraceFun, InitState);
        Err ->
            Err
    end.

xpath_eval_loop(Sock, ResultFun, TraceFun, State) ->
    case econfd_internal:term_read(Sock, infinity) of
        {ok, {return}} -> {ok, State};
        {ok, {trace, Str}} ->
            TraceFun(Str),
            xpath_eval_loop(Sock, ResultFun, TraceFun, State);
        {ok, {error, Str}} ->
            {error, {?CONFD_ERR_XPATH, Str}};
        {ok, {IKP, Value}} ->
            case ResultFun(IKP, Value, State) of
                {?ITER_STOP, State2} ->
                    econfd_internal:bin_write(Sock, <<?ITER_STOP:32>>),
                    {ok, State2};
                {?ITER_CONTINUE, State2} ->
                    econfd_internal:bin_write(Sock, <<?ITER_CONTINUE:32>>),
                    xpath_eval_loop(Sock, ResultFun, TraceFun, State2)
            end;
        Err ->
            Err
    end.

%% @doc Evaluate the XPath expression Expr, returning the result as a string.
-spec xpath_eval_expr(Socket, Tid, Expr, TraceFun, Context) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Expr :: binary(),
      TraceFun :: fun((binary()) -> none()) | 'undefined',
      Context :: econfd:ikeypath() | [],
      Result :: {'ok', binary()} | err().
xpath_eval_expr(Sock, Tid, Expr, TraceFun, Context) ->
    xpath_eval_expr(Sock, Tid, Expr, [{tracefun,TraceFun},{context,Context}]).

%% @doc Evaluate the XPath expression Expr, returning the result as a string.
-spec xpath_eval_expr(Socket, Tid, Expr, Options) -> Result when
      Socket :: econfd:socket(),
      Tid :: integer(),
      Expr :: binary() | {'compiled', Source, Compiled},
      Source :: binary(),
      Compiled :: [binary() | tuple()],
      Options :: [xpath_eval_option()],
      Result :: {'ok', binary()} | err().
xpath_eval_expr(Sock, Tid, Expr, Options) ->
    TraceFun = proplists:get_value(tracefun,        Options, undefined),
    Context  = proplists:get_value(context,         Options, []),
    LLPos    = proplists:get_value('leaf-list-pos', Options, 0),
    VarBinds = proplists:get_value(varbindings,     Options, []),
    Root     = proplists:get_value(root,            Options, undefined),

    R = {Expr, TraceFun /= undefined, reverse(Context), LLPos, VarBinds, Root},
    case intcall(Sock, ?MAAPI_XPATH_EVAL_EXPR, Tid, R) of
        ok ->
            xpath_eval_expr_loop(Sock, TraceFun);
        Err ->
            Err
    end.

xpath_eval_expr_loop(Sock, TraceFun) ->
    case econfd_internal:term_read(Sock, infinity) of
        {ok, {ok, Result}} ->
            {ok, Result};
        {ok, {trace, Str}} ->
            TraceFun(Str),
            xpath_eval_expr_loop(Sock, TraceFun);
        {ok, {error, Str}} ->
            {error, {?CONFD_ERR_XPATH, Str}}
    end.

%% @doc Convert a hkeypath to an ikeypath.
%%
%% @deprecated hkeypaths are not used in the erlang API.
-spec hkeypath2ikeypath(Socket, HKeypath) -> Result when
      Socket :: econfd:socket(),
      HKeypath :: [non_neg_integer()],
      Result :: {'ok', IKeypath} | err(),
      IKeypath :: econfd:ikeypath().
hkeypath2ikeypath(Sock, HKP) ->
    intcall(Sock, ?MAAPI_HKP2IKP, -1, HKP).

%% @doc Invoke an action defined in the data model.
-spec request_action(Socket, Params, IKeypath) -> Result when
      Socket :: econfd:socket(),
      Params :: [econfd:tagval()],
      IKeypath :: econfd:ikeypath(),
      Result :: 'ok' | {'ok', [econfd:tagval()]} | err().
request_action(Sock, Params, IKP) ->
    [[Ns|_]|_] = RIKP = reverse(IKP),   % NOTE, must be real reverse
    R = {{exml, Params}, RIKP, Ns},
    intcall(Sock, ?MAAPI_REQUEST_ACTION, -1, R).

%% @doc Prompt CLI user for a reply.
-spec cli_prompt(Socket, USid, Prompt, Echo) -> {'ok', binary()} | err() when
      Socket :: econfd:socket(),
      USid :: integer(),
      Prompt :: binary(),
      Echo :: boolean().
cli_prompt(Sock, Usess, Prompt, Echo) ->
    intcall(Sock, ?MAAPI_CLI_PROMPT, -1,
            {Usess, Prompt, [], Echo, infinity}).

%% @doc Prompt CLI user for a reply - return error if no reply is
%%      received within Timeout seconds.
-spec cli_prompt(Socket, USid, Prompt, Echo, Timeout) ->
          {'ok', binary()} | err() when
      Socket :: econfd:socket(),
      USid :: integer(),
      Prompt :: binary(),
      Echo :: boolean(),
      Timeout :: non_neg_integer().
cli_prompt(Sock, Usess, Prompt, Echo, Timeout) ->
    intcall(Sock, ?MAAPI_CLI_PROMPT, -1,
            {Usess, Prompt, [], Echo, 1000 * Timeout}).

%% @doc Read data from CLI until EOF.
-spec cli_read_eof(Socket, USid, Echo) -> {'ok', binary()} | err() when
      Socket :: econfd:socket(),
      USid :: integer(),
      Echo :: boolean().
cli_read_eof(Sock, Usess, Echo) ->
    intcall(Sock, ?MAAPI_CLI_READ_EOF, -1,
            {Usess, Echo, infinity}).

%% @doc Read data from CLI until EOF - return error if no reply is
%%      received within Timeout seconds.
-spec cli_read_eof(Socket, USid, Echo, Timeout) -> {'ok', binary()} | err() when
      Socket :: econfd:socket(),
      USid :: integer(),
      Echo :: boolean(),
      Timeout :: non_neg_integer().
cli_read_eof(Sock, Usess, Echo, Timeout) ->
    intcall(Sock, ?MAAPI_CLI_READ_EOF, -1,
            {Usess, Echo, 1000 * Timeout}).

%% @doc Prompt CLI user for a reply.
-spec cli_prompt_oneof(Socket, USid, Prompt, Choice) ->
          {'ok', binary()} | err() when
      Socket :: econfd:socket(),
      USid :: integer(),
      Prompt :: binary(),
      Choice :: binary().
cli_prompt_oneof(Sock, Usess, Prompt, Choice) ->
    intcall(Sock, ?MAAPI_CLI_PROMPT, -1,
            {Usess, Prompt, Choice, true, infinity}).

%% @doc Prompt CLI user for a reply - return error if no reply is
%%      received within Timeout seconds.
-spec cli_prompt_oneof(Socket, USid, Prompt, Choice, Timeout) ->
          {'ok', binary()} | err() when
      Socket :: econfd:socket(),
      USid :: integer(),
      Prompt :: binary(),
      Choice :: binary(),
      Timeout :: non_neg_integer().
cli_prompt_oneof(Sock, Usess, Prompt, Choice, Timeout) ->
    intcall(Sock, ?MAAPI_CLI_PROMPT, -1,
            {Usess, Prompt, Choice, true, 1000 * Timeout}).

%% @doc Write mesage to the CLI.
-spec cli_write(Socket, USid, Message) -> 'ok' | err() when
      Socket :: econfd:socket(),
      USid :: integer(),
      Message :: binary().
cli_write(Sock, Usess, Msg) ->
    intcall(Sock, ?MAAPI_CLI_WRITE, -1,
            {Usess, Msg}).

%% @doc Write system message.
-spec sys_message(Socket, To, Message) -> 'ok' | err() when
      Socket :: econfd:socket(),
      To :: binary(),
      Message :: binary().
sys_message(Sock, To, Msg) ->
    intcall(Sock, ?MAAPI_SYS_MESSAGE, -1,
            {To, Msg}).

%% @doc Write user message.
-spec user_message(Socket, To, From, Message) -> 'ok' | err() when
      Socket :: econfd:socket(),
      To :: binary(),
      From :: binary(),
      Message :: binary().
user_message(Sock, To, From, Msg) ->
    intcall(Sock, ?MAAPI_USER_MESSAGE, -1,
            {To, Msg, From}).

%% @doc Write priority message.
-spec prio_message(Socket, To, Message) -> 'ok' | err() when
      Socket :: econfd:socket(),
      To :: binary(),
      Message :: binary().
prio_message(Sock, To, Msg) ->
    intcall(Sock, ?MAAPI_PRIO_MESSAGE, -1,
            {To, Msg}).

%% @doc Control if we can create rw transactions.
-spec set_readonly_mode(Socket, Mode) -> {'ok', boolean()} | err() when
      Socket :: econfd:socket(),
      Mode :: boolean().
set_readonly_mode(Sock, Mode) ->
    ibool(intcall(Sock, ?MAAPI_SET_READONLY, -1,
                  if (Mode == true) -> 1;
                     true -> 0
                  end)).

%% @doc Start in-service upgrade.
-spec init_upgrade(Socket, TimeoutSecs, Flags) -> 'ok' | err() when
      Socket :: econfd:socket(),
      TimeoutSecs :: integer(),
      Flags :: non_neg_integer().
init_upgrade(Sock, TimeoutSecs, Flags) ->
    R = {TimeoutSecs, Flags},
    intcall(Sock, ?MAAPI_INIT_UPGRADE, -1, R).

%% @doc Do in-service upgrade.
-spec perform_upgrade(Socket, LoadPathList) -> 'ok' | err() when
      Socket :: econfd:socket(),
      LoadPathList :: [binary()].
perform_upgrade(Sock, LoadPathList) ->
    intcall(Sock, ?MAAPI_PERFORM_UPGRADE, -1, LoadPathList).

%% @doc Commit in-service upgrade.
-spec commit_upgrade(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
commit_upgrade(Sock) ->
    intcall(Sock, ?MAAPI_COMMIT_UPGRADE, -1, <<>>).

%% @doc Abort in-service upgrade.
-spec abort_upgrade(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
abort_upgrade(Sock) ->
    intcall(Sock, ?MAAPI_ABORT_UPGRADE, -1, <<>>).


%%% Daemon control functions

%% @doc Tell AAA to reload external AAA data.
-spec aaa_reload(Socket, Synchronous) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Synchronous :: boolean().
aaa_reload(Sock, Synchronous) ->
    intcall(Sock, ?MAAPI_AAA_RELOAD, -1, bool2int(Synchronous)).

%% @doc Tell ConfD to reload external SNMP Agent config data.
-spec snmpa_reload(Socket, Synchronous) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Synchronous :: boolean().
snmpa_reload(Sock, Synchronous) ->
    intcall(Sock, ?MAAPI_SNMPA_RELOAD, -1, bool2int(Synchronous)).

%% @doc Tell ConfD to proceed to next start phase.
-spec start_phase(Socket, Phase, Synchronous) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Phase :: 1 | 2,
      Synchronous :: boolean().
start_phase(Sock, Phase, Synchronous) when Phase >= 1, Phase =< 2 ->
    intcall(Sock, ?MAAPI_START_PHASE, -1, {Phase, bool2int(Synchronous)}).

%% @doc Wait until ConfD daemon has completely started.
%%
%% @equiv wait_start(Socket, 2)
-spec wait_start(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
wait_start(Sock) ->
    wait_start(Sock, 2).

%% @doc Wait until ConfD daemon has reached a certain start phase.
-spec wait_start(Socket, Phase) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Phase :: 1 | 2.
wait_start(Sock, Phase) when Phase >= 0, Phase =< 2 ->
    intcall(Sock, ?MAAPI_WAIT_START, -1, Phase).

%% @doc Tell ConfD daemon to reload its configuration.
-spec reload_config(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
reload_config(Sock) ->
    intcall(Sock, ?MAAPI_RELOAD_CONFIG, -1, <<>>).

-spec netconf_ssh_call_home(Socket, Host, Port) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Host :: econfd:ip() | string(),
      Port :: non_neg_integer().
netconf_ssh_call_home(Sock, Host, Port) ->
    intcall(Sock, ?MAAPI_NETCONF_SSH_CALL_HOME, -1, {Host, Port}).

-spec netconf_ssh_call_home_opaque(Socket,Host,Opaque,Port) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Host :: econfd:ip() | string(),
      Opaque :: string(),
      Port :: non_neg_integer().
netconf_ssh_call_home_opaque(Sock, Host, Opaque, Port) ->
    intcall(Sock, ?MAAPI_NETCONF_SSH_CALL_HOME_OPAQUE, -1, {Host, Opaque,Port}).

%% @doc Tell ConfD daemon to stop, returns when daemon has exited.
%%
%% @equiv stop(Sock, true)
-spec stop(Socket) -> 'ok' when
      Socket :: econfd:socket().
stop(Sock) ->
    stop(Sock, true).

%% @doc Tell ConfD daemon to stop, if Synchronous is true won't return
%%      until daemon has come to a halt.
%%
%% Note that the socket will most certainly not be possible to use again, since
%% ConfD will close its end when it exits.
-spec stop(Socket, Synchronous) -> 'ok' when
      Socket :: econfd:socket(),
      Synchronous :: boolean().
stop(Sock, Synchronous) ->
    intcall(Sock, ?MAAPI_STOP, -1, bool2int(Synchronous)),
    ok.

%% @doc Apply a template that has been loaded into NCS.
%%
%% The TemplateName parameter gives the name of the template. The Variables
%% parameter is a list of variables and names for substitution into the
%% template.
-spec ncs_apply_template(Socket, Tid, TemplateName, RootIKeypath, Variables,
                         Documents, Shared) -> 'ok' | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      TemplateName :: binary(),
      RootIKeypath :: econfd:ikeypath(),
      Variables :: term(),
      Documents :: term(),
      Shared :: boolean().
ncs_apply_template(Sock, Tid, TemplateName, RootIKP, Variables,
                   Documents, Shared) ->
    Term = {TemplateName, reverse(RootIKP), Variables,
            Documents, Shared, Shared},
    intcall(Sock, ?MAAPI_NCS_APPLY_TEMPLATE, Tid, Term).

%% @doc Retrieve a list of the templates currently loaded into NCS.
-spec ncs_templates(Socket) -> {'ok', binary()} | err() when
      Socket :: econfd:socket().
ncs_templates(Sock) ->
    intcall(Sock, ?MAAPI_NCS_TEMPLATES, -1, <<>>).

%% @doc Retrieve the variables used in a template.
-spec ncs_template_variables(Socket, Tid, TemplateName) ->
          {'ok', binary()} | err() when
      Socket :: econfd:socket(),
      Tid :: integer(),
      TemplateName :: binary().
ncs_template_variables(Sock, Tid, TemplateName) ->
    intcall(Sock, ?MAAPI_NCS_TEMPLATE_VARIABLES, Tid, TemplateName).

%% @doc Write a service log entry.
-spec ncs_write_service_log_entry(Socket, IKeypath, Message, Type, Level) ->
          'ok' | err() when
      Socket :: econfd:socket(),
      IKeypath :: econfd:ikeypath(),
      Message :: string(),
      Type :: econfd:value(),
      Level :: econfd:value().
ncs_write_service_log_entry(Sock, SIKP, Msg, Type, Level) ->
    Term = {lists:reverse(SIKP), 0, Msg, Type, Level},
    intcall(Sock, ?MAAPI_NCS_WRITE_SERVICE_LOG_ENTRY, -1, Term).


%%%--------------------------------------------------------------------
%%% Internal functions
%%%--------------------------------------------------------------------

%% @private
-spec intcall(Socket, Op, Tid, Request) -> Result when
      Socket :: econfd:socket(),
      Op :: integer(),
      Tid :: integer(),
      Request :: term(),
      Result :: read_ret().
intcall(Sock, Op, -1, <<>>) ->
    econfd_internal:confd_call_bin(Sock, <<>>, Op);
intcall(Sock, Op, Tid, <<>>) ->
    econfd_internal:confd_call_bin(Sock, <<Tid:32>>, Op);
intcall(Sock, Op, Tid, Arg) ->
    econfd_internal:confd_call(Sock, Arg, Op, Tid).

ibool({ok, 1}) -> {ok, true};
ibool({ok, 0}) -> {ok, false};
ibool(X) -> X.

bool2int(true)  -> 1;
bool2int(false) -> 0.

reverse(X) -> lists:reverse(X).

mk_uident(UId) ->
    case UId of
        #confd_user_identification{vendor = V, product = P, version = Vsn,
                                   client_identity = CId} ->
            {V, P, Vsn, CId};
        _ ->
            {undefined, undefined, undefined, <<"econfd">>}
    end.
