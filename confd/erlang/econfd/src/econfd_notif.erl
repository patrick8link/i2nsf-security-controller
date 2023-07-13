%%%-------------------------------------------------------------------
%%% @copyright 2006 Tail-F Systems AB
%%% @version {$Id$}
%%% @doc An Erlang interface equivalent to the event notifications C-API,
%%% (documented in confd_lib_events(3)).
%%% @end
%%%-------------------------------------------------------------------

-module(econfd_notif).

%%% external exports

-export([connect/2,
         connect/3,
         connect/4,
         close/1,
         recv/1,
         recv/2,
         handle_notif/1,
         notification_done/2,
         notification_done/3]).

-include("../include/econfd.hrl").
-include("../include/econfd_errors.hrl").
-include("econfd_internal.hrl").


%% Types
-type notification() :: #econfd_notif_audit{} |
                        #econfd_notif_syslog{} |
                        #econfd_notif_commit_simple{} |
                        #econfd_notif_commit_diff{} |
                        #econfd_notif_user_session{} |
                        #econfd_notif_ha{} |
                        #econfd_notif_subagent_info{} |
                        #econfd_notif_commit_failed{} |
                        #econfd_notif_snmpa{} |
                        #econfd_notif_forward_info{} |
                        #econfd_notif_confirmed_commit{} |
                        #econfd_notif_upgrade{} |
                        #econfd_notif_progress{} |
                        #econfd_notif_stream_event{} |
                        #econfd_notif_ncs_cq_progress{} |
                        #econfd_notif_ncs_audit_network{} |
                        'confd_heartbeat' | 'confd_health_check' |
                        'confd_reopen_logs' | 'ncs_package_reload'.

%%%--------------------------------------------------------------------
%%% External functions
%%%--------------------------------------------------------------------

%% @equiv connect(Address, 4565, Mask)
-spec connect(Address, Mask) -> econfd:connect_result() when
      Address :: econfd:ip(),
      Mask :: integer().
connect(Address, Mask) ->
    connect(Address, ?CONFD_PORT, Mask).

%% @equiv connect(Address, Port, Mask, [])
-spec connect(Address, Port, Mask) -> econfd:connect_result() when
      Address :: econfd:ip(),
      Port :: non_neg_integer(),
      Mask :: integer().
connect(Address, Port, Mask) ->
    connect(Address, Port, Mask, []).

%% @doc Connect to the notif server on host with address Address:Port.
%%
%% If the port is changed it must also be changed in confd.conf.
%% The Mask argument is a bitmask made out of the
%% bits defined in econfd.hrl as CONFD_NOTIF_XXX.
%% If CONFD_NOTIF_HEARTBEAT and/or CONFD_NOTIF_HEALTH_CHECK is included in
%% Mask, the corresponding desired interval (in milliseconds) must be
%% included in the options list.
%% If CONFD_NOTIF_STREAM_EVENT is included in Mask, 'stream_name' must be
%% included in the options list, 'start_time'/'stop_time' option may be used
%% for replay, 'xpath_filter' may be used for event notification filtering,
%% and 'usid' may be given to apply AAA restrictions.
%% To close a notification socket, use {@link close/1}.
-spec connect(Address, Port, Mask, Options) -> econfd:connect_result() when
      Address :: econfd:ip(),
      Port :: non_neg_integer(),
      Mask :: integer(),
      Options :: [Option],
      Option :: {'heartbeat_interval', integer()} |
                {'health_check_interval', integer()} |
                {'stream_name', atom()} |
                {'start_time', econfd:datetime()} |
                {'stop_time', econfd:datetime()} |
                {'xpath_filter', binary()} |
                {'usid', integer()} |
                {'verbosity', 0..3}.
connect(Address, Port, Mask, Options) ->
    if (Mask band ?CONFD_NOTIF_HEARTBEAT) /= 0 ->
            {value, {_, HbInter}} =
                lists:keysearch(heartbeat_interval, 1, Options);
       true ->
            HbInter = 0
    end,
    if (Mask band ?CONFD_NOTIF_HEALTH_CHECK) /= 0 ->
            {value, {_, HcInter}} =
                lists:keysearch(health_check_interval, 1, Options);
        true ->
            HcInter = 0
    end,
    if (Mask band ?CONFD_NOTIF_STREAM_EVENT) /= 0 ->
            {value, {_, StreamName}} =
                lists:keysearch(stream_name, 1, Options),
            case lists:keysearch(start_time, 1, Options) of
                {value, {_, StartTime}} ->
                    case lists:keysearch(stop_time, 1, Options) of
                        {value, {_, StopTime}} -> ok;
                        false                  -> StopTime = undefined
                    end;
                false ->
                    StartTime = StopTime = undefined
            end,
            case lists:keysearch(xpath_filter, 1, Options) of
                {value, {_, Filter}} -> ok;
                false                -> Filter = undefined
            end,
            case lists:keysearch(usid, 1, Options) of
                {value, {_, Usid}} -> ok;
                false              -> Usid = 0
            end,
            UseIKP = 1,
            StreamInfo = {StreamName, StartTime, StopTime, Filter, Usid,UseIKP};
        true ->
            StreamInfo = undefined
    end,
    case lists:keysearch(verbosity, 1, Options) of
        {value, {_, ProgressVerbosity}} -> ok;
        false                           -> ProgressVerbosity = 0
    end,
    case econfd_internal:connect(Address, Port, ?CLIENT_EVENT_MGR, []) of
        {ok, Socket} ->
            Term = {Mask, HbInter, HcInter, StreamInfo, ProgressVerbosity},
            case econfd_internal:confd_call(Socket, Term) of
                {ok, _Term} ->           % always 'ok'
                    {ok, Socket};
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

%% @doc Close the event notification connection.
-spec close(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
close(Socket) ->
    econfd_internal:close(Socket).

%% @equiv recv(Socket, infinity)
recv(Socket) ->
    recv(Socket, infinity).

%% @doc Wait for an event notification message and return corresponding
%% record depending on the type of the message.
%%
%% The logno element in the record is an integer.
%% These integers can be used as an index to the
%% function {@link econfd_logsyms:get_logsym/1} in order to get a
%% textual description for the event.
%%
%% When recv/2 returns <tt>{error, timeout}</tt> the connection (and its
%% event subscriptions) is still active and the application needs to call
%% recv/2 again. But if recv/2 returns
%% <tt>{error, Reason}</tt> the connection to ConfD is closed and all
%% event subscriptions associated with it are cleared.
-spec recv(Socket, Timeout) -> Result when
      Socket :: econfd:socket(),
      Timeout :: non_neg_integer() | 'infinity',
      Result :: {'ok', notification()} |
                {'error', econfd:transport_error()} |
                {'error', econfd:error_reason()}.
recv(Socket, TimeOut) ->
    case econfd_internal:term_read(Socket, TimeOut) of
        {ok, Notif} ->
            {ok, handle_notif(Notif)};
        {error, closed} ->
            {error, closed};
        {error, timeout} ->
            {error, timeout};
        {error, _Reason} ->
            econfd_internal:close(Socket),
            {error, {?CONFD_ERR_OS, <<"">>}}
    end.

%% @deprecated Use the function {@link recv/2} instead.
%% @doc Decode the notif message and return corresponding
%% record depending on the type of the message.
%%
%% It is the resposibility of the application to
%% read data from the notifications socket.
-spec handle_notif(Notif) -> notification() when
      Notif :: binary() | term().
handle_notif(B) when is_binary(B) ->
    handle_notif(?b2t(B));
handle_notif(Term) ->
    if element(1, Term) == ?CONFD_NOTIF_AUDIT ->
            #econfd_notif_audit{logno = element(2, Term),
                                user =  element(3, Term),
                                usid =  element(4, Term),
                                msg =   element(5, Term)};
       element(1, Term) == ?CONFD_NOTIF_DAEMON;
       element(1, Term) == ?CONFD_NOTIF_NETCONF;
       element(1, Term) == ?CONFD_NOTIF_DEVEL ;
       element(1, Term) == ?CONFD_NOTIF_JSONRPC ;
       element(1, Term) == ?CONFD_NOTIF_WEBUI ->
            #econfd_notif_syslog{logno = element(2, Term),
                                 prio =  element(3, Term),
                                 msg =   element(4, Term)};
       element(1, Term) == ?CONFD_NOTIF_COMMIT_SIMPLE ->
            Uinfo = econfd:mk_uinfo(element(3, Term)),
            #econfd_notif_commit_simple{
                              db =      element(2, Term),
                              uinfo =   Uinfo,
                              commit_diff_available = element(4, Term),
                              flags =   element(5, Term),
                              user =    Uinfo#confd_user_info.username,
                              ip =      Uinfo#confd_user_info.ip,
                              context = Uinfo#confd_user_info.context,
                              usid =    Uinfo#confd_user_info.usid,
                              proto =   Uinfo#confd_user_info.proto
                             };
       element(1, Term) == ?CONFD_NOTIF_COMMIT_DIFF ->
            Uinfo = econfd:mk_uinfo(element(3, Term)),
            #econfd_notif_commit_diff{
                              db =      element(2, Term),
                              uinfo =   Uinfo,
                              th =      element(4, Term),
                              flags =   element(5, Term),
                              comment = maybe_element(6, Term),
                              label =   maybe_element(7, Term),
                              user =    Uinfo#confd_user_info.username,
                              ip =      Uinfo#confd_user_info.ip,
                              context = Uinfo#confd_user_info.context,
                              usid =    Uinfo#confd_user_info.usid,
                              proto =   Uinfo#confd_user_info.proto
                             };
       element(1, Term) == ?CONFD_NOTIF_USER_SESSION ->
            Uinfo = econfd:mk_uinfo(element(3, Term)),
            #econfd_notif_user_session{
                              type    = element(2, Term),
                              uinfo   = Uinfo,
                              db      = element(4, Term),
                              user =      Uinfo#confd_user_info.username,
                              ip =        Uinfo#confd_user_info.ip,
                              context =   Uinfo#confd_user_info.context,
                              usid =      Uinfo#confd_user_info.usid,
                              proto =     Uinfo#confd_user_info.proto,
                              clearpass = Uinfo#confd_user_info.clearpass,
                              logintime = Uinfo#confd_user_info.logintime
                             };
       element(1, Term) ==  ?CONFD_NOTIF_HA_INFO ->
            {Type, Data} = element(2, Term),
            if Type == ?CONFD_HA_INFO_NOPRIMARY ;
               Type == ?CONFD_HA_INFO_SECONDARY_INITIALIZED;
               Type == ?CONFD_HA_INFO_IS_PRIMARY ;
               Type == ?CONFD_HA_INFO_IS_NONE ;
               Type == ?CONFD_HA_INFO_BESECONDARY_RESULT ->
                    #econfd_notif_ha{type = Type,
                                     data = Data};
               Type == ?CONFD_HA_INFO_SECONDARY_DIED;
               Type == ?CONFD_HA_INFO_SECONDARY_ARRIVED ->
                    #econfd_notif_ha{type = Type,
                                     data = unpack_ha_node(Data)}
            end;
       element(1, Term) ==  ?CONFD_NOTIF_SUBAGENT_INFO ->
            Info = element(2, Term),
            #econfd_notif_subagent_info{
                               type = element(1, Info),
                               name = element(2, Info)
                              };
       element(1, Term) == ?CONFD_NOTIF_COMMIT_FAILED ->
            Provider = element(2, Term),
            case Provider of
                ?DP_NETCONF ->
                    #econfd_notif_commit_failed {
                   provider = Provider,
                   dbname   = element(3, Term),
                   ip       = element(4, Term),
                   port     = element(5, Term)
                };
                ?DP_EXTERNAL ->
                    #econfd_notif_commit_failed {
                   provider = Provider,
                   dbname      = element(3, Term),
                   daemon_name = element(4, Term)
                  }
            end;
       element(1, Term) == ?CONFD_NOTIF_SNMPA ->
            #econfd_notif_snmpa {
                              pdutype = element(2, Term),
                              ip     = element(3, Term),
                              port    = element(4, Term),
                              errstatus = element(5, Term),
                              errindex = element(6, Term),
                              varbind  = len = element(8, Term)
                             };
       element(1, Term) == ?CONFD_NOTIF_FORWARD_INFO ->
            #econfd_notif_forward_info {
                              type = element(2, Term),
                              target = element(3, Term),
                              uinfo = econfd:mk_uinfo(element(4, Term))
                             };
       element(1, Term) == ?CONFD_NOTIF_HEARTBEAT ->
            confd_heartbeat;
       element(1, Term) == ?CONFD_NOTIF_HEALTH_CHECK ->
            confd_health_check;
       element(1, Term) == ?CONFD_NOTIF_CONFIRMED_COMMIT ->
            #econfd_notif_confirmed_commit {
                              type = element(2, Term),
                              timeout = element(3, Term),
                              uinfo = econfd:mk_uinfo(element(4, Term))
                             };
       element(1, Term) == ?CONFD_NOTIF_UPGRADE_EVENT ->
            #econfd_notif_upgrade {
                              event = element(2, Term)
                             };
       element(1, Term) == ?CONFD_NOTIF_PROGRESS orelse
       element(1, Term) == ?CONFD_NOTIF_COMMIT_PROGRESS ->
            Event = element(2, Term),
            #econfd_notif_progress{
                             type            = element(1,  Event),
                             timestamp       = element(2,  Event),
                             duration        = element(3,  Event),
                             usid            = element(4,  Event),
                             tid             = element(5,  Event),
                             database        = element(6,  Event),
                             context         = element(7,  Event),
                             trace_id        = element(8,  Event),
                             subsystem       = element(9,  Event),
                             phase           = element(10, Event),
                             msg             = element(11, Event),
                             annotation      = element(12, Event),
                             service         = element(13, Event),
                             service_phase   = element(14, Event),
                             commit_queue_id = element(15, Event),
                             node            = element(16, Event),
                             device          = element(17, Event),
                             device_phase    = element(18, Event),
                             package         = element(19, Event)
                            };
       element(1, Term) == ?CONFD_NOTIF_STREAM_EVENT ->
            case element(2, Term) of
                Atom when Atom == notification_complete;
                          Atom == replay_complete ->
                    #econfd_notif_stream_event{type = Atom};
                {replay_failed, Msg} ->
                    #econfd_notif_stream_event{type = replay_failed,
                                               replay_error = Msg};
                {EventTime, Exml} ->
                    #econfd_notif_stream_event{type = notification_event,
                                               event_time = EventTime,
                                               values = Exml}
            end;
       element(1, Term) == ?NCS_NOTIF_PACKAGE_RELOAD ->
            ncs_package_reload;
       element(1, Term) == ?NCS_NOTIF_CQ_PROGRESS ->
            #econfd_notif_ncs_cq_progress {
                              type = element(2, Term),
                              timestamp = element(3, Term),
                              cq_id = element(4, Term),
                              cq_tag = element(5, Term),
                              completed_devices = element(6, Term),
                              transient_devices = element(7, Term),
                              failed_devices = element(8, Term),
                              completed_services = element(9, Term),
                              failed_services = element(10, Term),
                              trace_id = element(11, Term)
                             };
       element(1, Term) == ?NCS_NOTIF_AUDIT_NETWORK ->
            Event = element(2, Term),
            #econfd_notif_ncs_audit_network {
               usid     = element(1, Event),
               tid      = element(2, Event),
               user     = element(3, Event),
               device   = element(4, Event),
               trace_id = element(5, Event),
               config   = element(6, Event)
              };
       element(1, Term) == ?CONFD_NOTIF_REOPEN_LOGS ->
            confd_reopen_logs
    end.

unpack_ha_node({NodeId, Peer}) ->
    #ha_node{nodeid = NodeId, addr = Peer}.

maybe_element(N, Tuple) when tuple_size(Tuple) < N ->
    undefined;
maybe_element(N, Tuple) ->
    case element(N, Tuple) of
        <<>> -> undefined;
        Elem -> Elem
    end.

%% @doc Indicate that we're done with diff processing.
%%
%% Whenever we subscribe to ?CONFD_NOTIF_COMMIT_DIFF we must indicate to
%% confd that we're done with the diff processing. The transaction
%% hangs until we've done this.
-spec notification_done(Socket, Thandle) -> Result when
      Socket :: econfd:socket(),
      Thandle :: integer(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
notification_done(Sock, Thandle) ->
    econfd_internal:term_write(Sock, {Thandle, done}).

%% @doc Indicate that we're done with notif processing.
%%
%% When we subscribe to ?CONFD_NOTIF_AUDIT with ?CONFD_NOTIF_AUDIT_SYNC
%% or to ?NCS_NOTIF_AUDIT_NETWORK with ?NCS_NOTIF_AUDIT_NETWORK_SYNC,
%% we must indicate that we're done with the notif processing. The user-session
%% hangs until we've done this.
-spec notification_done(Socket, Usid, NotifType) -> Result when
      Socket    :: econfd:socket(),
      Usid      :: integer(),
      NotifType :: 'audit' | 'audit_network',
      Result    :: 'ok' | {'error', econfd:error_reason()}.
notification_done(Sock, Usid, 'audit') ->
    econfd_internal:term_write(Sock, {Usid, synced});
notification_done(Sock, Usid, 'audit_network') ->
    econfd_internal:term_write(Sock, {Usid, audit_network_sync}).
