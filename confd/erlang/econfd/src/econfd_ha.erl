%%%-------------------------------------------------------------------
%%% @copyright 2006 Tail-F Systems AB
%%% @version {$Id$}
%%% @doc An Erlang interface equivalent to the HA C-API
%%% (documented in confd_lib_ha(3)).
%%% @end
%%%-------------------------------------------------------------------

-module(econfd_ha).

%%% external exports

-export([connect/2,
         connect/3,
         close/1,
         beprimary/2,
         besecondary/4,
         secondary_dead/2,
         benone/1,
         berelay/1,
         getstatus/1]).

%%% Deprecated
-export([
         bemaster/2,
         slave_dead/2,
         beslave/4
        ]).
%%% Deprecated end

-import(econfd_internal,
        [
         confd_call/2,
         term_write/2
        ]).

-include("../include/econfd.hrl").
-include("../include/econfd_errors.hrl").
-include("econfd_internal.hrl").


%% Types
-type ha_node() :: #ha_node{}.

%%%--------------------------------------------------------------------
%%% External functions
%%%--------------------------------------------------------------------

%% @equiv connect(Address, 4565, Mask)
-spec connect(Address, Token) -> econfd:connect_result() when
      Address :: econfd:ip(),
      Token :: binary().
connect(Address, Token) ->
    connect(Address, ?CONFD_PORT, Token).

%% @doc Connect to the HA subsystem on host with address Address:Port.
%%
%% If the port is changed it must also be changed in confd.conf
%% To close a HA socket, use {@link close/1}.
-spec connect(Address, Port, Token) -> econfd:connect_result() when
      Address :: econfd:ip(),
      Port :: non_neg_integer(),
      Token :: binary().
connect(Address, Port, Token) ->
    case econfd_internal:connect(Address, Port, ?CLIENT_HA, []) of
        {ok, Socket} ->
            econfd_internal:bin_write(Socket, Token),
            {ok, Socket};
        Error ->
            Error
    end.

%% @doc Close the HA connection.
-spec close(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
close(Socket) ->
    econfd_internal:close(Socket).

%% @doc Instruct a HA node to be primary in the cluster.
%% @deprecated Please use beprimary/2 instead
-spec bemaster(Socket, NodeId) -> Result when
      Socket :: econfd:socket(),
      NodeId :: econfd:value(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
bemaster(Socket, MyNodeId) ->
    beprimary(Socket, MyNodeId).

%% @doc Instruct a HA node to be primary in the cluster.
-spec beprimary(Socket, NodeId) -> Result when
      Socket :: econfd:socket(),
      NodeId :: econfd:value(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
beprimary(Socket, MyNodeId) ->
    case confd_call(Socket, {?CONFD_HA_ORDER_BEPRIMARY, MyNodeId}) of
        {ok, Reply} -> Reply;
        Err -> Err
    end.

%% @doc Instruct ConfD that another node is dead.
%% @deprecated Please use secondary_dead/2 instead
-spec slave_dead(Socket, NodeId) -> Result when
      Socket :: econfd:socket(),
      NodeId :: econfd:value(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
slave_dead(Socket, NodeId) ->
    secondary_dead(Socket, NodeId).

%% @doc Instruct ConfD that another node is dead.
-spec secondary_dead(Socket, NodeId) -> Result when
      Socket :: econfd:socket(),
      NodeId :: econfd:value(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
secondary_dead(Socket, NodeId) ->
    case confd_call(Socket, {?CONFD_HA_ORDER_SECONDARY_DEAD, NodeId}) of
        {ok, Reply} -> Reply;
        Err -> Err
    end.

%% @doc Instruct a HA node to be secondary in the cluster where
%% PrimaryNodeId is primary.
%% @deprecated please use besecondary/2 instead
-spec beslave(Socket, NodeId, PrimaryNodeId, WaitReplyBool) -> Result when
      Socket :: econfd:socket(),
      NodeId :: econfd:value(),
      PrimaryNodeId :: ha_node(),
      WaitReplyBool :: integer(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
beslave(Socket, MyNodeId, Primary, WaitP) ->
    besecondary(Socket, MyNodeId, Primary, WaitP).

%% @doc Instruct a HA node to be secondary in the cluster where
%% PrimaryNodeId is primary.
-spec besecondary(Socket, NodeId, PrimaryNodeId, WaitReplyBool) -> Result when
      Socket :: econfd:socket(),
      NodeId :: econfd:value(),
      PrimaryNodeId :: ha_node(),
      WaitReplyBool :: integer(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
besecondary(Socket, MyNodeId, Primary, WaitP) ->
    Request = {?CONFD_HA_ORDER_BESECONDARY, MyNodeId,
               {Primary#ha_node.nodeid, Primary#ha_node.addr},
               WaitP},
    if
        WaitP == 1 ->
            case confd_call(Socket, Request) of
                {ok, Reply} -> Reply;
                Err -> Err
            end;
        WaitP == 0 ->
            term_write(Socket, Request)
    end.

%% @doc Instruct a HA node to be nothing in the cluster.
-spec benone(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
benone(Socket) ->
    case confd_call(Socket, {?CONFD_HA_ORDER_BENONE}) of
        {ok, Reply} -> Reply;
        Err -> Err
    end.

%% @doc Instruct a HA secondary to be a relay for other secondaries.
-spec berelay(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
berelay(Socket) ->
    case confd_call(Socket, {?CONFD_HA_ORDER_BERELAY}) of
        {ok, Reply} -> Reply;
        Err -> Err
    end.

%% @doc Request status from a HA node.
-spec getstatus(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
getstatus(Socket) ->
    case confd_call(Socket, {?CONFD_HA_ORDER_GETSTATUS}) of
        {ok, Reply} ->
            {Status, List} = Reply,
            {ok, #ha_status{status = Status,
                            data = lists:map(fun({Nid, Addr}) ->
                                                     #ha_node{nodeid = Nid,
                                                              addr = Addr}
                                             end, List)}};
        Err -> Err
    end.

