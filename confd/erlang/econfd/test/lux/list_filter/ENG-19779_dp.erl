-module('ENG-19779_dp').

-export([start/0]).

-on_load(on_load/0).

-include("econfd.hrl").
-include("econfd_list_filter.hrl").

-define(UINFO, 3).
-define(TIMEOUT, 60000).

on_load() ->
    start(),
    ok.

start() ->
    spawn(fun init/0).


init() ->
    io:format("INIT ~p\n", [self()]),
    wait_started({127,0,0,1}, ?CONFD_PORT),

    {ok, M} = econfd_maapi:connect({127,0,0,1}, ?CONFD_PORT),
    {ok, D} = econfd:init_daemon('ENG-19779_dp', ?CONFD_SILENT, user, M,
                                 {127,0,0,1}, ?CONFD_PORT),

    TransCbs = #confd_trans_cbs{init = fun init_trans/1},
    ok = econfd:register_trans_cb(D, TransCbs),

    ok = econfd:register_data_cb(
           D, #confd_data_cbs{callpoint = 'ENG-19779',
                              get_elem = fun get_elem/2,
                              get_next = fun get_next/3
                             },
          ?CONFD_DATA_WANT_FILTER),
    ok = econfd:register_data_cb(
           D, #confd_data_cbs{callpoint = 'ENG-19779-obj',
                              get_elem = fun get_elem/2,
                              get_next_object = fun get_next_object/3
                             },
          ?CONFD_DATA_WANT_FILTER),

    ok = econfd:register_done(D),

    loop().

wait_started(Address, Port) ->
    {ok, S} = retry_connect(Address, Port, 10, undefined),
    econfd_cdb:wait_start(S),
    econfd_cdb:close(S).

retry_connect(_Address, _Port, 0, LastErr) ->
    LastErr;
retry_connect(Address, Port, N, _LastErr) ->
    case econfd_cdb:connect(Address, Port) of
        {ok, S} ->
            {ok, S};
        LastErr ->
            timer:sleep(100),
            retry_connect(Address, Port, N - 1, LastErr)
    end.

loop() ->
    receive
    after infinity ->
            ok
    end.

init_trans(_Tx) ->
    ok.

get_elem(_Tx, [name,{<<"One">>}|_]) ->
    {ok, <<"One">>};
get_elem(_Tx, [size,{<<"One">>}|_]) ->
    {ok, {?C_UINT8, 8}};
get_elem(_Tx, [name,{<<"Two">>}|_]) ->
    {ok, <<"Two">>};
get_elem(_Tx, [size,{<<"Two">>}|_]) ->
    {ok, {?C_UINT8, 16}};
get_elem(_Tx, [name,{<<"Three">>}|_]) ->
    {ok, <<"Three">>};
get_elem(_Tx, [size,{<<"Three">>}|_]) ->
    {ok, {?C_UINT8, 24}};
get_elem(_Tx, _Path) ->
    {ok, not_found}.

get_next(#confd_trans_ctx{list_filter = undefined} = Tx, Path, -1) ->
    undefined = econfd:data_get_list_filter(Tx),
    econfd:log(?CONFD_LEVEL_INFO, "get_next(~p) ~nfilter undefined~n",
               [Path]),
    {ok, {{<<"One">>}, 2}};
get_next(#confd_trans_ctx{list_filter = undefined} = Tx, _Path, 2) ->
    undefined = econfd:data_get_list_filter(Tx),
    {ok, {{<<"Two">>}, 3}};
get_next(#confd_trans_ctx{list_filter = undefined} = Tx, _Path, 3) ->
    undefined = econfd:data_get_list_filter(Tx),
    {ok, {{<<"Three">>}, 4}};
get_next(#confd_trans_ctx{list_filter = undefined} = Tx, _Path, 4) ->
    undefined = econfd:data_get_list_filter(Tx),
    {ok, {false, undefined}};
get_next(#confd_trans_ctx{list_filter = Filter} = Tx, Path, -1) ->
    Filter = econfd:data_get_list_filter(Tx),
    econfd:log(?CONFD_LEVEL_INFO, "get_next(~p) ~nfilter ~s~n",
               [Path, fmt_filter(Filter)]),
    {ok, {{<<"One">>}, 2}, econfd:data_set_filtered(Tx, true)};
get_next(#confd_trans_ctx{list_filter = Filter} = Tx, _Path, 2) ->
    Filter = econfd:data_get_list_filter(Tx),
    {ok, {{<<"Two">>}, 3}};
get_next(#confd_trans_ctx{list_filter = Filter} = Tx, _Path, 3) ->
    Filter = econfd:data_get_list_filter(Tx),
    {ok, {false, undefined}}.

get_next_object(#confd_trans_ctx{list_filter = undefined} = Tx, Path, -1) ->
    undefined = econfd:data_get_list_filter(Tx),
    econfd:log(?CONFD_LEVEL_INFO, "get_next_object(~p) ~nfilter ~s~n",
               [Path, fmt_filter(undefined)]),
    Objects =
        [{[<<"One">>, {?C_UINT8, 8}, not_found], 2},
         {[<<"Two">>, {?C_UINT8, 16}, not_found], 3}],
    {ok, Objects, ?TIMEOUT};
get_next_object(#confd_trans_ctx{list_filter = undefined} = Tx, _Path, 3) ->
    undefined = econfd:data_get_list_filter(Tx),
    Objects = [{[<<"Three">>, {?C_UINT8, 24}, not_found], 4}],
    {ok, Objects, ?TIMEOUT};
get_next_object(#confd_trans_ctx{list_filter = undefined} = Tx, _Path, 4) ->
    undefined = econfd:data_get_list_filter(Tx),
    {ok, {false, undefined}};
get_next_object(#confd_trans_ctx{list_filter = Filter} = Tx, Path, -1) ->
    %% assert filter is returned as it should from data_get_list_filter
    Filter = econfd:data_get_list_filter(Tx),
    econfd:log(?CONFD_LEVEL_INFO, "get_next_object(~p) ~nfilter ~s~n",
               [Path, fmt_filter(Filter)]),
    Objects =
        [{[<<"One">>, {?C_UINT8, 8}, not_found], 2},
         {[<<"Two">>, {?C_UINT8, 16}, not_found], 3}],
    {ok, Objects, ?TIMEOUT, econfd:data_set_filtered(Tx, true)};
get_next_object(#confd_trans_ctx{list_filter = Filter} = Tx, _Path, 3) ->
    %% assert filter is returned as it should from data_get_list_filter
    Filter = econfd:data_get_list_filter(Tx),
    {ok, {false, undefined}}.

fmt_filter(undefined) ->
    "undefined";
fmt_filter(#confd_list_filter{type = ?CONFD_LF_OR,
                              expr1 = Expr1, expr2 = Expr2}) ->
    io_lib:format("~s OR ~s", [fmt_filter(Expr1), fmt_filter(Expr2)]);
fmt_filter(#confd_list_filter{type = ?CONFD_LF_AND,
                              expr1 = Expr1, expr2 = Expr2}) ->
    io_lib:format("~s AND ~s", [fmt_filter(Expr1), fmt_filter(Expr2)]);
fmt_filter(#confd_list_filter{type = ?CONFD_LF_CMP,
                              node = Node, op = Op, val = Value}) ->
    io_lib:format("~p ~s ~p", [Node, fmt_op(Op), Value]);
fmt_filter(#confd_list_filter{type = ?CONFD_LF_EXEC,
                              node = Node, val = Value, op = Op}) ->
    io_lib:format("~s(~p, ~p)", [fmt_op(Op), Node, Value]).


fmt_op(?CONFD_CMP_EQ) -> "=";
fmt_op(?CONFD_CMP_NEQ) -> "!=";
fmt_op(?CONFD_CMP_GT) -> ">";
fmt_op(?CONFD_CMP_GTE) -> ">=";
fmt_op(?CONFD_CMP_LT) -> "<";
fmt_op(?CONFD_CMP_LTE) -> "=<";
fmt_op(?CONFD_EXEC_RE_MATCH) -> "re-match";
fmt_op(?CONFD_EXEC_DERIVED_FROM) -> "derived-from".
