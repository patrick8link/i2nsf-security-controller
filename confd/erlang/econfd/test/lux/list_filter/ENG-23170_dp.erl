-module('ENG-23170_dp').

-export([start/0]).

-include("econfd.hrl").
-include("econfd_list_filter.hrl").
-include("ietf-origin.hrl").

start() ->
    ok = application:start(econfd),
    wait_started({127,0,0,1}, ?CONFD_PORT),

    {ok, M} = econfd_maapi:connect({127,0,0,1}, ?CONFD_PORT),
    {ok, D} = econfd:init_daemon('interface_dp', ?CONFD_SILENT, user, M,
                                 {127,0,0,1}, ?CONFD_PORT),

    TransCbs = #confd_trans_cbs{init = fun init_trans/1},
    ok = econfd:register_trans_cb(D, TransCbs),

    ok = econfd:register_data_cb(
           D, #confd_data_cbs{callpoint = 'interfaceCP',
                              get_elem = fun get_elem/2,
                              get_next = fun get_next/3,
                              get_attrs = fun get_attrs/3
                             },
          ?CONFD_DATA_WANT_FILTER),
    io:format("~s: registered interfaceCP~n", [?MODULE]),

    ok = econfd:register_done(D),
    io:format("~s: started~n", [?MODULE]).

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

init_trans(_Tx) ->
    ok.

get_elem(_Tx, ['ip-address',{<<"eth0">>}|_]) ->
    {ok, ?CONFD_IPV4({100,10,0,1})};
get_elem(_Tx, [mtu,{<<"eth0">>}|_]) ->
    {ok, ?CONFD_UINT16(1500)};
get_elem(_Tx, ['ip-address',{<<"lo">>}|_]) ->
    {ok, ?CONFD_IPV4({127,0,0,1})};
get_elem(_Tx, [mtu,{<<"lo">>}|_]) ->
    {ok, ?CONFD_UINT16(0)};
get_elem(_Tx, _Path) ->
    {ok, not_found}.

get_next(#confd_trans_ctx{list_filter = undefined}, _Path, -1) ->
    ok = io:format("no list filter found~n", []),
    {ok, {{<<"eth0">>}, 1}};
get_next(#confd_trans_ctx{list_filter = Filter} = Tx, _Path, -1) ->
    ok = fmt_filter(Filter),
    {ok, {{<<"eth0">>}, 2}, econfd:data_set_filtered(Tx, true)};
get_next(_Tx, _Path, 1) ->
    {ok, {{<<"lo">>}, 2}};
get_next(_Tx, _Path, 2) ->
    {ok, {false, undefined}}.

get_attrs(_Tx, [_, {<<"eth0">>}|_], _AtttL) ->
    Intended = {?C_IDENTITYREF, {?or__ns, ?or_intended}},
    {ok, [{?CONFD_ATTR_ORIGIN, Intended}]};
get_attrs(_Tx, [{<<"eth0">>}|_], _AtttL) ->
    Intended = {?C_IDENTITYREF, {?or__ns, ?or_intended}},
    {ok, [{?CONFD_ATTR_ORIGIN, Intended}]};
get_attrs(_Tx, [_, {<<"lo">>}|_], _AtttL) ->
    System = {?C_IDENTITYREF, {?or__ns, ?or_system}},
    {ok, [{?CONFD_ATTR_ORIGIN, System}]};
get_attrs(_Tx, [{<<"lo">>}|_], _AtttL) ->
    System = {?C_IDENTITYREF, {?or__ns, ?or_system}},
    {ok, [{?CONFD_ATTR_ORIGIN, System}]};
get_attrs(_Tx, _Path, _AtttL) ->
    {ok, []}.

fmt_filter(Filter) ->
    ok = io:format("FilterBegin~n"),
    ok = fmt_filter(Filter, ""),
    ok = io:format("FilterEnd~n").

fmt_filter(#confd_list_filter{type = ?CONFD_LF_ORIGIN,
                              val = Val}, Indent) ->
    ok = io:format("~sFilter type: LF_ORIGIN - Filter value: ~s~n",
                   [Indent, fmt_val(Val)]);
fmt_filter(#confd_list_filter{type = Type,
                              expr1 = Expr1,
                              expr2 = Expr2},
           Indent) ->
    ok = io:format("~sFilter type: ~s~n", [Indent, fmt_type(Type)]),
    case Expr1 of
        undefined ->
            ok;
        _ ->
            ok = io:format("~sexpr1~n", [Indent]),
            fmt_filter(Expr1, "  "++Indent)
    end,
    case Expr2 of
        undefined ->
            ok;
        _ ->
            ok = io:format("~sexpr2~n", [Indent]),
            fmt_filter(Expr2, "  " ++ Indent)
    end.

fmt_type(?CONFD_LF_OR) ->
    "LF_OR";
fmt_type(?CONFD_LF_AND) ->
    "LF_AND";
fmt_type(?CONFD_LF_CMP) ->
    "LF_CMP";
fmt_type(?CONFD_LF_NOT) ->
    "LF_NOT";
fmt_type(?CONFD_LF_ORIGIN) ->
    "LF_ORIGIN";
fmt_type(_) ->
    "unexpected filter type".

fmt_val({?C_IDENTITYREF, {?or__ns, ?or_intended}}) ->
    "intended";
fmt_val({?C_IDENTITYREF, {?or__ns, ?or_system}}) ->
    "system";
fmt_val({?C_IDENTITYREF, {?or__ns, ?or_default}}) ->
    "default";
fmt_val(_) ->
    "unexpected origin value".
