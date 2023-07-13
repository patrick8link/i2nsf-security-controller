-module('ENG-19690_dp').

-export([start/0]).

-on_load(on_load/0).

-include("econfd.hrl").

-define(KEYS, [<<"one">>, <<"two">>, <<"three">>, <<"four">>]).
-define(OBJECTS, [{[<<"one">>, <<"extra-1">>], 2},
                  {[<<"two">>, <<"extra-2">>], 3},
                  {[<<"three">>, <<"extra-3">>], 4},
                  {[<<"four">>, <<"extra-4">>], 5}]).
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
    {ok, D} = econfd:init_daemon('ENG-19690_dp', ?CONFD_SILENT, user, M,
                                 {127,0,0,1}, ?CONFD_PORT),

    TransCbs = #confd_trans_cbs{init = fun init_trans/1},
    ok = econfd:register_trans_cb(D, TransCbs),

    ok = econfd:register_data_cb(
           D, #confd_data_cbs{callpoint = 'ENG-19690',
                              get_elem = fun get_elem/2,
                              get_next = fun get_next/3,
                              find_next = fun find_next/4
                             }),

    ok = econfd:register_data_cb(
           D, #confd_data_cbs{callpoint = 'ENG-19690-obj',
                              get_elem = fun get_elem/2,
                              get_next = fun get_next/3,
                              get_next_object = fun get_next_object/3,
                              find_next_object = fun find_next_object/4
                             }),

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

get_elem(_Tx, [name,{Key}|_]) ->
    case lists:member(Key, ?KEYS) of
        true ->
            {ok, Key};
        false ->
            {ok, not_found}
    end;
get_elem(_Tx, [extra,{Key}|_]) ->
    case lists:keyfind(Key, 1, [list_to_tuple(Obj) ||
                                   {Obj, _Id} <- ?OBJECTS]) of
        false ->
            {ok, not_found};
        {_Key, Value} ->
            {ok, Value}
    end.

get_next(Tx, Path, -1) ->
    put(process_key(Tx, next), ?KEYS),
    get_next(Tx, Path, 0);
get_next(Tx, _Path, _NextId) ->
    Key = process_key(Tx, next),
    case get(Key) of
        [] ->
            erase(Key),
            {ok, {false, undefined}};
        [Value|Values] ->
            put(Key, Values),
            {ok, {{Value}, 0}}
    end.

find_next(Tx, _Path, ?CONFD_FIND_NEXT, {FindKey}) ->
    Key = process_key(Tx, next),
    case split(FindKey, ?KEYS) of
        false ->
            erase(Key),
            {ok, {false, undefined}};
        [Value|_] = Values ->
            put(Key, Values),
            {ok, {{Value}, 0}}
    end.

get_next_object(Tx, [object|_] = Path, -1) ->
    put(process_key(Tx, next_object), ?OBJECTS),
    get_next_object(Tx, Path, 0);
get_next_object(Tx, [object|_], _NextId) ->
    Key = process_key(Tx, next_object),
    case get(Key) of
        [] ->
            erase(Key),
            {ok, {false, undefined}};
        [ObjAndId|Values] ->
            put(Key, Values),
            {ok, ObjAndId}
    end;
get_next_object(Tx, ['multi-object'|_] = Path, -1) ->
    put(process_key(Tx, next_multi_object), ?OBJECTS),
    get_next_object(Tx, Path, 1);
get_next_object(Tx, ['multi-object'|_] = Path, NextId) ->
    get_next_object2(Tx, Path, NextId, next_multi_object,
                     fun (ObjAndId) -> ObjAndId end);
get_next_object(Tx, ['find-next-multi-object'|_] = Path, -1) ->
    put(process_key(Tx, next_multi_object), ?OBJECTS),
    get_next_object(Tx, Path, 1);
get_next_object(Tx, ['find-next-multi-object'|_] = Path, NextId) ->
    get_next_object2(Tx, Path, NextId, next_multi_object,
                     fun ({Obj, _Id}) -> {Obj, -1} end).

get_next_object2(Tx, Path, NextId, Type, IdFun) ->
    Key = process_key(Tx, Type),
    NextObjId = NextId + 1,
    case get(Key) of
        [{_Obj, NextObjId} = ObjAndId1,ObjAndId2|Values] ->
            put(Key, Values),
            {ok, [IdFun(ObjAndId1), IdFun(ObjAndId2)], ?TIMEOUT};
        [{_Obj, NextObjId} = ObjAndId1] ->
            put(Key, []),
            {ok, [IdFun(ObjAndId1), false], ?TIMEOUT};
        _ ->
            {_, Objects} = lists:split(NextId - 1, ?OBJECTS),
            case Objects of
                [] ->
                    erase(Key),
                    {ok, {false, undefined}};
                _ ->
                    put(Key, Objects),
                    get_next_object(Tx, Path, NextId)
            end
    end.

find_next_object(Tx, [object|_], ?CONFD_FIND_NEXT, {FindKey}) ->
    Key = process_key(Tx, next_object),
    find_next_object2(Tx, FindKey, Key, ?OBJECTS);
find_next_object(Tx, ['multi-object'|_], ?CONFD_FIND_NEXT, {FindKey}) ->
    Key = process_key(Tx, next_multi_object),
    find_next_object2(Tx, FindKey, Key, ?OBJECTS);
find_next_object(Tx, ['find-next-multi-object'|_],
                 ?CONFD_FIND_NEXT, {FindKey}) ->
    Key = process_key(Tx, next_multi_object),
    Objects =
        case get(Key) of
            undefined ->
                case ?OBJECTS of
                    %% only allow new objects on the first element to
                    %% verify that the traversal id is used.
                    [{[FindKey|_], _}|_] ->
                        ?OBJECTS;
                    _ ->
                        []
                end;
            CachedObjects ->
                NObj = length(CachedObjects),
                lists:nthtail(length(?OBJECTS) - NObj - 1,
                              ?OBJECTS)
        end,
    find_next_object2(Tx, FindKey, Key, Objects).

find_next_object2(_Tx, FindKey, Key, Objects) ->
    case split(1, FindKey, Objects) of
        false ->
            erase(Key),
            {ok, {false, undefined}};
        [ObjAndId|Values] ->
            put(Key, Values),
            {ok, ObjAndId}
    end.

process_key(#confd_trans_ctx{traversal_id = TraversalId}, Type) ->
    {traversal, Type, TraversalId}.

split(_Key, []) ->
    false;
split(_Key, [_Last]) ->
    false;
split(Key, [Key|Rest]) ->
    Rest;
split(Key, [_|Rest]) ->
    split(Key, Rest).

split(_N, _Key, []) ->
    false;
split(_N, _Key, [_Last]) ->
    false;
split(N, Key, [{List,_Id}|Rest]) ->
    case lists:nth(N, List) of
        Key ->
            Rest;
        _ ->
            split(N, Key, Rest)
    end.
