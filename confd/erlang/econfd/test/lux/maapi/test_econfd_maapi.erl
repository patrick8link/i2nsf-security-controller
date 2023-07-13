-module(test_econfd_maapi).

-export([test/0]).

%%% include files
-include_lib("econfd/include/econfd.hrl").

-define(NS, 'urn:test:econfd:maapi').
-define(PERSONS, [<<"Bamse">>,<<"Farmor">>,<<"Lille Skutt">>]).

test() ->
    application:start(econfd),

    {ok, M} = econfd_maapi:connect({127,0,0,1}, ?CONFD_PORT),
    try
        ok = econfd_maapi:start_user_session(M, <<"admin">>, <<"maapi">>,
                                             [<<"admin">>],
                                             {127,0,0,1}, ?CONFD_PROTO_TCP),
        try
            {ok, Th} =
                econfd_maapi:start_trans(M, ?CONFD_RUNNING, ?CONFD_READ),
            Res =
                try
                    lists:foldl(
                      fun({Name, Fun}, Result) ->
                              case test(M, Th, Fun) of
                                  ok ->
                                      Result;
                                  {error, Stacktrace} ->
                                      io:format("ERROR~n~p~n", [Stacktrace]),
                                      [Name|Result]
                              end
                      end, [], [{test_maapi_xpath_get_next,
                                 fun test_maapi_xpath_get_next/2}])
                after
                    econfd_maapi:finish_trans(M, Th)
                end,
            case Res of
                [] ->
                    io:format("ALL READ OK~n", []);
                _ ->
                    io:format("~p ERROR(S)~n", [length(Res)])
            end,

            {ok, Th1} =
                econfd_maapi:start_trans(
                  M, ?CONFD_RUNNING, ?CONFD_READ_WRITE),
            try
                test_maapi_get_rollback_id(M, Th1)
            after
                econfd_maapi:finish_trans(M, Th1)
            end,

            io:format("ALL READ/WRITE OK~n", [])
        after
            econfd_maapi:end_user_session(M)
        end
    after
        econfd_maapi:close(M)
    end.

test(M, Th, Fun) ->
    try
        ok = Fun(M, Th)
    catch
        _:_:Stacktrace ->
            {error, Stacktrace}
    end.


%% test cases
test_maapi_xpath_get_next(M, Th) ->
    io:format("test_maapi_xpath_get_next~n", []),

    io:format("  * verify list traversal without xpath...", []),
    C = econfd_maapi:init_cursor(M, Th,
                                 [person,persons,maapi,[?NS|econfd_maapi]]),
    done = verify_list_get_next(C, ?PERSONS),
    io:format(" OK~n", []),

    io:format("  * verify list xpath age > 42...", []),
    C2 = econfd_maapi:init_cursor(M, Th,
                                  [person,persons,maapi,[?NS|econfd_maapi]],
                                  "age > 42"),
    done = verify_list_get_next(C2, [<<"Farmor">>]),
    io:format(" OK~n", []),

    io:format("  * verify list xpath age < 43...", []),
    C3 = econfd_maapi:init_cursor(M, Th,
                                  [person,persons,maapi,[?NS|econfd_maapi]],
                                  "age < 43"),
    done = verify_list_get_next(C3, [<<"Bamse">>, <<"Lille Skutt">>]),
    io:format(" OK~n", []),

    ok.

verify_list_get_next(C, []) ->
    done = econfd_maapi:get_next(C);
verify_list_get_next(C, [Key|Rest]) ->
    case econfd_maapi:get_next(C) of
        {ok, {Key}, C2} ->
            verify_list_get_next(C2, Rest)
    end.

test_maapi_get_rollback_id(M, Th) ->
    io:format("test_maapi_get_rollback_id~n", []),
    IKP = ['rollback-leaf',maapi,[?NS|econfd_maapi]],
    ok = econfd_maapi:set_elem(M, Th, IKP, ?CONFD_UINT64(erlang:system_time())),
    ok = econfd_maapi:apply_trans(M, Th, _KeepOpen = true, _Flags = 0),
    io:format("  * verify rollback id > -1...", []),
    case econfd_maapi:get_rollback_id(M, Th) of
        FixedNr when is_integer(FixedNr),
                     FixedNr > -1 ->
            io:format(" ~p OK~n", [FixedNr])
    end.
