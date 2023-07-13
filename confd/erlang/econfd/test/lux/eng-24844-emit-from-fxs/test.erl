-module(test).

-export([test/0]).

%%% include files
-include_lib("econfd/include/econfd.hrl").

-include_lib("withdef.hrl").

-define(NS, 'ba:se').

test() ->
    application:start(econfd),
    {ok, M} = econfd_maapi:connect({127,0,0,1}, ?CONFD_PORT),
    try
        ok = econfd_maapi:start_user_session(M, <<"admin">>, <<"test_context">>,
                                             [<<"admin">>],
                                             {127,0,0,1}, ?CONFD_PROTO_TCP),
        try
            {ok, Th} =
                econfd_maapi:start_trans(M, ?CONFD_RUNNING, ?CONFD_READ_WRITE),
            IKP = ['with-defaults',x,[?NS|'xbase-container']],
            Val = {?C_ENUM_VALUE, ?ncwd_report_all_tagged},
            X = econfd_maapi:set_elem(M, Th, IKP, Val),
            Res = econfd_maapi:get_elem(M, Th, IKP),
            ok = econfd_maapi:apply_trans(M, Th, _KeepOpen = true, _Flags = 0),
            io:format("result:~p~n", [Res])
        after
            econfd_maapi:end_user_session(M)
        end
    after
        econfd_maapi:close(M)
    end.
