%%% ----------------------------------------------------------------------------
%%% Created: 22 March 2021 by perander@cisco.com
%%% ----------------------------------------------------------------------------
-module(test_econfd_maapi).

-export([fail/0, pass/0]).


-include("econfd.hrl").
-include("econfd_errors.hrl").

-define(NS, 'urn:test').


maapi(Fun) ->
    application:start(econfd),
    {ok, M} = econfd_maapi:connect({127,0,0,1}, ?CONFD_PORT),
    try
        ok = econfd_maapi:start_user_session(M, <<"admin">>, <<"maapi">>,
                                             [<<"admin">>],
                                             {127,0,0,1}, ?CONFD_PROTO_TCP),
        try
            {ok, Th} =
                econfd_maapi:start_trans(M, ?CONFD_RUNNING, ?CONFD_READ_WRITE),
            try
                Fun(M, Th)
            after
                econfd_maapi:finish_trans(M, Th)
            end
        after
            econfd_maapi:end_user_session(M)
        end
    after
        econfd_maapi:close(M)
    end.

fail() ->
    maapi(
      fun(M, Th) ->
              IKP = [a_leaf, [?NS|test]],
              Error = {error, {?CONFD_ERR_BADTYPE,
                               <<"\"é\" is not a valid value.">>}} =
                  econfd_maapi:set_elem(M, Th, IKP, <<16#e9>>),
              io:format("~p~n", [Error])
      end).


pass() ->
    maapi(
      fun(M, Th) ->
              IKP = [a_leaf, [?NS|test]],
              ok = econfd_maapi:set_elem(M, Th, IKP, <<16#e9>>),
              io:format("ok~n")
      end).
