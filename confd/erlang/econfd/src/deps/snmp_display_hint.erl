%%%-------------------------------------------------------------------
%%% @copyright 2012 Tail-f Systems AB
%%% @doc SMIv2 DISPLAY-HINT parser
%%% See RFC 2579.
%%%-------------------------------------------------------------------
-module(snmp_display_hint).
-export([compile_int_dh/1, compile_octet_string_dh/1,
         int_to_string/2, string_to_int/2,
         octet_string_to_string/2, string_to_octet_string/2
        ]).
-export_type([int_dh/0, octet_string_dh/0]).

%% integer-format specification
-record(ispec, {
          format :: hex | decimal | octal | binary,
          decimal_point :: undefined | non_neg_integer(),
          fread,
          fwrite
         }).

%% octet-format specification
-record(ospec, {
          repeat = false :: boolean(),
          length :: 'undefined' | non_neg_integer(),
          format :: 'undefined' | hex | decimal | octal | ascii | utf8,
          fread,
          fwrite,
          separator :: undefined | char(),
          terminator :: undefined | char()
         }).

-opaque int_dh() :: #ispec{}.
-opaque octet_string_dh() :: [#ospec{}].

-type octet_string() :: list(byte()).

%%% Exported functions

-spec compile_int_dh(string()) ->
        {ok, int_dh()}
      | {error, Reason :: term()}.
compile_int_dh(Str) ->
    try
        {ok, compile_int(Str)}
    catch
        throw:Error ->
            Error;
        _:_ ->
            {error, syntax_error}
    end.

-spec int_to_string(integer(), int_dh()) -> string().
%% @doc Convert an integer to a string.
%% Cannot fail, unless called with bad arguments.
int_to_string(Int, ISpec) ->
    i2s(Int, ISpec).

-spec string_to_int(string(), int_dh()) ->
        {ok, integer()}
      | {error, Reason :: term()}.
string_to_int(Str, ISpec) ->
    try
        {ok, s2i(Str, ISpec)}
    catch
        throw:Error ->
            Error;
        _:_ ->
            {error, syntax_error}
    end.

-spec compile_octet_string_dh(string()) ->
        {ok, octet_string_dh()}
      | {error, Reason :: term()}.
compile_octet_string_dh(Str) ->
    try
        {ok, compile_str(Str)}
    catch
        throw:Error ->
            Error;
        _:_ ->
            {error, syntax_error}
    end.

-spec octet_string_to_string(octet_string(), octet_string_dh()) -> string().
%% @doc Convert an octet string to a string.
%% Cannot fail, unless called with bad arguments.
octet_string_to_string(L, OSpecs) ->
    lists:flatten(os2s_1(L, OSpecs)).

-spec string_to_octet_string(string(), octet_string_dh()) ->
        {ok, octet_string()}
      | {error, Reason :: term()}.
string_to_octet_string(Str, OSpecs) ->
    try
        {ok, s2os(Str, OSpecs)}
    catch
        throw:Error ->
            Error;
        _:_:_Stacktrace ->
            %io:format("** ~p\n~p\n\n", [_X, Stacktrace]),
            {error, syntax_error}
    end.

%%% Internal functions

compile_int([$d, $- | T]) ->
    #ispec{format = decimal,
           decimal_point = list_to_integer(T)};
compile_int([$d]) ->
    #ispec{format = decimal,
           fwrite = {"~w", []}};
compile_int([$x]) ->
    #ispec{format = hex,
           fwrite = {"~.16X", ["0x"]},
           fread = "~16u"};
compile_int([$o]) ->
    #ispec{format = octal,
           fwrite = {"~.8X", ["0"]},
           fread = "~8u"};
compile_int([$b]) ->
    #ispec{format = binary,
           fwrite = {"~.2B", []},
           fread = "~2u"}.

compile_str(Str) ->
    compile_str1(Str, #ospec{}).

%% optional repeat indicator
compile_str1([$* | T], OSpec) ->
    compile_str2(T, OSpec#ospec{repeat = true});
compile_str1(Str, OSpec) ->
    compile_str2(Str, OSpec).

%% mandatory octet length
compile_str2([H | _] = Str, OSpec) when H >= $0, H =< $9 ->
    {ok, [Int], T} = io_lib:fread("~d", Str),
    compile_str3(T, OSpec#ospec{length = Int}).

%% mandatory display format
compile_str3([H | T], OSpec) ->
    Format =
        case H of
            $x -> hex;
            $d -> decimal;
            $o -> octal;
            $a -> ascii;
            $t -> utf8
        end,
    Fread =
        case Format of
            hex -> "~16u";
            octal -> "~8u";
            decimal -> "~u";
            _ -> undefined
        end,
    Fwrite =
        case Format of
            hex -> "~.16B";
            octal -> "~.8B";
            decimal -> "~w";
            _ -> undefined
        end,
    compile_str4(T, OSpec#ospec{format = Format,
                                fread = Fread, fwrite = Fwrite}).

%% optional display separator
compile_str4([H | T], OSpec) when H /= '*' andalso (H < $0 orelse H > $9) ->
    compile_str5(T, OSpec#ospec{separator = H});
compile_str4(Str, OSpec) ->
    compile_str_final(Str, OSpec).

%% optional repeat terminator
compile_str5([H | T], #ospec{repeat = true} = OSpec)
  when H /= '*' andalso (H < $0 orelse H > $9) ->
    compile_str_final(T, OSpec#ospec{terminator = H});
compile_str5(Str, OSpec) ->
    compile_str_final(Str, OSpec).

compile_str_final([], OSpec) ->
    validate_ospec(OSpec),
    [OSpec];
compile_str_final(Str, OSpec) ->
    %% parse more octet-format specifications
    validate_ospec(OSpec),
    [OSpec | compile_str(Str)].

validate_ospec(#ospec{length = 0, separator = undefined}) ->
    throw(error);
validate_ospec(_OSpec) ->
    ok.

i2s(Int, #ispec{format = decimal, decimal_point = undefined}) ->
    integer_to_list(Int);
i2s(Int, #ispec{format = decimal, decimal_point = Point}) ->
    Str = integer_to_list(abs(Int)),
    Len = length(Str),
    if Int < 0 ->
            "-";
       true ->
            ""
    end ++
        if Len =< Point ->
                %% less digits than point, fill with zeros
                [$0, $. | lists:duplicate(Point-Len, $0)] ++ Str;
           true ->
                shift(Str, Len, Point)
        end;
i2s(Int, #ispec{fwrite = {Format, Args}}) ->
    lists:flatten(io_lib:fwrite(Format, [Int | Args])).

shift(Str, Len, Len) ->
    [$. | Str];
shift([H | T], Len, Point) ->
    [H | shift(T, Len-1, Point)].

s2i(Str, #ispec{format = decimal}) ->
    %% just remove the optional decimal point and parse
   list_to_integer(Str -- [$.]);
s2i("-" ++ T, ISpec) ->
    - s2i(T, ISpec);
s2i("0x" ++ Str, #ispec{format = hex, fread = Fmt}) ->
    {ok, [Int], []} = io_lib:fread(Fmt, Str),
    Int;
s2i("0" ++ Str, #ispec{format = octal, fread = Fmt}) ->
    {ok, [Int], []} = io_lib:fread(Fmt, Str),
    Int;
s2i(Str, #ispec{fread = Fmt}) ->
    {ok, [Int], []} = io_lib:fread(Fmt, Str),
    Int.

os2s_1([RepeatCount | T], [#ospec{repeat = true} = S | OSpecs]) ->
    os2s(T, RepeatCount, S, OSpecs);
os2s_1(L, [S | OSpecs]) ->
    os2s(L, 1, S, OSpecs).

os2s(L, RepeatCount, S, OSpecs) ->
    case os2s_2(L, S, RepeatCount == 1) of
        {Str, []} ->
            %% no more octets to consume
            Str;
        {Str, Rest} when RepeatCount > 1 ->
            %% re-use last one once again, since repeat count > 1
            [Str, os2s(Rest, RepeatCount - 1, S, OSpecs)];
        {Str, Rest} when RepeatCount == 1, OSpecs /= [] ->
            %% we have more octet-format specifications, use the next one
            [Str, os2s_1(Rest, OSpecs)];
        {Str, Rest} when OSpecs == [] ->
            %% no more octet-format specifications, re-use the last one
            [Str, os2s_1(Rest, [S])]
    end.

os2s_2([], _, _IsLast) ->
    {[], []};
os2s_2(L, S, IsLast) ->
    {L1Rev, L2} = take(L, S#ospec.length, []),
    L1 = lists:reverse(L1Rev),
    Fmt = S#ospec.fwrite,
    Str1 = case Fmt of
               undefined ->
                   L1;
               _ ->
                   io_lib:fwrite(Fmt, [octets_to_int(L1)])
           end,
    Str2 = if L2 == [] ->
                   %% supress terminator or separator
                   [];
              IsLast, S#ospec.terminator /= undefined ->
                   [S#ospec.terminator];
              S#ospec.separator /= undefined ->
                   [S#ospec.separator];
              true ->
                   []
           end,
    {[Str1, Str2], L2}.

s2os([], _) ->
    [];
s2os(Str, [S | OSpecs]) ->
    case S#ospec.repeat of
        true ->
            %% we need to count the number of times this spec
            %% was used, and use that number as the first octet
            {L, Str2, RepeatCount} = parse_with_one_ospec(Str, S),
            Octets = [RepeatCount | L];
        false ->
            {Octets, Str2, _} = parse_with_one_ospec(Str, S)
    end,
    if OSpecs == [], Octets /= [] ->
            %% No more octet specs; re-use the last one.
            %% Octets /= [] means we consumed something, so we won't
            %% go into a loop here.
            Octets ++ s2os(Str2, [S]);
       true ->
            Octets ++ s2os(Str2, OSpecs)
    end.

-spec parse_with_one_ospec(string(), #ospec{}) ->
         {octet_string(), Rest :: string(), RepeatCount :: non_neg_integer()}.
parse_with_one_ospec(Str, OSpec) ->
    parse_with_one_ospec(Str, OSpec, 0, []).

parse_with_one_ospec([], _, N, Acc) ->
    {lists:reverse(Acc), [], N};
parse_with_one_ospec([_H | _T] = Str, S, N, Acc) ->
    #ospec{separator = Separator, terminator = Terminator, format = Format} = S,
    case S#ospec.length of
        0 ->
            %% no octets, continue
            parse_with_one_ospec_2(Str, S, N, Acc);
        Len when Format == ascii orelse Format == utf8->
            %% just consume the bytes, we don't do any conversion
            {Acc2, Str2} = take(Str, Len, Acc),
            parse_with_one_ospec_2(Str2, S, N, Acc2);
        Len when Separator /= undefined;
                 Terminator /= undefined ->
            %% scan for the separator or terminator
            {Str1, Str2} = split_with_separator(Str, Separator, Terminator, []),
            %% convert Str1 according to the format, producing Len bytes
            Fmt = S#ospec.fread,
            {ok, [Int], []} = io_lib:fread(Fmt, Str1),
            Octets = int_to_octets(Int, Len),
            parse_with_one_ospec_2(Str2, S, N, lists:reverse(Octets) ++ Acc);
        Len ->
            %% convert Str according to the format
            Fmt = S#ospec.fread,
            {_, [Int], Str2} = io_lib:fread(Fmt, Str),
            Octets = int_to_octets(Int, Len),
            parse_with_one_ospec_2(Str2, S, N, lists:reverse(Octets) ++ Acc)
    end.

parse_with_one_ospec_2([], _S, N, Acc) ->
    {lists:reverse(Acc), [], N+1};
parse_with_one_ospec_2([T|Str], #ospec{terminator = T}, N, Acc) ->
    {lists:reverse(Acc), Str, N+1};
parse_with_one_ospec_2([Sep|Str], #ospec{separator = Sep} = S, N, Acc) ->
    parse_with_one_ospec_2(Str, S, N, Acc);
parse_with_one_ospec_2(Str, S, N, Acc) ->
    case S#ospec.repeat of
        true ->
            parse_with_one_ospec(Str, S, N+1, Acc);
        false ->
            {lists:reverse(Acc), Str, N+1}
    end.


take(Str, 0, Acc) ->
    {Acc, Str};
take([H | T], Len, Acc) ->
    take(T, Len-1, [H | Acc]);
take([], _, Acc) ->
    {Acc, []}.

octets_to_int(L) ->
    octets_to_int(L, 0).

octets_to_int([H | T], Acc) ->
    octets_to_int(T, H + (Acc bsl 8));
octets_to_int([], Acc) ->
    Acc.

int_to_octets(Int, Len) ->
    int_to_octets(Int, Len, []).

int_to_octets(0, Len, Acc) ->
    lists:duplicate(Len, 0) ++ Acc;
int_to_octets(N, Len, Acc) ->
    int_to_octets(N bsr 8, Len - 1, [N rem 256 | Acc]).

split_with_separator([Separator | _] = T, Separator, _Terminator, Acc) ->
    {lists:reverse(Acc), T};
split_with_separator([Terminator | _] = T, _Separator, Terminator, Acc) ->
    {lists:reverse(Acc), T};
split_with_separator([H | T], Separator, Terminator, Acc) ->
    split_with_separator(T, Separator, Terminator, [H | Acc]);
split_with_separator([], _, _, Acc) ->
    {lists:reverse(Acc), []}.

