%% @doc Yanger plugin converting posix regexes (used by OpenConfig
%% models) to w3c regexes required by the standard.
%%
%% At this point only leading and terminating anchors are removed.
%%
%% @author mvolf@cisco.com

-module(yanger_oc).
-behaviour(yanger_plugin).

-export([init/1]).

-include_lib("yanger/include/yang.hrl").

-define(OC_EXT_POSIX, {'openconfig-extensions','regexp-posix'}).

-define(PARENT_STATEMENTS,
        [module, submodule, container, list, choice, 'case', 'leaf-list', leaf,
         grouping, uses, augment, typedef, type, union]).

init(Ctx) ->
    Ctx1 = yanger_plugin:register_hook(Ctx, #hooks.mk_type, fun pattern_fix_hook/3),
    yanger_plugin:register_transform(Ctx1, oc, fun oc_transform/2).

oc_transform(_Ctx, Modules) ->
    [transform_module(Module) || Module <- Modules].

pattern_fix_hook(Ctx, Type=#type{base=string, type_spec=TS}, M) ->
    case module_uses_posix(M) of
        true ->
            #string_type_spec{patterns=Ptrns} = TS,
            NewPtrns = lists:map(fun fix_spec_pattern/1, Ptrns),
            {Ctx, Type#type{type_spec=TS#string_type_spec{patterns=NewPtrns}}};
        false ->
            {Ctx, Type}
    end;
pattern_fix_hook(Ctx, Type, _) ->
    {Ctx, Type}.

module_uses_posix(M) ->
    yang:search_one_substmt(?OC_EXT_POSIX, M#module.stmt) /= false.

fix_spec_pattern(Pat={_W3Re, Regex, Invert}) ->
    case fix_pattern(Regex) of
        Regex ->
            Pat;
        Fixed ->
            {ok, Re} = w3cregex:compile(Fixed),
            {Re, Fixed, Invert}
    end.

transform_module(Module) ->
    case module_uses_posix(Module) of
        true ->
            Module#module{stmt=fix_statement(Module#module.stmt)};
        false ->
            Module
    end.

fix_statement(Stm={pattern, Pattern, Pos, Stmts}) ->
    case fix_pattern(Pattern) of
        Pattern ->
            Stm;
        FixPattern ->
            {pattern, FixPattern, Pos, Stmts}
    end;
fix_statement(S={Kwd, Arg, Pos, Stmts}) ->
    case lists:member(Kwd, ?PARENT_STATEMENTS) of
        true ->
            {Kwd, Arg, Pos, [fix_statement(Stmt) || Stmt <- Stmts]};
        false ->
            S
    end.

fix_pattern(<<"^", Rest/binary>>) ->
    fix_pattern_end(Rest);
fix_pattern(Pattern) ->
    %% unanchored pattern
    fix_pattern_end(<<".*", Pattern/binary>>).

fix_pattern_end(Pattern) ->
    Len = size(Pattern)-1,
    case Pattern of
        <<Main:Len/binary, "$">> ->
            Main;
        _ ->
            %% unanchored pattern
            <<Pattern/binary, ".*">>
    end.
