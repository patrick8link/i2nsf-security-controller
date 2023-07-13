%%%-------------------------------------------------------------------
%%% @copyright 2006 Tail-F Systems AB
%%% @version {$Id$}
%%% @doc An Erlang interface equivalent to the confd_lib_dp C-API
%%% (documented in confd_lib_dp(3)).
%%%
%%% This module is used to connect to ConfD and provide callback
%%% functions so that ConfD can populate its northbound agent
%%% interfaces with external data.  Thus the library consists of a
%%% number of API functions whose purpose is to install different
%%% callback functions at different points in the XML tree which is
%%% the representation of the device configuration. Read more about
%%% callpoints in the ConfD User Guide.
%%% @end
%%%-------------------------------------------------------------------

-module(econfd).
-export([start/0,
         init_daemon/6,
         set_debug/3,
         set_daemon_d_opaque/2,
         set_daemon_flags/2,
         stop_daemon/1,
         register_trans_cb/2,
         register_trans_validate_cb/2,
         register_db_cbs/2,
         register_data_cb/2,
         register_data_cb/3,
         register_range_data_cb/5,
         register_valpoint_cb/2,
         register_action_cb/2,
         register_authentication_cb/2,
         register_service_cb/2,
         register_nano_service_cb/4,
         register_done/1,
         pp_value/1,
         pp_kpath/1,
         decrypt/1,
         controlling_process/2,
         bitbig_set_bit/2,
         bitbig_clr_bit/2,
         bitbig_bit_is_set/2]).

-export([data_reply_ok/1,
         data_reply_value/2,
         data_reply_next_key/3,
         data_reply_not_found/1,
         data_reply_value_array/2,
         data_reply_tag_value_array/2,
         data_reply_next_object_value_array/3,
         data_reply_next_object_tag_value_array/3,
         data_reply_next_object_value_arrays/3,
         data_reply_found/1,
         data_reply_error/2,
         data_set_timeout/2,
         data_get_list_filter/1,
         data_set_filtered/2,
         action_set_timeout/2]).

-export([notification_send/3,
         notification_send/4,
         notification_replay_complete/1,
         notification_replay_failed/2,
         register_notification_stream/2]).

-export([log/2,
         log/3,
         log/4]).

-import(econfd_internal,
        [
         term_write/2,
         term_write/3
        ]).

%% application internal exports, used by other econfd modules
-export([mk_uinfo/1, mk_uinfo/2, report_err/4]).
-export([trans_put/3, trans_get/3, trans_erase/3]).

%% used by the Makefile to do edoc
-export([doc_application/1]).

-include("../include/econfd.hrl").
-include("../include/econfd_errors.hrl").
-include("../include/econfd_list_filter.hrl").
-include("econfd_internal.hrl").
-include("econfd_proto.hrl").

%%% types
-export_type(
   [socket/0, value/0, qtag/0, key/0, ikeypath/0, tagpath/0, type/0,
    namespace/0, tag_val_object/0, tag_val_object_next/0, vals/0, vals_next/0,
    objects/0, datetime_date_and_time/0, datetime/0, error_reason/0, ip/0,
    connect_result/0, tagval/0, transport_error/0
   ]).
-export_type(
   [cb_exists_optional/0, cb_get_elem/0, cb_get_next/0,
    cb_find_next/0, cb_num_instances/0, cb_get_object/0, cb_get_next_object/0,
    cb_find_next_object/0, cb_set_elem/0, cb_create/0, cb_remove/0,
    cb_get_attrs/0, cb_set_attr/0, cb_move_after/0, cb_write_all/0,
    cb_validate/0, cb_action/0, cb_completion_action/0, cb_ctx/0,
    cb_trans_lock/0, cb_write/0, cb_ok/0, cb_candidate_commit/0, cb_db/0,
    cb_lock_partial/0, cb_unlock_partial/0, cb_ok_db/0, cb_authentication/0,
    cb_get_log_times/0, cb_replay/0, cb_str_to_val/0, cb_val_to_str/0,
    cb_validate_value/0, cb_get_case/0, cb_set_case/0, list_filter_type/0,
    list_filter_op/0
   ]).

-type socket() :: port() | int_ipc:sock().
%% When running econfd internally the socket is a tuple.

-type connect_result() :: {'ok', socket()} |
                          {'error', error_reason()} |
                          {'error', atom()}.
%% This is the return type of connect() function.

-type ipv4() :: {0..255, 0..255, 0..255, 0..255}.
-type ipv6() :: {0..65535, 0..65535, 0..65535, 0..65535,
                 0..65535, 0..65535, 0..65535, 0..65535}.
-type ip() :: ipv4() | ipv6().
%% 4-tuples for IP v4 addresses and 8-tuples for IP v6 addresses.

-type value() :: binary() | tuple() | float() | boolean() | integer() | qtag() |
                 {Tag :: integer(), Value :: term()} | [value()] | 'not_found' |
                 'default'.
%% This type is central for this library. Values are returned from the CDB
%% functions, they are used to read and write in the MAAPI module and they
%% are also used as keys in ikeypath().
%%
%% We have the following value representation for the data model types
%%<ul>
%% <li> string - Always represented as a single binary. </li>
%% <li> int32  - This is represented as a single integer. </li>
%% <li> int8   - {?C_INT8, Val} </li>
%% <li> int16  - {?C_INT16, Val} </li>
%% <li> int64  - {?C_INT64, Val} </li>
%% <li> uint8  - {?C_UINT8, Val} </li>
%% <li> uint16 - {?C_UINT16, Val} </li>
%% <li> uint32 - {?C_UINT32, Val} </li>
%% <li> uint64 - {?C_UINT64, Val} </li>
%% <li> inet:ipv4-address - 4-tuple </li>
%% <li> inet:ipv4-address-no-zone - 4-tuple </li>
%% <li> inet:ipv6-address - 8-tuple </li>
%% <li> inet:ipv6-address-no-zone - 8-tuple </li>
%% <li> boolean - The atoms 'true' or 'false' </li>
%% <li> xs:float() and xs:double() - Erlang floats </li>
%% <li> leaf-list - An erlang list of values. </li>
%% <li> binary, yang:hex-string, tailf:hex-list (etc) -
%%      {?C_BINARY, binary()} </li>
%% <li> yang:date-and-time - {?C_DATETIME, datetime_date_and_time()} </li>
%% <li> xs:duration - {?C_DURATION, {Y,M,D,H,M,S,Mcr}} </li>
%% <li> instance-identifier - {?C_OBJECTREF, econfd:ikeypath()} </li>
%% <li> yang:object-identifier - {?C_OID, Int32Binary}, where Int32Binary is a
%%      binary with OID compontents as 32-bit integers in the default
%%      big endianness. </li>
%% <li> yang:dotted-quad - {?C_DQUAD, binary()} </li>
%% <li> yang:hex-string  - {?C_HEXSTR, binary()} </li>
%% <li> inet:ipv4-prefix - {?C_IPV4PREFIX, {{A,B,C,D}, PrefixLen}} </li>
%% <li> inet:ipv6-prefix - {?C_IPV6PREFIX, {{A,B,C,D,E,F,G,H}, PrefixLen}} </li>
%% <li> tailf:ipv4-address-and-prefix-length -
%%      {?C_IPV4_AND_PLEN, {{A,B,C,D}, PrefixLen}} </li>
%% <li> tailf:ipv6-address-and-prefix-length -
%%      {?C_IPV6_AND_PLEN, {{A,B,C,D,E,F,G,H}, PrefixLen}} </li>
%% <li> decimal64 - {?C_DECIMAL64, {Int64, FractionDigits}} </li>
%% <li> identityref - {?C_IDENTITYREF, {NsHash, IdentityHash}} </li>
%% <li> bits - {?C_BIT32, Bits::integer()}, {?C_BIT64, Bits::integer()}, or
%%      {?C_BITBIG, Bits:binary()}
%%      depending on the highest bit position assigned </li>
%% <li> enumeration - {?C_ENUM_VALUE, IntVal}, where IntVal is the integer
%%      value for a given "enum" statement according to the YANG specification.
%%      When we have compiled a YANG module into a .fxs file, we can use the
%%      --emit-hrl option to confdc(1) to create a .hrl file with macro
%%      definitions for the enum values. </li>
%%</ul>
%%
%% There is also a "pseudo type" that indicates a non-existing value,
%% which is represented as the atom 'not_found'.
%% Finally there is a "pseudo type" to indicate that a leaf with a default
%% value defined in the data model does not have a value set - this is
%% represented as the atom 'default'.
%%
%% For all of the abovementioned (non-"pseudo") types we have the corresponding
%% macro in econfd.hrl. We strongly suggest that the ?CONFD_xxx macros are used
%% whenever we either want to construct a value or match towards a value:
%% Thus we write code as:
%% <pre>
%%  case econfd_cdb:get_elem(...) of
%%      {ok, ?CONFD_INT64(42)} ->
%%          foo;
%%
%% or
%%  econfd_cdb:set_elem(... ?CONFD_INT64(777), ...)
%%
%% or
%%  {ok, ?CONFD_INT64(I)} = econfd_cdb:get_elem(...)
%%
%%</pre>

-type datetime_date_and_time() :: {
    Year::integer(), Month::integer(), Day::integer(),
    Hour::integer(), Minute::integer(), Second::integer(),
    MicroSecond::integer(),
    TZ::integer(), TZMinutes::integer()}.

-type datetime() :: {C_DATETIME::integer(), datetime_date_and_time()}.
%% The value representation for yang:date-and-time, also used in the
%% API functions for notification streams.

-type key() :: {value()} | [Index::integer()].
%% Keys are parts of ikeypath(). In the YANG data model we define how many
%% keys a list node has. If we have 1 key, the key is an arity-1
%% tuple, 2 keys - an arity-2 tuple and so forth.
%% The [Index] notation is only valid for keys in ikeypaths when we use CDB.

-type tag_cons(T1, T2) :: nonempty_improper_list(T1, T2).
-type namespace() :: atom().
-type tag() :: atom().

-type qtag() :: tag() | tag_cons(namespace(), tag()).
%% A "qualified tag" is either a single tag or a pair of a namespace and a
%% tag.  An example could be 'interface' or
%% ['http://example.com/ns/interfaces/2.1' | interface]

-type ikeypath() :: [qtag() | key()].
%% An ikeypath() is a list describing a path down into the data tree.
%% The Ikeypaths are used to denote specific objects in the XML instance
%% document.  The list is in backwards order, thus the head of the list
%% is the leaf element.  All the data callbacks defined in
%% #confd_data_cbs{} receive ikeypath() lists as an argument.  The last
%% (top) element of the list is a pair `[NS|XmlTag]' where NS is
%% the atom defining the XML namespace of the XmlTag and
%% XmlTag is an XmlTag::atom() denoting the toplevel XML element.
%% Elements in the list that have a different namespace than their parent
%% are also qualified through such a pair with the element's namespace,
%% but all other elements are represented by their unqualified tag() atom.
%% Thus an ikeypath() uniquely addresses an instance of an element in
%% the configuration XML tree.  List entries are
%% identified by an element in the ikeypath() list expressed as {Key}
%% or, when we are using CDB, as [Integer]. During an individual CDB
%% session all the elements are implictly numbered, thus we can through
%% a call to econfd_cdb:num_instances/2 retrieve how many entries (N)
%% for a given list that we have, and then retrieve those entries
%% (0 - (N-1)) inserting [I] as the key.

-type tagpath() :: [qtag()].
%% A tagpath() is a list describing a path down into the schema tree.
%% I.e. as opposed to an ikeypath(), it has no instance information.
%% Additionally the last (top) element is not `[NS|XmlTag]' as in
%% ikeypath(), but only `XmlTag' - i.e. it needs to be combined with
%% a namespace to uniquely identify a schema node. The other elements
%% in the path are qualified - or not - exactly as for ikeypath().

-type tagval() :: {qtag(), value() |
                   'start' | {'start', Index :: integer()} |
                   'stop' | 'leaf' | 'delete'}.
%% This is used to represent XML elements together with their values,
%% typically in a list representing an XML subtree as in the arguments
%% and result of the 'action' callback. Typeless elements have the
%% special "values":<ul>
%% <li>`start' - opening container or list element.</li>
%% <li>`{start, Index :: integer()}' - opening list element with CDB Index
%% instead of key value(s) - only valid for CDB access.</li>
%% <li>`stop' - closing container or list element.</li>
%% <li>`leaf' - leaf with type "empty".</li>
%% <li>`delete' - delete list entry.</li></ul>
%% The qtag() tuple element may have the namespace()-less form (i.e. tag()) for
%% XML elements in the "current" namespace. For a detailed description of how to
%% represent XML as a list of tagval() elements, please refer to the "Tagged
%% Value Array" specification in the XML STRUCTURES section of the
%% confd_types(3) manual page.

-type type() :: term().
%% Identifies a type definition in the schema.

-type error_reason() :: binary() | #confd_error{} | tuple().
%% The callback functions may return errors either as a plain string
%% or via a #confd_error{} record - see econfd.hrl and the section EXTENDED
%% ERROR REPORTING in confd_lib_lib(3) (tuple() is only for internal
%% ConfD/NCS use). {error, String} is equivalent to
%% {error, #confd_error{ code = application, str = String }}.

-type transport_error() :: 'timeout' | 'closed'.

-type tag_val_object() :: {'exml', [TV::tagval()]}.
-type tag_val_object_next() :: {tag_val_object(), Next::term()}.

-type vals() :: [V::value()].
-type vals_next() :: {vals(), Next::term()}.

-type objects() :: [vals_next() | tag_val_object_next() | 'false'].

-type confd_trans_ctx() :: #confd_trans_ctx{}.

-type cb_exists_optional_reply() :: boolean().
-type cb_exists_optional() ::
    fun((T::confd_trans_ctx(), KP::ikeypath()) ->
        {'ok', cb_exists_optional_reply()}
      | {'ok', cb_exists_optional_reply(), confd_trans_ctx()}
      | {'error', error_reason()} | 'delayed_response').
%% This is the callback for #confd_data_cbs.exists_optional.
%% The exists_optional callback must be present
%% if our YANG model has presence containers or leafs of type empty.

-type cb_get_elem_reply() :: value() | 'not_found'.
-type cb_get_elem() ::
    fun((T::confd_trans_ctx(), KP::ikeypath()) ->
        {'ok', cb_get_elem_reply()}
      | {'ok', cb_get_elem_reply(), confd_trans_ctx()}
      | {'error', error_reason()} | 'delayed_response').
%% This is the callback for #confd_data_cbs.get_elem.

-type cb_get_next_reply() :: {Key::key(), Next::term()}
                           | {'false', 'undefined'}.
-type cb_get_next() ::
    fun((T::confd_trans_ctx(), KP::ikeypath(), Prev::term()) ->
        {'ok', cb_get_next_reply()}
      | {'ok', cb_get_next_reply(), confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% This is the callback for #confd_data_cbs.get_next.  Prev is
%% the integer -1 on the first call.

-type cb_find_next_reply() :: {Key::key(), Next::term()}
                            | {'false', 'undefined'}.
-type cb_find_next() ::
    fun((T::confd_trans_ctx(), KP::ikeypath(), FindNextType::integer(),
         PrevKey::key()) ->
        {'ok', cb_find_next_reply()}
      | {'ok', cb_find_next_reply(), confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% This is the callback for #confd_data_cbs.find_next.

-type cb_num_instances_reply() :: integer().
-type cb_num_instances() ::
    fun((T::confd_trans_ctx(), KP::ikeypath()) ->
        {'ok', cb_num_instances_reply()}
      | {'ok', cb_num_instances_reply(), confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% Optional callback, if it doesn't exist it will be emulated
%% by consecutive calls to get_next().
%% It is the callback for #confd_data_cbs.num_instances.

-type cb_get_object_reply() ::
    vals() | tag_val_object() | 'not_found'.
-type cb_get_object() ::
    fun((T::confd_trans_ctx(), KP::ikeypath()) ->
        {'ok', cb_get_object_reply()}
      | {'ok', cb_get_object_reply(), confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% Optional callback which is used to return an entire object.
%% It is the callback for #confd_data_cbs.get_object.
%% For a detailed description of the two forms of the value list,
%% please refer to the "Value Array" and "Tag Value Array" specifications,
%% respectively, in the XML STRUCTURES section of the confd_types(3)
%% manual page.

-type cb_get_next_object_reply() ::
    vals_next() | tag_val_object_next() | {'false', 'undefined'}.
-type cb_get_next_object() ::
    fun((T::confd_trans_ctx(), KP::ikeypath(), Prev::term()) ->
        {'ok', cb_get_next_object_reply()}
      | {'ok', cb_get_next_object_reply(), confd_trans_ctx()}
      | {'ok', objects(), TimeoutMillisecs::integer()}
      | {'ok', objects(), TimeoutMillisecs::integer(), confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% Optional callback which combines the functionality of
%% get_next() and get_object(), and adds the possibility
%% to return multiple objects.
%% It is the callback for #confd_data_cbs.get_next_object.
%% For a detailed description of the two forms of the value list,
%% please refer to the "Value Array" and "Tag Value Array" specifications,
%% respectively, in the XML STRUCTURES section of the confd_types(3)
%% manual page.

-type cb_find_next_object_reply() ::
    vals_next() | tag_val_object_next() | {'false', 'undefined'}.
-type cb_find_next_object() ::
    fun((T::confd_trans_ctx(), KP::ikeypath(), FindNextType::integer(),
         PrevKey::key()) ->
        {'ok', cb_find_next_object_reply()}
      | {'ok', cb_find_next_object_reply(), confd_trans_ctx()}
      | {'ok', objects(), TimeoutMillisecs::integer()}
      | {'ok', objects(), TimeoutMillisecs::integer(), confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% Optional callback which combines the functionality of
%% find_next() and get_object(), and adds the possibility
%% to return multiple objects.
%% It is the callback for #confd_data_cbs.find_next_object.
%% For a detailed description of the two forms of the value list,
%% please refer to the "Value Array" and "Tag Value Array" specifications,
%% respectively, in the XML STRUCTURES section of the confd_types(3)
%% manual page.

-type cb_set_elem() ::
    fun((T::confd_trans_ctx(), KP::ikeypath(),Value::value()) ->
        'ok'
      | {'ok', confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% It is the callback for #confd_data_cbs.set_elem. Only used
%% when we use external database config data, e.g. not for statistics.

-type cb_create() ::
    fun((T::confd_trans_ctx(), KP::ikeypath()) ->
        'ok'
      | {'ok', confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% It is the callback for #confd_data_cbs.create. Only used
%% when we use external database config data, e.g. not for statistics.

-type cb_remove() ::
    fun((T::confd_trans_ctx(), KP::ikeypath()) ->
        'ok'
      | {'ok', confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% It is the callback for #confd_data_cbs.remove. Only used
%% when we use external database config data, e.g. not for statistics.

-type cb_get_case_reply() :: Case::qtag() | 'not_found'.

-type cb_get_case() ::
    fun((T::confd_trans_ctx(), KP::ikeypath(), ChoicePath::[qtag()]) ->
        {'ok', cb_get_case_reply()}
      | {'ok', cb_get_case_reply(), confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% This is the callback for #confd_data_cbs.get_case. Only used when we
%% use 'choice' in the data model.
%% Normally ChoicePath is just a single element with the name of the
%% choice, but if we have nested choices without intermediate data nodes,
%% it will be similar to an ikeypath, i.e. a reversed list of choice and
%% case names giving the path through the nested choices.

-type cb_set_case() ::
    fun((T::confd_trans_ctx(), KP::ikeypath(),
         ChoicePath::[qtag()], Case :: qtag() | '$none') ->
        'ok'
      | {'ok', confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% This is the callback for #confd_data_cbs.set_case. Only used when we
%% use 'choice' in the data model. Case == '$none'
%% means that no case is chosen (i.e. all have been deleted).
%% Normally ChoicePath is just a single element with the name of the
%% choice, but if we have nested choices without intermediate data nodes,
%% it will be similar to an ikeypath, i.e. a reversed list of choice and
%% case names giving the path through the nested choices.

-type cb_get_attrs_reply() :: [{Attr::integer(), V::value()}] | 'not_found'.

-type cb_get_attrs() ::
    fun((T::confd_trans_ctx(), KP::ikeypath(), [Attr::integer()]) ->
        {'ok', cb_get_attrs_reply()}
      | {'ok', cb_get_attrs_reply(), confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% This is the callback for #confd_data_cbs.get_attrs.

-type cb_set_attr_value() :: value() | 'undefined'.

-type cb_set_attr() ::
    fun((T::confd_trans_ctx(), KP::ikeypath(),
         Attr::integer(), cb_set_attr_value()) ->
        'ok'
      | {'ok', confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% This is the callback for #confd_data_cbs.set_attr. Value == undefined
%% means that the attribute should be deleted.

-type cb_move_after() ::
    fun((T::confd_trans_ctx(), KP::ikeypath(), PrevKeys::{value()}) ->
        'ok'
      | {'ok', confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% This is the callback for #confd_data_cbs.move_after. PrevKeys == {}
%% means that the list entry should become the first one.

-type cb_write_all() ::
    fun((T::confd_trans_ctx(), KP::ikeypath()) ->
        'ok'
      | {'ok', confd_trans_ctx()}
      | {'error', error_reason()}
      | 'delayed_response').
%% This is the callback for #confd_data_cbs.write_all. The KP argument
%% is currently always [], since the callback does not pertain to any
%% particular data node.

-type cb_validate() ::
    fun((T::confd_trans_ctx(), KP::ikeypath(), Newval::value()) ->
        'ok'
      | {'ok', confd_trans_ctx()}
      | {'validation_warn', Reason::binary()}
      | {'error', error_reason()}).
%% It is the callback for #confd_valpoint_cb.validate.

-type cb_action() :: cb_action_act() | cb_action_cmd().
%% It is the callback for #confd_action_cb.action

-type cb_action_act() ::
    fun((U::#confd_user_info{}, Name::qtag(),
         KP::ikeypath(), [Param::tagval()]) ->
        'ok' | {'ok', [Result::tagval()]} | {'error', error_reason()}).
%% It is the callback for #confd_action_cb.action when invoked as an
%% action request.

-type cb_action_cmd() ::
    fun((U::#confd_user_info{}, Name::binary(),
         Path::binary(), [Arg::binary()]) ->
        'ok' | {'ok', [Result::binary()]} | {'error', error_reason()}).
%% It is the callback for #confd_action_cb.action when invoked as a
%% CLI command callback.

-type cb_completion_action() ::
    fun((U::#confd_user_info{}, CliStyle::integer(), Token::binary(),
         CompletionChar::integer(), IKP::ikeypath(), CmdPath::binary(),
         Id::binary(), TP::term(), Extra::term()) ->
        [string() | {'info', string()} | {'desc', string()} | 'default']).
%% It is the callback for #confd_action_cb.action when invoked as a
%% CLI command completion.

-type cb_ctx() ::
    fun((confd_trans_ctx()) ->
        'ok' | {'ok', confd_trans_ctx()} | {'error', error_reason()}).
%% The callback for #confd_trans_validate_cbs.init and
%% #confd_trans_cbs.init as well as
%% several other callbacks in #confd_trans_cbs{}

-type cb_trans_lock() ::
    fun((confd_trans_ctx()) ->
        'ok' | {'ok', confd_trans_ctx()}
      | {'error', error_reason()} | 'confd_already_locked').
%% The callback for #confd_trans_cbs.trans_lock. The confd_already_locked
%% return value is equivalent to {error, #confd_error{ code = in_use }}.

-type cb_write() ::
    fun((confd_trans_ctx()) ->
        'ok' | {'ok', confd_trans_ctx()}
      | {'error', error_reason()} | 'confd_in_use').
%% The callback for #confd_trans_cbs.write_start and
%% #confd_trans_cbs.prepare. The confd_in_use return value is equivalent to
%% {error, #confd_error{ code = in_use }}.

-type cb_ok() ::
    fun((confd_trans_ctx()) ->
        'ok' | {'error', error_reason()}).
%% The callback for #confd_trans_cbs.finish and
%% #confd_trans_validate_cbs.stop

-type cb_candidate_commit() ::
    fun((#confd_db_ctx{}, Timeout::integer()) ->
        'ok' | {'error', error_reason()}).
%% The callback for #confd_db_cbs.candidate_commit

-type cb_db() ::
    fun((#confd_db_ctx{}, DbName::integer()) ->
        'ok' | {'error', error_reason()}).
%% The callback for #confd_db_cbs.lock, #confd_db_cbs.unlock, and
%% #confd_db_cbs.delete_config

-type cb_lock_partial() ::
    fun((#confd_db_ctx{}, DbName::integer(), LockId::integer(), [ikeypath()]) ->
        'ok' | {'error', error_reason()}).
%% The callback for #confd_db_cbs.lock_partial

-type cb_unlock_partial() ::
    fun((#confd_db_ctx{}, DbName::integer(), LockId::integer()) ->
        'ok' | {'error', error_reason()}).
%% The callback for #confd_db_cbs.unlock_partial

-type cb_ok_db() ::
    fun((#confd_db_ctx{}) ->
        'ok' | {'error', error_reason()}).
%% The callback for #confd_db_cbs.candidate_confirming_commit
%% and several other callbacks in #confd_db_cbs{}

-type cb_authentication() ::
    fun((#confd_authentication_ctx{}) ->
        'ok' | 'error' | {'error', binary()}).
%% The callback for #confd_authentication_cb.auth

-type cb_get_log_times() ::
    fun((#confd_notification_ctx{}) ->
        {'ok', {Created::datetime(), Aged::datetime() | 'not_found'}}
      | {'error', error_reason()}).
%% The callback for #confd_notification_stream_cbs.get_log_times

-type cb_replay() ::
    fun((#confd_notification_ctx{}, Start::datetime(),
         Stop::datetime() | 'undefined') ->
        'ok' | {'error', error_reason()}).
%% The callback for #confd_notification_stream_cbs.replay

-type cb_str_to_val() ::
    fun((TypeCtx::term(), String::string()) ->
        {'ok', Value::value()} | 'error'
      | {'error', Reason::binary()} | none()).
%% The callback for #confd_type_cbs.str_to_val. The TypeCtx argument is
%% currently unused (passed as 'undefined'). The function may fail - this
%% is equivalent to returning 'error'.

-type cb_val_to_str() ::
    fun((TypeCtx::term(), Value::value()) ->
        {'ok', String::string()} | 'error'
      | {'error', Reason::binary()} | none()).
%% The callback for #confd_type_cbs.val_to_str. The TypeCtx argument is
%% currently unused (passed as 'undefined'). The function may fail - this
%% is equivalent to returning 'error'.

-type cb_validate_value() ::
    fun((TypeCtx::term(), Value::value()) ->
        'ok' | 'error' | {'error', Reason::binary()} | none()).
%% The callback for #confd_type_cbs.validate. The TypeCtx argument is
%% currently unused (passed as 'undefined'). The function may fail - this
%% is equivalent to returning 'error'.

-type list_filter_type() :: ?CONFD_LF_OR | ?CONFD_LF_AND | ?CONFD_LF_NOT
                          | ?CONFD_LF_CMP | ?CONFD_LF_EXISTS
                          | ?CONFD_LF_EXEC | ?CONFD_LF_ORIGIN.

-type cmp_op() :: ?CONFD_CMP_NOP | ?CONFD_CMP_EQ | ?CONFD_CMP_NEQ
                | ?CONFD_CMP_GT | ?CONFD_CMP_GTE | ?CONFD_CMP_LT
                | ?CONFD_CMP_LTE.

-type exec_op() :: ?CONFD_EXEC_STARTS_WITH | ?CONFD_EXEC_RE_MATCH
                 | ?CONFD_EXEC_DERIVED_FROM
                 | ?CONFD_EXEC_DERIVED_FROM_OR_SELF.

-type list_filter_op() :: cmp_op() | exec_op().

%%%--------------------------------------------------------------------
%%% External functions
%%%--------------------------------------------------------------------

%% @doc Starts the econfd application.
-spec start() ->
    'ok' | {'error', Reason::term()}.
start() ->
    application:start(econfd).

%% @doc Starts and links to a gen_server which connects to ConfD.
%% This gen_server holds two sockets to ConfD, one so called control
%% socket and one worker socket (See confd_lib_dp(3) for an explanation
%% of those sockets.)
%%
%% To avoid blocking control socket callback requests due to
%% long-running worker socket callbacks, the control socket callbacks
%% are run in the gen_server, while the worker socket callbacks are run
%% in a separate process that is spawned by the gen_server. This means
%% that applications must not share e.g. MAAPI sockets between
%% transactions, since this could result in simultaneous use of a socket
%% by the gen_server and the spawned process.
%%
%% The gen_server is used to install sets of callback Funs.  The
%% gen_server state is a #confd_daemon_ctx{}. This structure is passed
%% to all the callback functions.
%%
%% The daemon context includes a d_opaque element holding the Dopaque
%% term - this can be used by the application to pass application
%% specific data into the callback functions.
%%
%% The Name::atom() parameter is used in various debug printouts and
%% is also used to uniquely identify the daemon.
%%
%% The  DebugLevel parameter is used to control the
%% debug level. The following levels are available:
%%
%% <ul><li>?CONFD_SILENT
%%        No debug printouts whatsoever are produced by the library.
%%</li><li>
%%?CONFD_DEBUG
%%       Various printouts will occur for various error conditions.
%%</li><li>
%%?CONFD_TRACE
%%       The execution of callback functions will be traced.
%%</li></ul>
%%       The Estream parameter is used by all printouts from the
%%       library.
-spec init_daemon(Name::atom(), DebugLevel::integer(), Estream::io:device(),
                  Dopaque::term(), Ip::ip(), Port::integer()) ->
    {'ok', Pid::pid()} | {'error', Reason::term()}.
init_daemon(Name, DebugLevel, Estream, Dopaque, Ip, Port)
  when is_atom(Name), is_integer(DebugLevel) ->
    econfd_daemon:start_link(Name, DebugLevel, Estream, Dopaque,Ip,Port).

%% @doc Change the DebugLevel and/or Estream for a running daemon
-spec set_debug(Daemon::pid(), DebugLevel::integer(), Estream::io:device()) ->
    'ok'.
set_debug(Daemon, DebugLevel, Estream) ->
    gen_server:call(Daemon, {set_debug, DebugLevel, Estream}).

%% @doc Set the d_opaque field in the daemon which is typically
%% used by the callbacks
-spec set_daemon_d_opaque(Daemon::pid(), Dopaque::term()) ->
    'ok'.
set_daemon_d_opaque(Daemon, Dopaque) ->
    gen_server:cast(Daemon, {set_d_opaque, Dopaque}).

%% @doc Change the flag settings for a daemon. See ?CONFD_DAEMON_FLAG_XXX
%% in econfd.hrl for the available flags. This function should be called
%% immediately after creating the daemon context with init_daemon/6.
-spec set_daemon_flags(Daemon, Flags) -> 'ok' when
      Daemon :: pid(),
      Flags :: non_neg_integer().
set_daemon_flags(Daemon, Flags) ->
    gen_server:call(Daemon, {'set_flags', Flags}).

%% @doc Silently stop a daemon
-spec stop_daemon(Daemon::pid()) ->
    'ok'.
stop_daemon(Daemon) ->
    econfd_daemon:stop(Daemon).

%% @doc Register transaction phase callbacks.
%% See confd_lib_dp(3) for a thorough description of the transaction phases.
%% The record #confd_trans_cbs{} contains callbacks for all of the
%% phases for a transaction. If we use this external data api only for
%% statistics data only the init() and the finish() callbacks should be
%% used.  The init() callback must return 'ok', {error, String}, or {ok, Tctx}
%% where Tctx is the same #confd_trans_ctx that was supplied to the
%% init callback but possibly with the opaque field filled in. This field
%% is meant to be used by the user to manage user data.
-spec register_trans_cb(Daemon::pid(), TransCbs::#confd_trans_cbs{}) ->
    'ok' | {'error', Reason::term()}.
register_trans_cb(Daemon, TransCbs)
  when is_record(TransCbs, confd_trans_cbs) ->
    gen_server:call(Daemon, {register_trans_cb, TransCbs}).

%% @doc Register validation transaction callback.
%% This function maps an init and a finish function for validations.
%% See seme function in confd_lib_dp(3)
%% The init() callback must return 'ok', {error, String}, or {ok, Tctx}
%% where Tctx is the same #confd_trans_ctx that was supplied to the
%% init callback but possibly with the opaque field filled in.
-spec register_trans_validate_cb(Daemon::pid(),
                                 ValidateCbs::#confd_trans_validate_cbs{}) ->
    'ok' | {'error', Reason::term()}.
register_trans_validate_cb(Daemon, ValidateCbs)
  when is_record(ValidateCbs, confd_trans_validate_cbs) ->
    gen_server:call(Daemon, {register_trans_validate_cbs, ValidateCbs}).

%% @doc Register extern db callbacks.
-spec register_db_cbs(Daemon::pid(), DbCbs::#confd_db_cbs{}) ->
    'ok' | {'error', Reason::term()}.
register_db_cbs(Daemon, DbCbs) when is_record(DbCbs, 'confd_db_cbs') ->
     gen_server:call(Daemon, {register_db_cb, DbCbs}).

%% @doc Register the data callbacks.
-spec register_data_cb(Daemon :: pid(), DbCbs :: #confd_data_cbs{}) ->
    'ok' | {'error', Reason::term()}.
register_data_cb(Daemon, DataCbs) ->
    register_data_cb(Daemon, DataCbs, 0).

%% @doc Register the data callbacks.
-spec register_data_cb(Daemon :: pid(),
                       DbCbs :: #confd_data_cbs{},
                       Flags :: non_neg_integer()) ->
    'ok' | {'error', Reason::term()}.
register_data_cb(Daemon, DataCbs, Flags)
  when is_atom(DataCbs#confd_data_cbs.callpoint) ->
    gen_server:call(Daemon, {register_data_cbs, DataCbs, Flags}).

%% @doc Register data callbacks for a range of keys.
-spec register_range_data_cb(Daemon::pid(), DataCbs::#confd_data_cbs{},
                             [Lower::value()], [Higher::value()],
                             IKP::ikeypath()) ->
    'ok' | {'error', Reason::term()}.
register_range_data_cb(Daemon, DataCbs, Lower, Higher, IKP)->
    gen_server:call(Daemon, {confd_register_range_data_cb,
                             DataCbs, Lower, Higher, IKP}).

%% @doc Register validation callback on a valpoint
-spec register_valpoint_cb(Daemon::pid(), ValpointCbs::#confd_valpoint_cb{}) ->
    'ok' | {'error', Reason::term()}.
register_valpoint_cb(Daemon, ValpointCbs) ->
     gen_server:call(Daemon, {register_valpoint_cbs, ValpointCbs}).

%% @doc Register action callback on an actionpoint
-spec register_action_cb(Daemon::pid(), ActionCbs::#confd_action_cb{}) ->
    'ok' | {'error', Reason::term()}.
register_action_cb(Daemon, ActionCb) ->
     gen_server:call(Daemon, {register_action_cb, ActionCb}).

%% @doc Register authentication callback.
%% Note, this can not be used to *perform* the authentication.
-spec register_authentication_cb(
    Daemon::pid(),
    AuthenticationCb::#confd_authentication_cb{}) ->
        'ok' | {'error', Reason::term()}.
register_authentication_cb(Daemon, AuthenticationCb) ->
     gen_server:call(Daemon, {register_authentication_cb, AuthenticationCb}).

%% @doc Register notif callbacks on an streamname
-spec register_notification_stream(
    Daemon::pid(),
    NotifCbs::#confd_notification_stream_cbs{}) ->
        {'ok', #confd_notification_ctx{}} | {'error', Reason::term()}.
register_notification_stream(_Daemon, NotifCb)
  when ((NotifCb#confd_notification_stream_cbs.get_log_times == undefined)
        and
        (NotifCb#confd_notification_stream_cbs.replay /= undefined)) ->
    {error, badarg};  %% must have either both or none
register_notification_stream(_Daemon, NotifCb)
  when ((NotifCb#confd_notification_stream_cbs.get_log_times /= undefined)
        and
        (NotifCb#confd_notification_stream_cbs.replay == undefined)) ->
    {error, badarg};  %% must have eitehr both or none
register_notification_stream(Daemon, NotifCb) ->
    gen_server:call(Daemon, {register_notification_stream, NotifCb}).

%% @doc This function must be called when all callback registrations are done.
-spec register_done(Daemon::pid()) ->
    'ok' | {'error', Reason::term()}.
register_done(Daemon) ->
     gen_server:call(Daemon, register_done).

%% @doc Reply 'ok' for delayed_response.
%% This function can be used explicitly by the erlang application
%% if a data callback returns the atom delayed_response. In that
%% case it is the responsibility of the application to later
%% invoke one of the data_reply_xxx() functions. If delayed_response is
%% not used, none of the explicit data replying functions need to be used.
-spec data_reply_ok(Tctx::confd_trans_ctx()) ->
    'ok' | {'error', Reason::term()}.
data_reply_ok(Tctx) ->
    data_reply_value(Tctx, 0).

%% @doc Reply a value for delayed_response.
%% This function can be used explicitly by the erlang application
%% if a data callback returns the atom delayed_response. In that
%% case it is the responsibility of the application to later
%% invoke one of the data_reply_xxx() functions. If delayed_response is
%% not used, none of the explicit data replying functions need to be used.
-spec data_reply_value(Tctx::confd_trans_ctx(), V::value()) ->
    'ok' | {'error', Reason::term()}.
data_reply_value(Tctx, V) ->
    Dx = Tctx#confd_trans_ctx.dx,
    if Tctx#confd_trans_ctx.lastop == ?CONFD_PROTO_CALLBACK,
        Tctx#confd_trans_ctx.last_proto_op == ?CONFD_VALIDATE_VALUE ->
            trans_put(Dx, thvalidate, Tctx);
       true ->
            trans_put(Dx, th, Tctx)
    end,
    R = {?CONFD_PROTO_CALLBACK, Tctx#confd_trans_ctx.query_ref,
         Dx#confd_daemon_ctx.daemon_id, V},
    term_write(?wsock(Tctx),R).

%% @doc Reply with next key for delayed_response.
%% Like data_reply_value() - only used in combination with delayed_response.
-spec data_reply_next_key(Tctx::confd_trans_ctx(),
                          Key :: key() | 'false', Next::term()) ->
    'ok' | {'error', Reason::term()}.
data_reply_next_key(Tctx, Key, Next)  ->
    %% FIXME in_num_instances
    Dx = Tctx#confd_trans_ctx.dx,
    trans_put(Dx, th, data_set_filtered(Tctx, false)),
    ReplyVal =
        if Key == false ->
                false;
           Next == -1 ->
                {mk_filtered_next(Tctx, -1), Key};
           true ->
                NextInt = ets:update_counter(confd_next_map_from_int, incr, 1),
                Ekey = {Tctx#confd_trans_ctx.thandle, NextInt},
                ets:insert(confd_next_map_from_int, {Ekey, Next, [NextInt]}),
                {mk_filtered_next(Tctx, {Tctx#confd_trans_ctx.traversal_id,
                                         NextInt}), Key}
        end,
    R = {?CONFD_PROTO_CALLBACK, Tctx#confd_trans_ctx.query_ref,
         Dx#confd_daemon_ctx.daemon_id, ReplyVal},
    term_write(?wsock(Tctx),R).

%% @doc Reply 'not found' for delayed_response.
%% Like data_reply_value() - only used in combination with delayed_response.
-spec data_reply_not_found(Tctx::confd_trans_ctx()) ->
    'ok' | {'error', Reason::term()}.
data_reply_not_found(Tctx) ->
    data_reply_value(Tctx, not_found).

%% @doc Reply 'found' for delayed_response.
%% Like data_reply_value() - only used in combination with delayed_response.
-spec data_reply_found(Tctx::confd_trans_ctx()) ->
    'ok' | {'error', Reason::term()}.
data_reply_found(Tctx) ->
    data_reply_value(Tctx, 1).

%% @doc Reply a list of values for delayed_response.
%% Like data_reply_value() - only used in combination with delayed_response,
%% and get_object() callback.
-spec data_reply_value_array(Tctx :: confd_trans_ctx(),
                             Values :: vals() | tag_val_object() | 'false') ->
    'ok' | {'error', Reason::term()}.
data_reply_value_array(Tctx,Values) ->
    Dx = Tctx#confd_trans_ctx.dx,
    trans_put(Dx, th, Tctx),
    R = {?CONFD_PROTO_CALLBACK, Tctx#confd_trans_ctx.query_ref,
         Dx#confd_daemon_ctx.daemon_id,Values},
    term_write(?wsock(Tctx),R).

%% @doc Reply a list of tagged values for delayed_response.
%% Like data_reply_value() - only used in combination with delayed_response,
%% and get_object() callback.
-spec data_reply_tag_value_array(Tctx::confd_trans_ctx(),
                                 TagVals::[tagval()]) ->
    'ok' | {'error', Reason::term()}.
data_reply_tag_value_array(Tctx,Values) ->
    data_reply_value_array(Tctx,{exml,Values}).

%% @doc Reply with values and next key for delayed_response.
%% Like data_reply_value() - only used in combination with delayed_response,
%% and get_next_object() callback.
-spec data_reply_next_object_value_array(
    Tctx::confd_trans_ctx(),
    Values :: vals() | tag_val_object() | 'false',
    Next::term()) ->
        'ok' | {'error', Reason::term()}.
data_reply_next_object_value_array(Tctx, Values, Next)  ->
    %% FIXME in_num_instances
    Dx = Tctx#confd_trans_ctx.dx,
    trans_put(Dx, th, data_set_filtered(Tctx, false)),
    ReplyVal =
        if Values == false ->
                false;
           Next == -1 ->
                {mk_filtered_next(Tctx, -1), Values};
           true ->
                NextInt = ets:update_counter(confd_next_map_from_int, incr, 1),
                Ekey = {Tctx#confd_trans_ctx.thandle, NextInt},
                ets:insert(confd_next_map_from_int, {Ekey, Next, [NextInt]}),
                {mk_filtered_next(Tctx, {Tctx#confd_trans_ctx.traversal_id,
                                         NextInt}), Values}
        end,
    R = {?CONFD_PROTO_CALLBACK, Tctx#confd_trans_ctx.query_ref,
         Dx#confd_daemon_ctx.daemon_id, ReplyVal},
    term_write(?wsock(Tctx),R).

%% @doc Reply with tagged values and next key for delayed_response.
%% Like data_reply_value() - only used in combination with delayed_response,
%% and get_next_object() callback.
-spec data_reply_next_object_tag_value_array(Tctx::confd_trans_ctx(),
                                             [TV::tagval()],
                                             Next::term()) ->
    'ok' | {'error', Reason::term()}.
data_reply_next_object_tag_value_array(Tctx, Values, Next)  ->
    data_reply_next_object_value_array(Tctx, {exml, Values}, Next).

%% @doc Reply with multiple objects, each with values and next key, plus
%% cache timeout, for delayed_response.
%% Like data_reply_value() - only used in combination with delayed_response,
%% and get_next_object() callback.
-spec data_reply_next_object_value_arrays(Tctx::confd_trans_ctx(),
                                          Objects :: objects(),
                                          TimeoutMillisecs::integer()) ->
    'ok' | {'error', Reason::term()}.
data_reply_next_object_value_arrays(Tctx, Objects, TimeoutMillisecs)  ->
    %% FIXME in_num_instances
    Dx = Tctx#confd_trans_ctx.dx,
    trans_put(Dx, th, data_set_filtered(Tctx, false)),
    ReplyVal =
        if Objects == false ->
                false;
           true ->
                TH = Tctx#confd_trans_ctx.thandle,
                TraversalId = Tctx#confd_trans_ctx.traversal_id,
                NextFun = fun (Next, _Ints=[]) ->
                                  mk_filtered_next(Tctx, Next);
                              (Next, _Ints) ->
                                  Next
                          end,
                {_, ReplyObjects} =
                    process_next_objects(Objects, [], TH, TraversalId, NextFun),
                {ReplyObjects, TimeoutMillisecs}
        end,
    R = {?CONFD_PROTO_CALLBACK, Tctx#confd_trans_ctx.query_ref,
         Dx#confd_daemon_ctx.daemon_id, ReplyVal},
    term_write(?wsock(Tctx),R).

process_next_objects([{Values, -1}|Rest], Ints0, TH, TraversalId, NextFun) ->
    {Ints, ReplyObjects} =
        process_next_objects(Rest, Ints0, TH, TraversalId, NextFun),
    {Ints, [{NextFun({TraversalId, -1}, Ints0), Values}|ReplyObjects]};
process_next_objects([{Values, Next}|Rest], Ints0, TH, TraversalId, NextFun) ->
    NextInt = ets:update_counter(confd_next_map_from_int, incr, 1),
    {Ints, ReplyObjects} =
        process_next_objects(Rest, [NextInt|Ints0], TH, TraversalId, NextFun),
    Ekey = {TH, NextInt},
    ets:insert(confd_next_map_from_int, {Ekey, Next, Ints}),
    {Ints, [{NextFun({TraversalId, NextInt}, Ints0), Values}|ReplyObjects]};
%% only last object may be 'false'
process_next_objects([false], Ints, _TH, _TraversalId, _NextFun) ->
    {Ints, [false]};
process_next_objects([], Ints, _TH, _TraversalId, _NextFun) ->
    {Ints, []}.

mk_filtered_next(Tctx, Next) ->
    case data_is_filtered(Tctx) of
        true ->
            {filtered, Next};
        false ->
            Next
    end.

%% @doc Reply an error for delayed_response.
%% Like data_reply_value() - only used in combination with delayed_response.
-spec data_reply_error(Tctx::confd_trans_ctx(), Error::error_reason()) ->
    'ok' | {'error', Reason::term()}.
data_reply_error(Tctx, Error) ->
    Dx = Tctx#confd_trans_ctx.dx,
    Fd = if (Tctx#confd_trans_ctx.lastop == ?CONFD_PROTO_NEW_TRANS) or
            (Tctx#confd_trans_ctx.lastop == ?CONFD_PROTO_NEW_VALIDATE) ->
                 Dx#confd_daemon_ctx.ctl;
            true ->
                 Dx#confd_daemon_ctx.worker
         end,
    R = {Tctx#confd_trans_ctx.lastop,
         Tctx#confd_trans_ctx.query_ref,
         Dx#confd_daemon_ctx.daemon_id,
         error,
         econfd_daemon:mk_error(Error)},
    term_write(Fd, R).

%% @doc Extend (or shorten) the timeout for the current callback invocation.
%% The timeout is given in seconds from the point in time when the function
%% is called.
-spec data_set_timeout(Tctx::confd_trans_ctx(), Seconds::integer()) ->
    'ok' | {'error', Reason::term()}.
data_set_timeout(Tctx, Seconds) ->
    Dx=Tctx#confd_trans_ctx.dx,
    R = {?CONFD_PROTO_CALLBACK_TIMEOUT, Tctx#confd_trans_ctx.query_ref,
         Dx#confd_daemon_ctx.daemon_id, Seconds},
    term_write(?wsock(Tctx), R).

%% @doc Return list filter for the current operation if any.
-spec data_get_list_filter(Tctx::confd_trans_ctx()) ->
    'undefined' | #confd_list_filter{}.
data_get_list_filter(#confd_trans_ctx{list_filter = ListFilter}) ->
    ListFilter.

%% @doc Set filtered flag on transaction context in the first callback
%% call of a list traversal. This signals that all list entries
%% returned by the data provider for this list traversal match the
%% filter.
-spec data_set_filtered(Tctx :: confd_trans_ctx(), IsFiltered :: boolean()) ->
    confd_trans_ctx().
data_set_filtered(#confd_trans_ctx{cb_flags = CbFlags} = Tctx,
                  true = _IsFiltered) ->
    Tctx#confd_trans_ctx{cb_flags = CbFlags bor ?CONFD_TRANS_CB_FLAG_FILTERED};
data_set_filtered(#confd_trans_ctx{cb_flags = CbFlags0} = Tctx,
                  false = _IsFiltered) ->
    CbFlags = CbFlags0 band (bnot ?CONFD_TRANS_CB_FLAG_FILTERED),
    Tctx#confd_trans_ctx{cb_flags = CbFlags}.

%% @doc Return true if the filtered flag is set on the transaction.
-spec data_is_filtered(Tctx :: confd_trans_ctx()) ->
    boolean().
data_is_filtered(#confd_trans_ctx{cb_flags = CbFlags}) ->
    (CbFlags band ?CONFD_TRANS_CB_FLAG_FILTERED) =/= 0.

%% @doc Extend (or shorten) the timeout for the current action callback
%% invocation. The timeout is given in seconds from the point in time when
%% the function is called.
-spec action_set_timeout(Uinfo::#confd_user_info{}, Seconds::integer()) ->
    'ok' | {'error', Reason::term()}.
action_set_timeout(Uinfo, Seconds) ->
    Actx = Uinfo#confd_user_info.actx,
    Dx = Actx#confd_action_ctx.dx,
    R = {?CONFD_PROTO_CALLBACK_TIMEOUT, Actx#confd_action_ctx.query_ref,
         Dx#confd_daemon_ctx.daemon_id, Seconds},
    term_write(Dx#confd_daemon_ctx.worker, R).

%% @doc Send a notification defined at the top level of a YANG module.
-spec notification_send(Nctx::#confd_notification_ctx{},
                        DateTime::datetime(),
                        TagVals::[tagval()]) ->
    'ok' | {'error', Reason::term()}.
notification_send(Nctx, DateTime, ValueList) ->
    notification_send(Nctx, DateTime, ValueList, []).

%% @doc Send a notification defined as a child of a container or list
%% in a YANG 1.1 module. IKP is the fully instantiated path for the
%% parent of the notification in the data tree.
-spec notification_send(Nctx::#confd_notification_ctx{},
                        DateTime::datetime(), TagVals::[tagval()],
                        IKP::ikeypath()) ->
    'ok' | {'error', Reason::term()}.
notification_send(Nctx, DateTime, ValueList, IKP) ->
    Tup = {exml, ValueList},
    Term = {?CONFD_PROTO_NOTIF_SEND,
            Nctx#confd_notification_ctx.streamname,
            case Nctx#confd_notification_ctx.subid of
                0 -> undefined;
                _ -> Nctx#confd_notification_ctx.subid
            end,
            DateTime,
            Nctx#confd_notification_ctx.flags,
            Tup,
            lists:reverse(IKP)},
    Sock = Nctx#confd_notification_ctx.notif_worker,
    term_write(Sock, Term, ?CONFD_PROTO_REQUEST).

%% @doc Call this function when replay is done
-spec notification_replay_complete(Nctx::#confd_notification_ctx{}) ->
    'ok' | {'error', Reason::term()}.
notification_replay_complete(Nctx) ->
    T = {?CONFD_PROTO_NOTIF_REPLAY_COMPLETE,
         Nctx#confd_notification_ctx.streamname,
         Nctx#confd_notification_ctx.subid},
    Sock = Nctx#confd_notification_ctx.notif_worker,
    term_write(Sock, T, ?CONFD_PROTO_REQUEST).

%% @doc Call this function when replay has failed for some reason
-spec notification_replay_failed(Nctx::#confd_notification_ctx{},
                                 ErrorString::binary()) ->
    'ok' | {'error', Reason::term()}.
notification_replay_failed(Nctx, ErrorString) when is_binary(ErrorString) ->
    T = {?CONFD_PROTO_NOTIF_REPLAY_FAILED,
         Nctx#confd_notification_ctx.streamname,
         Nctx#confd_notification_ctx.subid,
         ErrorString
        },
    Sock = Nctx#confd_notification_ctx.notif_worker,
    term_write(Sock, T, ?CONFD_PROTO_REQUEST).

%% @doc Pretty print a value.
-spec pp_value(V::value()) ->
    iolist().

pp_value(T) when is_tuple(T) and ((size(T) == 4) or (size(T)==8)) ->
    inet_parse:ntoa(T);
pp_value(B) when is_binary(B) ->
    io_lib:format("~s", [?b2l(B)]);
pp_value({_Tag,Val}) ->
    io_lib:format("~p",[Val]);  %% FIXME all datetaypes .. etc
pp_value(V) ->
    io_lib:format("~p",[V]).

%% @doc Pretty print an ikeypath.
-spec pp_kpath(IKP::ikeypath()) ->
    iolist().
pp_kpath(IKP) ->
    [[_Ns|V] | Rest] = lists:reverse(IKP),
    lists:flatten(pp_kpath2([V|Rest])).

pp_kpath2([Last]) ->
    pp_path_value(Last);
pp_kpath2([V|Vs]) ->
    [pp_path_value(V) | pp_kpath2(Vs)].
pp_path_value([_Ns|Val])-> pp_path_value(Val);
pp_path_value(V) when is_tuple(V) ->
    StringForm = [pp_value(Key) || Key <- ?t2l(V)],
    Keys = string:join(StringForm, " "),
    "{" ++ Keys ++ "}";
pp_path_value(V) when is_atom(V) -> "/" ++ atom_to_list(V).

%% @doc Decrypts a value of type tailf:des3-cbc-encrypted-string
%% or tailf:aes-cfb-128-encrypted-string. Requires that
%% econfd_maapi:install_crypto_keys/1 has been called in the node.
-spec decrypt(binary()) ->
    {'ok', binary()}
  | {'error', {Ecode :: integer(), Reason :: binary()}}.
decrypt(<<"$7$", Base64EncryptedBinary/binary>>) ->
    case ets:lookup(confd_installed_crypto_keys, des3) of
        [{_, Key1, Key2, Key3, _DummyIVec}] ->
            <<IVec:8/binary, EncryptedBinary/binary>> =
                base64:decode(Base64EncryptedBinary),
            IoData = crypto:crypto_one_time(des_ede3_cbc, [Key1, Key2, Key3],
                                            IVec, EncryptedBinary,
                                            _Encrypt = false),
            {ok, unpad(iolist_to_binary(IoData))};
        _ ->
            {error, {?CONFD_ERR_NOEXISTS, <<"No des3-cbc keys available">>}}
    end;
decrypt(<<"$8$", Base64EncryptedBinary/binary>>) ->
    case ets:lookup(confd_installed_crypto_keys, aes128) of
        [{_, Key, _DummyIVec}] ->
            <<IVec:16/binary, EncryptedBinary/binary>> =
                base64:decode(Base64EncryptedBinary),
            IoData = crypto:crypto_one_time(aes_128_cfb128, Key, IVec,
                                            EncryptedBinary, _Encrypt = false),
            {ok, unpad(iolist_to_binary(IoData))};
        _ ->
            {error, {?CONFD_ERR_NOEXISTS, <<"No aes-cfb-128 keys available">>}}
    end;
decrypt(<<"$9$", Base64EncryptedBinary/binary>>) ->
    case ets:lookup(confd_installed_crypto_keys, aes256) of
        [{_, Key}] ->
            <<IVec:16/binary, EncryptedBinary/binary>> =
                base64:decode(Base64EncryptedBinary),
            IoData = crypto:crypto_one_time(aes_256_cfb128, Key, IVec,
                                            EncryptedBinary, _Encrypt = false),
            {ok, unpad(iolist_to_binary(IoData))};
        _ ->
            {error,
             {?CONFD_ERR_NOEXISTS, <<"No aes-256-cfb-128 keys available">>}}
    end;
decrypt(<<"$3$", Base64EncryptedBinary/binary>>) ->
    %% old-style with fixed ivec, "shouldn't happen"
    case ets:lookup(confd_installed_crypto_keys, des3) of
        [{_, Key1, Key2, Key3, IVec}] ->
            EncryptedBinary = base64:decode(Base64EncryptedBinary),
            IoData = crypto:crypto_one_time(des_ede3_cbc, [Key1, Key2, Key3],
                                            IVec, EncryptedBinary,
                                            _Encrypt = false),
            {ok, unpad(iolist_to_binary(IoData))};
        _ ->
            {error, {?CONFD_ERR_NOEXISTS, <<"No des3-cbc keys available">>}}
    end;
decrypt(<<"$4$", Base64EncryptedBinary/binary>>) ->
    %% old-style with fixed ivec, "shouldn't happen"
    case ets:lookup(confd_installed_crypto_keys, aes128) of
        [{_, Key, IVec}] ->
            EncryptedBinary = base64:decode(Base64EncryptedBinary),
            IoData = crypto:crypto_one_time(aes_128_cfb128, Key, IVec,
                                            EncryptedBinary, _Encrypt = false),
            {ok, unpad(iolist_to_binary(IoData))};
        _ ->
            {error, {?CONFD_ERR_NOEXISTS, <<"No aes-cfb-128 keys available">>}}
    end.

unpad(<<0, _/binary>>) ->
    <<>>;
unpad(<<>>) ->
    <<>>;
unpad(<<H, T/binary>>) ->
    UT = unpad(T),
    <<H, UT/binary>>.


%% @doc Set a bit in a C_BITBIG binary.
-spec bitbig_set_bit(binary(), integer()) ->
    binary().
bitbig_set_bit(Binary, Position) ->
    Bitmask = bitbig_bin2bm(Binary) bor (1 bsl Position),
    bitbig_pad(bitbig_bm2bin(Bitmask), size(Binary)).

%% @doc Clear a bit in a C_BITBIG binary.
-spec bitbig_clr_bit(binary(), integer()) ->
    binary().
bitbig_clr_bit(Binary, Position) ->
    Bitmask = bitbig_bin2bm(Binary) band (bnot (1 bsl Position)),
    bitbig_pad(bitbig_bm2bin(Bitmask), size(Binary)).

%% @doc Test a bit in a C_BITBIG binary.
-spec bitbig_bit_is_set(binary(), integer()) ->
    boolean().
bitbig_bit_is_set(Binary, Position) ->
    (bitbig_bin2bm(Binary) band (1 bsl Position)) =/= 0.

bitbig_pad(Binary, Size) when size(Binary) < Size ->
    %% pad to original size
    <<Binary/binary, 0:((Size - size(Binary)) * 8)>>;
bitbig_pad(Binary, _Size) ->
    Binary.

bitbig_bin2bm(Binary) ->
    binary:decode_unsigned(Binary, little).

bitbig_bm2bin(Bitmask) ->
    binary:encode_unsigned(Bitmask, little).

%% @doc Logs Fmt to devel.log if running internal, otherwise to
%% standard out. Level can be one of ?CONFD_LEVEL_ERROR |
%% ?CONFD_LEVEL_INFO | ?CONFD_LEVEL_TRACE
-spec log(Level::integer(), Fmt::string()) ->
    'ok'.
log(Level, Fmt) ->
    log(Level, Fmt, []).

%% @doc Logs Fmt with Args to devel.log if running internal,
%% otherwise to standard out. Level can be one of
%% ?CONFD_LEVEL_ERROR | ?CONFD_LEVEL_INFO | ?CONFD_LEVEL_TRACE
-spec log(Level::integer(), Fmt::string(), Args::list()) ->
    'ok'.
log(Level, Fmt, Args) ->
    econfd_internal:log(Level, Fmt, Args).

%% @doc Logs Fmt with Args to devel.log if running internal,
%% otherwise to IoDevice. Level can be one of
%% ?CONFD_LEVEL_ERROR | ?CONFD_LEVEL_INFO | ?CONFD_LEVEL_TRACE
-spec log(IoDevice::io:device(), Level::integer(),
    Fmt::string(), Args::list()) -> ok.
log(IoDevice, Level, Fmt, Args) ->
    econfd_internal:log(IoDevice, Level, Fmt, Args).

%% @doc Assigns a new controlling process Pid to Socket
-spec controlling_process(Socket::term(), Pid::pid()) ->
    'ok' | {'error', Reason::term()}.
controlling_process(Socket, Pid) ->
    econfd_internal:controlling_process(Socket, Pid).

%% @private Register NCS service callbacks.
-spec register_service_cb(Daemon::pid(), ServiceCbs::#ncs_service_cbs{})  ->
    'ok' | {'error', Reason::term()}.
register_service_cb(Daemon, ServiceCbs)
  when is_atom(ServiceCbs#ncs_service_cbs.servicepoint)  ->
    gen_server:call(Daemon, {register_service_cb, ServiceCbs}).

%% @private Register NCS service callbacks.
-spec register_nano_service_cb(Daemon::pid(), Component::binary(),
                               State::binary(),
                               ServiceCbs::#ncs_nano_service_cbs{})  ->
    'ok' | {'error', Reason::term()}.
register_nano_service_cb(Daemon, Component, State, NanoServiceCbs)
  when is_atom(NanoServiceCbs#ncs_nano_service_cbs.servicepoint)  ->
    gen_server:call(Daemon,
                    {register_nano_service_cb,
                     Component, State, NanoServiceCbs}).

%% @doc Convert user info tuple received from ConfD
%% @private
-spec mk_uinfo(tuple()) ->
    #confd_user_info{}.
mk_uinfo({USid, User, Pass, Ctx, Proto, Ip, Port,
          LoginTime, SnmpV3Ctx, Flags}) ->
    mk_uinfo({USid, User, Pass, Ctx, Proto, Ip, Port,
              LoginTime, SnmpV3Ctx, Flags}, #confd_user_info{}).

%% @private
mk_uinfo({USid, User, Pass, Ctx, Proto, Ip, Port,
          LoginTime, SnmpV3Ctx, Flags}, OldUinfo) ->
    OldUinfo#confd_user_info{usid = USid, username = User, clearpass = Pass,
                             context = Ctx, proto = Proto, ip = Ip, port = Port,
                             logintime = LoginTime, snmp_v3_ctx = SnmpV3Ctx,
                             flags = Flags}.


%% @private
trans_put(Dx, Type, #confd_trans_ctx{uinfo = Uinfo0} = Tctx) ->
    Uinfo = econfd_internal:wrap_clearpass(Uinfo0),
    %% don't keep a copy of the daemon_ctx in each trans_ctx
    ets:insert(Dx#confd_daemon_ctx.transactions,
               {{Type, Tctx#confd_trans_ctx.thandle},
                Tctx#confd_trans_ctx{dx = undefined, uinfo = Uinfo}}).

%% @private
trans_get(Dx, Type, TH) ->
    %% set daemon_ctx in fetched trans_ctx
    case ets:lookup(Dx#confd_daemon_ctx.transactions, {Type, TH}) of
        [{_, #confd_trans_ctx{uinfo = Uinfo0} = Tctx}] ->
            Uinfo = econfd_internal:unwrap_clearpass(Uinfo0),
            Tctx#confd_trans_ctx{dx = Dx, uinfo = Uinfo};
        _ ->
            undefined
    end.

%% @private
trans_erase(Dx, Type, TH) ->
    ets:delete(Dx#confd_daemon_ctx.transactions, {Type, TH}).


%% @private
report_err(_Dx, _Level, Fmt, Args) ->
    error_logger:format(Fmt, Args).

%% @hidden
doc_application(Args) ->
    Ret = edoc_run:application(Args),
    case Ret of
        ok -> halt(0);
        error -> halt(1)
    end.
