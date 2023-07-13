%%%-------------------------------------------------------------------
%%% @copyright 2006 Tail-F Systems AB
%%% @version {$Id$}
%%% @doc An Erlang interface equivalent to the CDB C-API (documented
%%% in confd_lib_cdb(3)).
%%%
%%% The econfd_cdb library is used to connect to the  ConfD  built  in
%%% XML  database,  CDB. The purpose of this API to provide a read and
%%% subscription API to CDB.
%%%
%%% CDB owns and stores the configuration data and  the  user  of  the  API
%%% wants  to read that configuration data and also get notified when someone
%%% through either NETCONF, the CLI, the Web UI, or MAAPI  modifies
%%% the data so that the application can re-read the configuration data and
%%% act accordingly.
%%%
%%% == Paths ==
%%%
%%% In the C lib a path is a string. Assume the following
%%% YANG fragment:
%%%
%%% ```
%%%       container hosts {
%%%         list host {
%%%           key name;
%%%           leaf name {
%%%             type string;
%%%           }
%%%           leaf domain {
%%%             type string;
%%%           }
%%%           leaf defgw {
%%%             type inet:ip-address;
%%%           }
%%%           container interfaces {
%%%             list interface {
%%%               key name;
%%%               leaf name {
%%%                 type string;
%%%               }
%%%               leaf ip {
%%%                 type inet:ip-address;
%%%               }
%%%               leaf mask {
%%%                 type inet:ip-address;
%%%               }
%%%               leaf enabled {
%%%                 type boolean;
%%%               }
%%%             }
%%%           }
%%%         }
%%%       }
%%% '''
%%% Furthermore assume the database is populated with the following data
%%% ```
%%%           <hosts xmlns="http://acme.com/ns/hst/1.0">
%%%              <host>
%%%                <name>buzz</name>
%%%                <domain>tail-f.com</domain>
%%%                <defgw>192.168.1.1</defgw>
%%%                <interfaces>
%%%                  <interface>
%%%                    <name>eth0</name>
%%%                    <ip>192.168.1.61</ip>
%%%                    <mask>255.255.255.0</mask>
%%%                    <enabled>true</enabled>
%%%                  </interface>
%%%                  <interface>
%%%                    <name>eth1</name>
%%%                    <ip>10.77.1.44</ip>
%%%                    <mask>255.255.0.0</mask>
%%%                    <enabled>false</enabled>
%%%                  </interface>
%%%                </interfaces>
%%%              </host>
%%%            </hosts>
%%% '''
%%%
%%% The format path "/hosts/host{buzz}/defgw" refers to the leaf element
%%% called defgw of the host whose key (name element) is buzz.
%%%
%%% The format path "/hosts/host{buzz}/interfaces/interface{eth0}/ip"
%%% refers to the leaf element called "ip" in the "eth0" interface
%%% of the host called "buzz".
%%%
%%% In the Erlang CDB and MAAPI interfaces we use ikeypath() lists instead
%%% to address individual objects in the XML tree. The IkeyPath is backwards,
%%% thus the two above paths are expressed as
%%% ```
%%% [defgw, {<<"buzz">>}, host, [NS|hosts]]
%%% [ip, {<<"eth0">>}, interface, interfaces, {<<"buzz">>}, host, [NS|hosts]]
%%%
%%% '''
%%%
%%%  It is possible loop through all entries in a list as in:
%%% <pre>
%%% N = econfd_cdb:num_instances(CDB, [host,[NS|hosts]]),
%%% lists:map(fun(I) ->
%%%             econfd_cdb:get_elem(CDB, [defgw,[I],host,[NS|hosts]]), .......
%%%           end, lists:seq(0, N-1))
%%% </pre>
%%% Thus in the list with length N [Index] is an implicit key during the
%%% life of a CDB read session.
%%% @end
%%%-------------------------------------------------------------------

-module(econfd_cdb).

%%% external exports

-export([connect/0, connect/1, connect/2, connect/3,
         wait_start/1,
         get_phase/1,
         new_session/2,
         new_session/3,
         subscribe_session/1,
         end_session/1,
         close/1]).

-export([cd/2,
         get_elem/2,
         num_instances/2,
         next_index/2,
         index/2,
         exists/2,
         get_case/3,
         get_object/2,
         get_objects/4,
         get_values/3,
         subscribe/3,
         subscribe/4,
         subscribe/5,
         subscribe/6,
         subscribe_done/1,
         wait/3,
         diff_iterate/5,
         get_modifications_cli/2, get_modifications_cli/3,
         trigger_subscriptions/1, trigger_subscriptions/2,
         trigger_oper_subscriptions/1, trigger_oper_subscriptions/2,
         trigger_oper_subscriptions/3,
         get_txid/1
        ]).


%% cdb operational data API
-export([set_elem/3,
         set_elem2/3,
         create/2,
         delete/2,
         set_object/3,
         set_values/3,
         set_case/4]).

-export([mop_2_str/1]).

%%% Internal exports
-export([choice_path/1]).

-include("econfd_cdb_api.hrl").
-include("econfd_cdb.hrl").
-include("econfd_internal.hrl").
-include("../include/econfd.hrl").
-include("../include/econfd_errors.hrl").

%%% types

-type cdb_sess() :: #cdb_session{}.
%% A datastructure which is used as a handle to all the of the access
%% functions

-type subscription_sync_type() :: ?CDB_DONE_PRIORITY | ?CDB_DONE_SOCKET |
                                  ?CDB_DONE_TRANSACTION | ?CDB_DONE_OPERATIONAL.
%% Return value from the fun passed to wait/3,
%% indicating what to do with further notifications coming from
%% this transaction. These ints are defined in econfd.hrl

-type dbtype() :: ?CDB_RUNNING | ?CDB_STARTUP |
                  ?CDB_OPERATIONAL | ?CDB_PRE_COMMIT_RUNNING.
%% When we open CDB sessions we must choose which database to read
%% or write from/to. These ints are defined in econfd.hrl

-type err() :: {error, {integer(), binary()}} |
               {error, closed}.
%% Errors can be either
%% <ul><li> {error, Ecode::integer(), Reason::binary()} where Ecode is
%% one of the error codes defined in econfd_errors.hrl, and Reason is
%% (possibly empty) textual description </li>
%% <li> {error, closed} if the socket gets closed </li></ul>

-type sub_ns() :: econfd:namespace() | ''.
%% A namespace or use '' as wildcard (any namespace)

-type sub_type() :: ?CDB_SUB_RUNNING |
                    ?CDB_SUB_RUNNING_TWOPHASE |
                    ?CDB_SUB_OPERATIONAL.
%% Subscription type
%% <ul><li>
%% ?CDB_SUB_RUNNING - commit subscription.
%% </li><li>
%% ?CDB_SUB_RUNNING_TWOPHASE - two phase subscription, i.e. notification
%% will be received for prepare, commit, and possibly abort.
%% </li><li>
%% ?CDB_SUB_OPERATIONAL - subscription for changes to CDB operational data.
%% </li></ul>

%%%--------------------------------------------------------------------
%%% External functions
%%%--------------------------------------------------------------------

%%% Setup and tear down

%% @equiv connect({127,0,0,1})
-spec connect() -> econfd:connect_result().
connect() ->
    connect({127,0,0,1}).

%% @equiv connect(Address, 4565)
-spec connect(Address) -> econfd:connect_result() when
      Address :: econfd:ip().
connect(Address) ->
    connect(Address, ?CONFD_PORT).

%% @equiv connect(Address, Port, <<"econfd self()">>)
-spec connect(Address, Port) -> econfd:connect_result() when
      Address :: econfd:ip(),
      Port :: non_neg_integer().
connect(Address, Port) ->
    ClientName = list_to_binary(io_lib:format("econfd ~w", [self()])),
    connect(Address, Port, ClientName).

%% @doc Connect to CDB on the host with address Address:Port.
%%
%% If the port is changed it must also be changed in confd.conf
%%  A  call  to  cdb_connect()  is  typically  followed by a call to either
%%        new_session() for a reading session or a call to subscribe_session()
%%        for a subscription socket or calls to any of the write API functions
%% for a data socket.
%% ClientName is a string which confd will use as an identifier when
%% e.g. reporting status.
-spec connect(Address, Port, ClientName) -> econfd:connect_result() when
      Address :: econfd:ip(),
      Port :: non_neg_integer(),
      ClientName :: binary().
connect(Address, Port, ClientName) when is_binary(ClientName) ->
    case econfd_internal:connect(Address, Port, ?CLIENT_CDB, []) of
        {ok, Socket} ->
            %% Pass a name to ConfD for use when reporting status
            econfd_internal:bin_write(Socket,
                                      <<?OP_CLIENT_NAME:32,
                                        ClientName/binary>>),
            {ok, Socket};
        Error ->
            Error
    end.

%% @doc Wait for CDB to become available (reach start-phase one).
-spec wait_start(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
wait_start(Socket) ->
    request(#cdb_session{ socket = Socket }, ?OP_WAIT_START).

%% @doc Get CDB start-phase.
-spec get_phase(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: {ok, {Phase, Type}} | err(),
      Phase :: 0..2,
      Type :: 'false' | 'init' | 'normal' | 'upgrade'.
get_phase(Socket) ->
    request(#cdb_session{ socket = Socket }, ?OP_GET_PHASE).

%% @doc Get CDB transaction id.
%%
%% When we are a cdb client, and ConfD restarts, we can use this function
%% to retrieve the last CDB transaction id. If it the same as earlier
%% we don't need re-read the CDB data. This is also useful when we're
%% a CDB client in a HA setup.
-spec get_txid(Socket) -> Result when
      Socket :: econfd:socket(),
      Result :: {'ok', PrimaryNode, Now} | {'ok', Now},
      PrimaryNode :: term(),
      Now :: tuple().
get_txid(Socket) ->
    request(#cdb_session{ socket = Socket }, ?OP_GET_TXID).

%% @equiv trigger_subscriptions(Socket, all)
-spec trigger_subscriptions(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
trigger_subscriptions(Socket) ->
    trigger_subscriptions(Socket, all).

%% @doc Trigger CDB subscribers as if an update in the configuration
%%      had been done.
-spec trigger_subscriptions(Socket, SubPoints) -> 'ok' | err() when
      Socket :: econfd:socket(),
      SubPoints :: [pos_integer()] | 'all'.
trigger_subscriptions(Socket, all) ->
    trigger_subscriptions(Socket, []);
trigger_subscriptions(Socket, SubPoints) ->
    request(#cdb_session{ socket = Socket }, ?OP_TRIGGER_SUBS, SubPoints).

%% @equiv trigger_oper_subscriptions(Socket, all)
-spec trigger_oper_subscriptions(Socket) -> 'ok' | err() when
      Socket :: econfd:socket().
trigger_oper_subscriptions(Socket) ->
    trigger_oper_subscriptions(Socket, all).

%% @equiv trigger_oper_subscriptions(Socket, SubPoints, 0)
-spec trigger_oper_subscriptions(Socket, SubPoints) -> 'ok' | err() when
      Socket :: econfd:socket(),
      SubPoints :: [pos_integer()] | 'all'.
trigger_oper_subscriptions(Socket, Points) ->
    trigger_oper_subscriptions(Socket, Points, 0).

%% @doc Trigger CDB operational subscribers as if an update in oper data
%%      had been done.
%%
%% Flags can be given as ?CDB_LOCK_WAIT to have the
%%      call wait until the subscription lock becomes available, otherwise
%%      it should be 0.
-spec trigger_oper_subscriptions(Socket, SubPoints, Flags) -> 'ok' | err() when
      Socket :: econfd:socket(),
      SubPoints :: [pos_integer()] | 'all',
      Flags :: non_neg_integer().
trigger_oper_subscriptions(Socket, all, Flags) ->
    trigger_oper_subscriptions(Socket, [], Flags);
trigger_oper_subscriptions(Socket, SubPoints, Flags) ->
    request(#cdb_session{ socket = Socket }, ?OP_TRIGGER_OPER_SUBS,
            {SubPoints, Flags}).

%% @doc Initiate a new session using the socket returned by
%% connect().
-spec new_session(Socket, Db) -> Result when
      Socket :: econfd:socket(),
      Db :: dbtype(),
      Result :: {'ok', cdb_sess()} | err().
new_session(Socket, DbType) ->
    if (DbType == ?CDB_RUNNING) orelse
       (DbType == ?CDB_STARTUP) ->
            new_session(Socket, DbType, ?CDB_LOCK_SESSION);
       (DbType == ?CDB_OPERATIONAL) orelse
       (DbType == ?CDB_PRE_COMMIT_RUNNING) ->
            new_session(Socket, DbType, 0)
    end.

%% @doc Initiate a new session using the socket returned by connect(),
%% with detailed control via the Flags argument.
-spec new_session(Socket, Db, Flags) -> Result when
      Socket :: econfd:socket(),
      Db :: dbtype(),
      Flags :: non_neg_integer(),
      Result :: {'ok', cdb_sess()} | err().
new_session(Socket, DbType, Flags) ->
    CDB = #cdb_session{ socket = Socket },
    Opts = [useikp] ++
        if (Flags band ?CDB_LOCK_SESSION) =/= 0 -> [lock_session];
           true                                 -> []
        end ++
        if (Flags band ?CDB_LOCK_REQUEST) =/= 0 -> [lock_request];
           true                                 -> []
        end ++
        if (Flags band ?CDB_LOCK_PARTIAL) =/= 0 -> [lock_partial];
           true                                 -> []
        end ++
        if (Flags band ?CDB_LOCK_WAIT) =/= 0    -> [lock_wait];
           true                                 -> []
        end,
    case request(CDB, ?OP_NEW_SESSION, {DbType, Opts}) of
        ok ->
            {ok, CDB};
        Err ->
            Err
    end.

%% @doc Initialize a subscription socket.
%%
%% This is a socket that is used to receive notifications about
%%                  updates to the database. A subscription socket
%% is used in the subscribe() function.
-spec subscribe_session(Socket) -> {'ok', cdb_sess()} when
      Socket :: econfd:socket().
subscribe_session(Socket) ->
    {ok, #cdb_session{ socket = Socket }}.

%% @doc Terminate the session.
%%
%% This releases the lock on CDB which is active during a read session.
%% Returns a socket that can be re-used in new_session/2
%% We  use  connect()  to  establish a read socket to CDB. When the
%%   socket is closed, the read session is ended. We can reuse  the  same
%%   socket  for  another  read session, but we must then end the session
%%   and create another session using new_session/2.
%% %%
%%   While we have a live CDB read session, CDB is  locked  for  writing.
%%   Thus  all external entities trying to modify CDB are blocked as long
%%   as we have an open CDB read session. It is very  important  that  we
%%   remember  to  either  end_session()  or close() once we have
%%   read what we wish to read.
-spec end_session(CDB) -> {'ok', econfd:socket()} when
      CDB :: cdb_sess().
end_session(CDB) ->
    ok = request(CDB, ?OP_END_SESSION),
    {ok, CDB#cdb_session.socket}.

%% @doc End the session and close the socket.
-spec close(Socket | CDB) -> Result when
      Socket :: econfd:socket(),
      CDB :: cdb_sess(),
      Result :: 'ok' | {'error', econfd:error_reason()}.
close(#cdb_session{ socket = Socket }) when Socket /= undefined ->
    close(Socket);
close(Socket) when Socket /= undefined ->
    econfd_internal:close(Socket).

%% @doc Change the context node of the session.
%%
%% Note that this function can not be used as an existence test.
-spec cd(CDB, IKeypath) -> Result when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath(),
      Result :: 'ok' | err().
cd(CDB, IKP) ->
    request(CDB, ?OP_CD, lists:reverse(IKP)).

%% @doc Read an element.
%%
%% Note, the C interface has separate get
%%      functions for different types.
-spec get_elem(CDB, IKeypath) -> Result when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', econfd:value()} | err().
get_elem(CDB, IKP) ->
    request(CDB, ?OP_GET, lists:reverse(IKP)).

%% @doc Checks existense of an object.
%%
%% Leafs in the data model may be optional, and presence containers and
%% list entries may or may not exist. This function checks whether a node
%% exists in CDB, returning Int == 1 if it exists, Int == 0 if not.
-spec exists(CDB, IKeypath) -> Result when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', boolean()} | err().
exists(CDB, IKP) ->
    ibool(request(CDB, ?OP_EXISTS, lists:reverse(IKP))).

%% @doc Returns the number of entries in a list.
-spec num_instances(CDB, IKeypath) -> Result when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', integer()} | err().
num_instances(CDB, IKP) ->
    request(CDB, ?OP_NUM_INSTANCES, lists:reverse(IKP)).

%% @doc Returns the position (starting at 0) of the list entry after
%% the given path (which can be non-existing, and if multiple keys the
%% last keys can be '*').
-spec next_index(CDB, IKeypath) -> Result when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', integer()} | err().
next_index(CDB, IKP) ->
    request(CDB, ?OP_NXT_INDEX, lists:reverse(IKP)).

%% @doc Returns the position (starting at 0) of the list entry in path.
-spec index(CDB, IKeypath) -> Result when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', integer()} | err().
index(CDB, IKP) ->
    request(CDB, ?OP_KEY_INDEX, lists:reverse(IKP)).

%% @doc Returns the current case for a choice.
-spec get_case(CDB, IKeypath, Choice) -> Result when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath(),
      Choice :: econfd:qtag() | [econfd:qtag()],
      Result :: {'ok', econfd:qtag()} | err().
get_case(CDB, IKP, Choice) ->
    request(CDB, ?OP_GET_CASE, {choice_path(Choice), lists:reverse(IKP)}).

%% @doc Returns all the values in a container or list entry.
-spec get_object(CDB, IKeypath) -> Result when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath(),
      Result :: {'ok', [econfd:value()]} | err().
get_object(CDB, IKP) ->
    request(CDB, ?OP_GET_OBJECT, lists:reverse(IKP)).

%% @doc Returns all the values for NumEntries list entries.
%%
%% Starting at index StartIndex. The return value has one Erlang list for
%% each YANG list entry, i.e. it is a list of NumEntries lists.
-spec get_objects(CDB, IKeypath, StartIndex, NumEntries) -> Result when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath(),
      StartIndex :: integer(),
      NumEntries :: integer(),
      Result :: {'ok', [[econfd:value()]]} | err().
get_objects(CDB, IKP, StartIndex, NumEntries) ->
    request(CDB, ?OP_GET_OBJECTS, {lists:reverse(IKP), StartIndex, NumEntries}).

%% @doc Returns the values for the leafs that have the "value" 'not_found'
%% in the Values list.
%%
%% This can be used to read an arbitrary set of
%% sub-elements of a container or list entry. The return value is a list
%% of the same length as Values, i.e. the requested leafs are in the same
%% position in the returned list as in the Values argument. The elements
%% in the returned list are always "canonical" though, i.e. of the form
%% {@link econfd:tagval()}.
-spec get_values(CDB, IKeypath, Values) -> Result when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath(),
      Values :: [econfd:tagval()],
      Result :: {'ok', [econfd:tagval()]} | err().
get_values(CDB, IKP, Values) ->
    request(CDB, ?OP_GET_VALUES, {Values, lists:reverse(IKP)}).

%% @doc Only for CDB operational data:
%% Write Value into CDB.
-spec set_elem(CDB, Value, IKeypath) -> 'ok' | err() when
      CDB :: cdb_sess(),
      Value :: econfd:value(),
      IKeypath :: econfd:ikeypath().
set_elem(CDB, Value, IKP) ->
    request(CDB, ?OP_SET_ELEM, {Value, lists:reverse(IKP)}).

%% @doc Only for CDB operational data:
%% Write ValueBin into CDB. ValueBin is the textual value representation.
-spec set_elem2(CDB, ValueBin, IKeypath) -> 'ok' | err() when
      CDB :: cdb_sess(),
      ValueBin :: binary(),
      IKeypath :: econfd:ikeypath().
set_elem2(CDB, ValueBin, IKP) ->
    request(CDB, ?OP_SET_ELEM2, {ValueBin, lists:reverse(IKP)}).

%% @doc Only for CDB operational data:
%% Create the element denoted by IKP.
-spec create(CDB, IKeypath) -> 'ok' | err() when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath().
create(CDB, IKP) ->
    request(CDB, ?OP_CREATE, lists:reverse(IKP)).

%% @doc Only for CDB operational data:
%% Delete the element denoted by IKP.
-spec delete(CDB, IKeypath) -> 'ok' | err() when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath().
delete(CDB, IKP) ->
    request(CDB, ?OP_DELETE, lists:reverse(IKP)).

%% @doc Only for CDB operational data: Write an entire object,
%% i.e. YANG list entry or container.
-spec set_object(CDB, ValueList, IKeypath) -> 'ok' | err() when
      CDB :: cdb_sess(),
      ValueList :: [econfd:value()],
      IKeypath :: econfd:ikeypath().
set_object(CDB, ValueList, IKP) ->
    request(CDB, ?OP_SET_OBJECT, {ValueList, lists:reverse(IKP)}).

%% @doc Only for CDB operational data: Write a list of tagged values.
%%
%% This function is an alternative to
%% set_object/3, and allows for writing more complex structures
%% (e.g. multiple entries in a list).
-spec set_values(CDB, ValueList, IKeypath) -> 'ok' | err() when
      CDB :: cdb_sess(),
      ValueList :: [econfd:tagval()],
      IKeypath :: econfd:ikeypath().
set_values(CDB, ValueList, IKP) ->
    request(CDB, ?OP_SET_VALUES, {ValueList, lists:reverse(IKP)}).

%% @doc Only for CDB operational data: Set the case for a choice.
-spec set_case(CDB, IKeypath, Choice, Case) -> 'ok' | err() when
      CDB :: cdb_sess(),
      IKeypath :: econfd:ikeypath(),
      Choice :: econfd:qtag() | [econfd:qtag()],
      Case :: econfd:qtag().
set_case(CDB, IKP, Choice, Case) ->
    request(CDB, ?OP_SET_CASE,
            {{choice_path(Choice), Case}, lists:reverse(IKP)}).



%%% Subscription Interface

%% @doc Set up a CDB configuration subscription.
%%
%% A CDB subscription means that we are notified when CDB changes.
%% We can have multiple subscription points. Each subscription point
%% is defined through a path corresponding to the paths we use for read
%% operations, however they are in string form and allow formats that
%% aren't possible in a proper ikeypath(). It is possible to indicate
%% namespaces in the path with a prefix notation (see last example) -
%% this is only necessary if there are multiple elements with the same
%% name (in different namespaces) at some level in the path, though.
%%
%% We can subscribe either to specific leaf elements or entire
%% subtrees. Subscribing to list entries can be done using fully
%% qualified paths, or tagpaths to match multiple entries. A
%% path which isn't a leaf element automatically matches the subtree
%% below that path. When specifying keys to a list entry it is
%% possible to use the wildcard character * which will match any key
%% value.
%%
%% Some examples:
%%
%% <ul>
%% <li>
%%   /hosts
%%  <p>
%%   Means that we subscribe to any changes in the subtree - rooted at
%%   "/hosts". This includes additions or removals of "host" entries as well
%%   as changes to already existing "host" entries.
%%  </p>
%% </li>
%% <li>
%%   /hosts/host{www}/interfaces/interface{eth0}/ip
%%  <p>
%%   Means we are notified when host "www" changes its IP address on
%%   "eth0".
%%  </p>
%% </li>
%% <li>
%%   /hosts/host/interfaces/interface/ip
%%  <p>
%%   Means we are notified when any host changes any of its IP addresses.
%%  </p>
%% </li>
%% <li>
%%   /hosts/host/interfaces
%%  <p>
%%   Means we are notified when either an interface
%%   is added/removed or when an individual leaf element in an
%%   existing interface is changed.
%%  </p>
%% </li>
%% <li>
%%   /hosts/host/types:data
%%  <p>
%%   Means we are notified when any host changes the contents of its
%%   "data" element, where "data" is an element from a namespace with
%%   the prefix "types". The prefix is normally not necessary, see above.
%%  </p>
%% </li>
%% </ul>
%%
%% The priority value is an integer. When CDB  is  changed,  the
%% change  is  performed  inside  a transaction. Either a commit
%% operation from the CLI or  a  candidate-commit  operation  in
%% NETCONF  means  that  the  running database is changed. These
%% changes occur inside a ConfD transaction. CDB will handle the
%% subscriptions  in  lock-step  priority  order. First all
%% subscribers at the lowest priority are handled,  once  they  all
%% have synchronized via the return value from the fun passed to
%% wait/3, the next set - at the next priority  level -
%% is handled by CDB.
%%
%% Operational and configuration subscriptions can be done on the same
%% socket, but in that case the notifications may be arbitrarily
%% interleaved, including operational notifications arriving between
%% different configuration notifications for the same transaction. If
%% this is a problem, use separate sessions for operational and
%% configuration subscriptions.
%%
%% The namespace argument specifies the toplevel namespace, i.e.
%% the namespace for the first element in the path. The namespace is
%% optional, 0 can be used as "don't care" value.
%%
%% subscribe()  returns  a  subscription point which is an integer.
%% This integer value is used later in wait/3 to identify this
%% particular subscription.
%%
-spec subscribe(CDB, Priority, Ns, MatchKeyString) -> Result when
      CDB :: cdb_sess(),
      Priority ::integer(),
      Ns :: sub_ns(),
      MatchKeyString :: string(),
      Result :: {'ok', SubPoint} | err(),
      SubPoint :: pos_integer().
subscribe(CDB, Prio, Ns, MatchKeyString) ->
    MIKP = parse_keystring(MatchKeyString),
    request(CDB, ?OP_SUBSCRIBE, {Prio, Ns, {MIKP, true}}).

%% @equiv subscribe(CDB, Prio, '', MatchKeyString)
-spec subscribe(CDB, Priority, MatchKeyString) -> Result when
      CDB :: cdb_sess(),
      Priority ::integer(),
      MatchKeyString :: string(),
      Result :: {'ok', SubPoint} | err(),
      SubPoint :: pos_integer().
subscribe(CDB, Prio, MatchKeyString) ->
    subscribe(CDB, Prio, '', MatchKeyString).

%% @equiv subscribe(CDB, Type, 0, Prio, Ns, MatchKeyString)
-spec subscribe(CDB, Type, Priority, Ns, MatchKeyString) -> Result when
      CDB :: cdb_sess(),
      Type :: sub_type(),
      Priority ::integer(),
      Ns :: sub_ns(),
      MatchKeyString :: string(),
      Result :: {'ok', SubPoint} | err(),
      SubPoint :: pos_integer().
subscribe(CDB, Type, Prio, Ns, MatchKeyString) ->
    subscribe(CDB, Type, 0, Prio, Ns, MatchKeyString).

%% @doc Generalized subscription.
%%
%% Where Type is one of
%% <ul><li>
%% ?CDB_SUB_RUNNING - traditional commit subscription, same as subscribe/4.
%% </li><li>
%% ?CDB_SUB_RUNNING_TWOPHASE - two phase subscription, i.e. notification
%% will be received for prepare, commit, and possibly abort.
%% </li><li>
%% ?CDB_SUB_OPERATIONAL - subscription for changes to CDB operational data.
%% </li></ul>
%% Flags is either 0 or:
%% <ul><li>
%% ?CDB_SUB_WANT_ABORT_ON_ABORT - normally if a subscriber is the one
%%   to abort a transaction it will not receive an abort
%%   notification. This flags means that this subscriber wants an
%%   abort notification even if it originated the abort.
%% </li></ul>
-spec subscribe(CDB, Type, Flags, Priority, Ns, MatchKeyString) -> Result when
      CDB :: cdb_sess(),
      Type :: sub_type(),
      Flags :: non_neg_integer(),
      Priority ::integer(),
      Ns :: sub_ns(),
      MatchKeyString :: string(),
      Result :: {'ok', SubPoint} | err(),
      SubPoint :: pos_integer().
subscribe(CDB, Type, Flags, Prio, Ns, MatchKeyString) ->
    MIKP = parse_keystring(MatchKeyString),
    request(CDB, ?OP_SUBSCRIBE, {Type, Flags, 0, Prio, Ns, {MIKP, true}}).

%% @doc After a subscriber is done with all subscriptions and ready to
%%      receive updates this subscribe_done/1 must be called. Until it
%%      is no notifications will be delivered.
-spec subscribe_done(CDB) -> 'ok' | err() when
      CDB :: cdb_sess().
subscribe_done(CDB) ->
    request(CDB, ?OP_SUBSCRIBE_DONE).

%% @doc Wait for subscription events.
%%
%% The fun will be given a list of the subscription points that
%% triggered, and in the arity-3 case also Type and Flags for the
%% notification. There can be several points if we have issued several
%% subscriptions at the same priority.
%%
%% Type is one of:
%% <ul><li>
%%    ?CDB_SUB_PREPARE - notification for the prepare phase
%% </li><li>
%%    ?CDB_SUB_COMMIT  - notification for the commit phase
%% </li><li>
%%    ?CDB_SUB_ABORT   - notification for abort when prepare failed
%% </li><li>
%%    ?CDB_SUB_OPER    - notification for changes to CDB operational data
%% </li></ul>
%%
%% Flags is the 'bor' of zero or more of:
%% <ul><li>
%%    ?CDB_SUB_FLAG_IS_LAST - the last notification of its type for this session
%% </li><li>
%%    ?CDB_SUB_FLAG_TRIGGER - the notification was artificially triggered
%% </li><li>
%%    ?CDB_SUB_FLAG_REVERT - the notification is due to revert of a confirmed
%%                           commit
%% </li><li>
%%    ?CDB_SUB_FLAG_HA_SYNC -  the cause of the subscription
%%                             notification is initial synchronization
%%                             of a HA secondary from CDB on the primary.
%% </li><li>
%%    ?CDB_SUB_FLAG_HA_IS_SECONDARY - the system is currently in HA
%%    SECONDARY mode.
%% </li></ul>
%%
%% The fun can return the atom 'close' if we wish to close the socket and
%% return from wait/3. Otherwise there are three different types of
%% synchronization replies the application can use as return values from
%% either the arity-1 or the arity-3 fun:
%% <ul><li>
%%    ?CDB_DONE_PRIORITY
%%    This means that the application has acted on the subscription
%%    notification and CDB can continue to deliver further  notifications.
%% </li><li>
%%    ?CDB_DONE_SOCKET
%%    This  means that we are done. But regardless of priority, CDB
%%    shall not send any further notifications to us on our  socket
%%    that are related to the currently executing transaction.
%% </li><li>
%%    ?CDB_DONE_TRANSACTION
%%    This means that CDB should not send any further notifications
%%    to any subscribers - including ourselves  -  related  to  the
%%    currently executing transaction.
%% </li><li>
%%    ?CDB_DONE_OPERATIONAL
%%    This should be used when a subscription notification for
%%    operational data has been read. It is the only type that should
%%    be used in this case, since the operational data does not have
%%    transactions and the notifications do not have priorities.
%% </li></ul>
%% Finally the arity-3 fun can, when Type == ?CDB_SUB_PREPARE,
%% return an error either as <tt>{error, binary()}</tt> or as
%% <tt>{error, #confd_error{}}</tt>
%% ({error, tuple()} is only for internal ConfD/NCS use). This will
%% cause the commit of the current transaction to be aborted.
%%
%% CDB is locked for writing while config subscriptions are delivered.
%%
%% When wait/3 returns <tt>{error, timeout}</tt> the connection (and its
%% subscriptions) is still active and the application needs to call
%% wait/3 again. But if wait/3 returns <tt>ok</tt> or
%% <tt>{error, Reason}</tt> the connection to ConfD is closed and all
%% subscription points associated with it are cleared.
-spec wait(CDB, TimeOut, Fun) -> Result when
      CDB :: cdb_sess(),
      TimeOut :: integer() | 'infinity',
      Fun :: fun((SubPoints) ->
                        'close' | subscription_sync_type()) |
             fun((Type, Flags, SubPoints) ->
                        'close' | subscription_sync_type() |
                        {'error', econfd:error_reason()}),
      SubPoints :: [pos_integer()],
      Type :: integer(),
      Flags :: non_neg_integer(),
      Result :: 'ok' |
                {'error', 'badretval'} |
                {'error', econfd:transport_error()} |
                {'error', econfd:error_reason()}.
wait(CDB, TimeOut, Fun) ->
    case econfd_internal:term_read(CDB#cdb_session.socket,
                                   ?OP_SUB_EVENT, TimeOut) of
        {ok, {Type, Flags, PointList}} ->
            Ret = if is_function(Fun, 3) ->
                          (catch Fun(Type, Flags, PointList));
                     true ->
                          (catch Fun(PointList))
                  end,
            case Ret of
                _ when Ret == ?CDB_DONE_PRIORITY ;
                       Ret == ?CDB_DONE_SOCKET ;
                       Ret == ?CDB_DONE_TRANSACTION;
                       Ret == ?CDB_DONE_OPERATIONAL ->
                    sync_subscription_socket(CDB, Ret, TimeOut, Fun);
                {error, Reason} when Type == ?CDB_SUB_PREPARE ->
                    Abort = {?SYNC_ABORT, econfd_daemon:mk_error(Reason)},
                    sync_subscription_socket(CDB, Abort, TimeOut, Fun);
                close ->
                    {ok, Socket} = end_session(CDB),
                    close(Socket),
                    ok;
                _ ->
                    error_logger:format("bad retval from subscription "
                                        "fun: ~p~n", [Ret]),
                    close(CDB),
                    {error, badretval}
            end;
        {error, timeout} ->
            {error, timeout};
        Err ->
            close(CDB),
            Err
    end.

sync_subscription_socket(CDB, SyncType, TimeOut, Fun) ->
    case request(CDB, ?OP_SYNC_SUB, SyncType) of
        ok ->
            wait(CDB, TimeOut, Fun);
        Err ->
            error_logger:format("CDB sub_sync req: ~p~n", [Err]),
            close(CDB),
            Err
    end.

%% @doc Iterate over changes in CDB after a subscription triggers.
%%
%% This function can be called from within the fun passed to wait/3. When
%% called it will invoke Fun for each change that matched the Point. If
%% Flags is ?CDB_ITER_WANT_PREV, OldValue will be the previous value (if
%% available). When OldValue or Value is not available (or requested) they will
%% be the atom 'undefined'.
%% When Op == ?MOP_MOVED_AFTER (only for "ordered-by user" list entry),
%% Value == {} means that the entry was moved first in the list, otherwise
%% Value is a econfd:key() tuple that identifies the entry it was moved after.
-spec diff_iterate(CDB, SubPoint, Fun, Flags, State) -> Result when
      CDB :: cdb_sess(),
      SubPoint :: pos_integer(),
      Fun :: fun((IKeypath, Op, OldValue, Value, State) ->
                        {'ok', Ret, State} | {'error', term()}),
      IKeypath :: econfd:ikeypath(),
      Op :: integer(),
      OldValue :: econfd:value() | 'undefined',
      Value :: econfd:value() | 'undefined' | econfd:key() | {},
      State :: term(),
      Ret :: integer(),
      Flags :: non_neg_integer(),
      Result :: {'ok', State} | {'error', term()}.
diff_iterate(CDB, Point, Fun, Flags, InitState) ->
    Socket = CDB#cdb_session.socket,
    econfd_internal:bin_write(Socket,
                              <<?OP_SUB_ITERATE:32, Point:32, Flags:32>>),
    econfd_maapi:iterate_loop(Socket, Fun, InitState).

%% @equiv get_modifications_cli(CDB, Point, 0)
-spec get_modifications_cli(CDB, SubPoint) -> Result when
      CDB :: cdb_sess(),
      SubPoint :: pos_integer(),
      Result :: {'ok', CliString} | {'error', econfd:error_reason()},
      CliString :: binary().
get_modifications_cli(CDB, Point) ->
    get_modifications_cli(CDB, Point, 0).

%% @doc Return Return a string with the CLI commands that corresponds
%% to the changes that triggered subscription.
-spec get_modifications_cli(CDB, SubPoint, Flags) -> Result when
      CDB :: cdb_sess(),
      SubPoint :: pos_integer(),
      Flags :: non_neg_integer(),
      Result :: {'ok', CliString} | {'error', econfd:error_reason()},
      CliString :: binary().
get_modifications_cli(CDB, Point, Flags) ->
    request(CDB, ?OP_GET_CLI, {Point, Flags}).

%%%--------------------------------------------------------------------
%%% Internal functions
%%%--------------------------------------------------------------------

request(CDB, Op) ->
    econfd_internal:confd_call_bin(CDB#cdb_session.socket, <<>>, Op).

request(CDB, Op, Arg) ->
    econfd_internal:confd_call(CDB#cdb_session.socket, Arg, Op).


%% @private Internal function.
%% @doc It parses a keystring and returns a list that is somewhat
%% similar to an ikeypath() - it is only used for CDB subscriptions.
-spec parse_keystring(string()) -> [term()].
parse_keystring(Str) ->
    {ok, Res} = parse_keystring0(Str),
    Res.

parse_keystring0(Str) ->
    %% First split at "/"
    SlashSeparated = string:tokens(Str, "/"),

    %% Then go through each element and look for "{}", and "[]"
    IKP = lists:foldl(
                fun (E, Acc) ->
                        xx(skip_ws(E), Acc)
                end, [], SlashSeparated),
    {ok, lists:reverse(IKP)}.


xx(Str, Acc) -> xx(Str, [], Acc).

xx([H|T], Sofar, Acc) when (H == ${) or (H == $[) ->
    %% Sofar is path element
    E = mk_elem(Sofar),
    {'', Y} = yy([H|T]),
    [Y, E | Acc];
xx([H|T], Sofar, Acc) ->
    xx(T, [H|Sofar], Acc);
xx([], Sofar, Acc) ->
    [mk_elem(Sofar)|Acc].


%% yy(Str)
%%   "foo{bar}" -> {foo, {<<"bar">>}}
%%   "{bar}     -> {'',  {<<"bar">>}}
%%   "foo
%%   "foo"      -> foo
yy(Str) -> yy(Str, []).

yy([], Sofar) ->
    mk_elem(Sofar);
yy([$[|T], Sofar) ->
    E = mk_elem(Sofar),
    Z = collect_until(T, $]),
    {E, [list_to_integer(Z)]};
yy([${|T], Sofar) ->
    E = mk_elem(Sofar),
    Z = collect_until(T, $}),
    {E, {list_to_binary(Z)}};
yy([H|T], Sofar) ->
    yy(T, [H|Sofar]).

%% @private
%% @doc Skips initial white space, returns input string up to, but
%%      excluding Stop.
-spec collect_until(String, Stop) -> String when
      String :: string(),
      Stop :: char().
collect_until(Str, Stop) ->
    collect_until(skip_ws(Str), Stop, []).

collect_until([Stop|_], Stop, Sofar) ->
    lists:reverse(skip_ws(Sofar));
collect_until([C|T], Stop, Sofar) ->
    collect_until(T, Stop, [C|Sofar]);
collect_until([], _Stop, Sofar) ->
    %% We are lax
    lists:reverse(skip_ws(Sofar)).

%% @private
%% @doc  Return string without leading white space.
-spec skip_ws(String) -> String when
      String :: string().
skip_ws([Ws|T]) when Ws =< 32 ->
    skip_ws(T);
skip_ws(Str) ->
    Str.

mk_elem([]) ->
    '';
mk_elem(List) ->
    case string:tokens(lists:reverse(skip_ws(List)), ":") of
        [Ns, Tag] ->
            [list_to_atom(Ns)|list_to_atom(Tag)];
        [Tag] ->
            list_to_atom(Tag)
    end.

%% @private
choice_path(Tag) when is_atom(Tag) ->
    [Tag];
choice_path([Ns|Tag]) when is_atom(Ns), is_atom(Tag) ->
    [[Ns|Tag]];
choice_path(Path) ->
    lists:reverse(Path).

ibool({ok, 1}) -> {ok, true};
ibool({ok, 0}) -> {ok, false};
ibool(X) -> X.

%% @private
mop_2_str(?MOP_CREATED) -> "MOP_CREATED";
mop_2_str(?MOP_DELETED) -> "MOP_DELETED";
mop_2_str(?MOP_MODIFIED) -> "MOP_MODIFIED";
mop_2_str(?MOP_VALUE_SET) -> "MOP_VALUE_SET";
mop_2_str(?MOP_MOVED_AFTER) -> "MOP_MOVED_AFTER".
