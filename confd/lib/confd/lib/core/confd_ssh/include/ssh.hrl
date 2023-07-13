%% References a SSH server or client running over some carrier (incoming or
%% outgoing SSH connection or a raw TCP connection)
-record(ssh_conn, {
    %% helps tracing back where this was created
    %% for example use {?MODULE, ?FUNCTION_NAME}
    created_at :: term(),

    %% For debug and info purposes, destination of this connection
    target :: confdssh:ssh_target(),

    %% The type of connection which will carry SSH protocol inside it, can be
    %% new SSH or legacy, or even TCP
    carrier_type :: confdssh_conn:carrier_type(),

    %% Type of connection, server or client
    conn_type :: confdssh_conn:connection_type(),

    pid :: confdssh:conn_pid() % opaque pid or daemon ref or connection ref
}).

-define(IS_SSH_OPTS(Val), is_tuple(Val) andalso element(1, Val) =:= ssh_opts).
