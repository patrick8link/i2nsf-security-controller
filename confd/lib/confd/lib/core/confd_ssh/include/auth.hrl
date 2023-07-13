-record(ssh_auth, {
    luser :: 'undefined' | binary(), % | ncm_server:match_var(),
    ruser :: 'undefined' | binary(), % | ncm_server:match_var(),
    auth_order = [] :: [confdssh_auth:auth_method()],
        % | ncm_server:match_var(),
    passwd :: 'undefined' | binary() | fun (() -> binary()
        | {error, no_clear_text}), % | ncm_server:match_var(),
    key_dir :: 'undefined' | string(), % | ncm_server:match_var(),
    priv_key :: 'undefined' | confdssh_auth:priv_key_fun(),
        % | ncm_server:match_var(),
    host_key_verif = 'none' :: confdssh_key:ssh_host_key_verif(),
        % | ncm_server:match_var(),
    host_keys = [] :: [confdssh_key:ssh_host_key()] % | ncm_server:match_var()
}).

-record(tcp_auth, {
    luser :: 'undefined' | binary(),
    ruser :: binary(),
    group :: 'undefined' | binary()
}).
