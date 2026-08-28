%% @doc RPC provider: hecate_turn_credentials.mint_credential. Mints one
%% short-lived TURN credential from a master secret that lives only in
%% this process's environment -- never in a client app. Follows coturn's
%% use-auth-secret / REST-API convention exactly: username is a unix
%% expiry timestamp, password is base64(HMAC-SHA1(secret, username)).
%% coturn derives the same pair independently from the same secret at
%% ALLOCATE time, so nothing round-trips to coturn here.
%%
%% No input is required or checked. Every mesh peer that can reach this
%% procedure gets a credential -- this exists to keep the master secret
%% out of a public APK, not to gate who may place a call (see
%% hecate-cam2me: contact/call authorization is deny/block, a separate
%% concern from this one).
-module(mint_turn_credential).

-behaviour(macula_response).

-export([init/1, handle_request/2]).

%% Covers one call session without needing mid-call credential rotation.
%% coturn's own relay-allocation lifetime (refreshed automatically by the
%% ICE agent) is independent of this -- this TTL only bounds how long the
%% USERNAME/PASSWORD pair itself is accepted for a fresh ALLOCATE.
-define(TTL_SECONDS, 3600).

%% One deployed TURN server for this PoC -- see turn.macula.io's own
%% provisioning script. Worth a config knob only once a second server
%% exists.
-define(TURN_URL, <<"turn:turn.macula.io:3478?transport=udp">>).

init(_Args) -> {ok, undefined}.

handle_request(_Payload, State) ->
    mint(os:getenv("TURN_SHARED_SECRET"), State).

mint(false, State) ->
    {error, turn_shared_secret_not_configured, State};
mint(Secret, State) when is_list(Secret) ->
    {reply, credential(list_to_binary(Secret)), State}.

credential(Secret) ->
    Expiry = erlang:system_time(second) + ?TTL_SECONDS,
    Username = integer_to_binary(Expiry),
    Password = base64:encode(crypto:mac(hmac, sha, Secret, Username)),
    #{
        username    => Username,
        credential  => Password,
        ttl_seconds => ?TTL_SECONDS,
        urls        => [?TURN_URL]
    }.
