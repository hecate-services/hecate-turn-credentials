-module(mint_turn_credential_tests).

-include_lib("eunit/include/eunit.hrl").

no_secret_configured_fails_test() ->
    os:unsetenv("TURN_SHARED_SECRET"),
    Result = mint_turn_credential:handle_request(#{}, undefined),
    ?assertEqual({error, turn_shared_secret_not_configured, undefined}, Result).

%% Verifies the actual HMAC scheme, not just the reply's shape: coturn
%% derives password = base64(HMAC-SHA1(secret, username)) independently
%% at ALLOCATE time, so a credential this module mints has to satisfy
%% that same formula against the username it hands back, or coturn
%% rejects it.
mints_a_credential_matching_the_hmac_scheme_test() ->
    os:putenv("TURN_SHARED_SECRET", "test-secret"),
    {reply, Reply, undefined} = mint_turn_credential:handle_request(#{}, undefined),
    os:unsetenv("TURN_SHARED_SECRET"),
    #{username := Username, credential := Credential,
      ttl_seconds := Ttl, urls := Urls} = Reply,
    Expected = base64:encode(crypto:mac(hmac, sha, <<"test-secret">>, Username)),
    ?assertEqual(Expected, Credential),
    ?assertEqual(3600, Ttl),
    ?assertEqual([<<"turn:turn.macula.io:3478?transport=udp">>], Urls).

username_is_a_near_future_unix_timestamp_test() ->
    os:putenv("TURN_SHARED_SECRET", "test-secret"),
    {reply, #{username := Username}, undefined} =
        mint_turn_credential:handle_request(#{}, undefined),
    os:unsetenv("TURN_SHARED_SECRET"),
    Expiry = binary_to_integer(Username),
    Now = erlang:system_time(second),
    ?assert(Expiry > Now),
    ?assert(Expiry =< Now + 3600).
