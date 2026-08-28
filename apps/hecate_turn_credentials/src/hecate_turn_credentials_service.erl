%% @doc The hecate_om service contract: what this service is and may do.
%%
%% SIX CALLBACKS, ALL REQUIRED. hecate_om resolves them BY NAME at startup, on a
%% live node, so a service that forgets one dies with `undef' where nobody is
%% watching. The `-behaviour' attribute below is what turns that into a compile
%% error instead, and the generated test suite guards the attribute itself.
-module(hecate_turn_credentials_service).

-behaviour(hecate_om_service).

-export([info/0, start/1, stop/1, health/0, capabilities/0, identity_spec/0]).

info() ->
    #{name => <<"hecate-turn-credentials">>,
      version => <<"0.1.0">>,
      description => <<"Mints short-lived TURN credentials for hecate-cam2me over the mesh">>}.

start(_Opts) -> hecate_turn_credentials_sup:start_link().

stop(_State) -> ok.

%% The one thing this service needs to do its job at all: without
%% TURN_SHARED_SECRET every mint_turn_credential call fails, so a
%% missing secret is a real health failure, not a hypothetical one.
health() -> health(os:getenv("TURN_SHARED_SECRET")).

health(false) -> {down, turn_shared_secret_not_configured};
health(Secret) when is_list(Secret) -> ok.

%% Declaring `handler' makes hecate_om_capabilities register this with
%% the mesh pool AND publish the signed direct-dial DHT record in one
%% call at boot (via hecate_om:boot/1), including periodic re-advertise
%% -- see mint_turn_credential.erl for the actual RPC logic.
capabilities() ->
    [#{name => <<"hecate_turn_credentials.mint_credential">>,
      version => 1,
      handler => {mint_turn_credential, []}}].

%% THE AUTHORITY THIS SERVICE ASKS THE REALM FOR, and deliberately nothing more.
%% Ask for exactly the topics you publish and subscribe to. Popped, an attacker
%% gains precisely this and no more, which is the whole point of listing it.
%%
%% The scope is claimed now because it is the namespace every later resource
%% hangs under, and a scope costs nothing while a rename costs every deployed
%% peer.
identity_spec() ->
    #{scope => <<"hecate-turn-credentials">>,
      actions => [],
      resources => [],
      ttl_days => 30}.
