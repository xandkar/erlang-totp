-module(totp_SUITE).

-include("totp_extra_params.hrl").

%% Callbacks
-export(
    [ all/0
    , groups/0
    ]).

%% Test cases
-export(
    [ t_rfc/1
    ]).

-define(GROUP, totp).

%% ============================================================================
%% Common Test callbacks
%% ============================================================================

all() ->
    [ {group, ?GROUP}
    ].

groups() ->
    Tests =
        [ t_rfc
        ],
    Properties = [parallel],
    [ {?GROUP, Properties, Tests}
    ].

%% =============================================================================
%%  Test cases
%% =============================================================================

t_rfc(_Cfg) ->
    totp:tests_rfc6238().
