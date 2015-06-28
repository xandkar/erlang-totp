-record(totp_extra_params,
    { hash_algo = sha :: hotp_hmac:hash_algo()
    , length    = 8   :: integer()  % Number of digits desired
    , time_zero = 0   :: non_neg_integer()
    , time_now        :: non_neg_integer()
    , time_step = 30  :: pos_integer()
    }).
