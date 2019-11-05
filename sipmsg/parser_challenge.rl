// -*-go-*-
//
// HTTP Challenge parser
package sipmsg

%% machine challenge;
%% write data;

func parseChallenge (data []byte) (*Challenge, error) {
    cs := 0
    l := ptr(len(data))
    var p, m, pe, eof ptr = 0, 0, l, l
    ch := &Challenge{}

%%{
    action sm        { m = p }
    action realm     { ch.realm = data[m + 1: p - 1]}
    action domain    { ch.domain = data[m:p]}
    action nonce     { ch.nonce = data[m + 1:p - 1]}
    action opaque    { ch.opaque = data[m + 1:p - 1]}

    include grammar "grammar.rl";

    qopval  = ("auth"i %{ ch.qop |= QOPAuth } | "auth-int"i %{ ch.qop |= QOPAuthInt });
    uri     = ABS_URI | abs_path;

    realm   = "realm"i EQUAL quoted_string >sm %realm;
    domain  = "domain"i EQUAL LDQUOT uri >sm (SP+ uri)* %domain RDQUOT;
    nonce   = "nonce"i EQUAL quoted_string >sm %nonce;
    opaque  = "opaque"i EQUAL quoted_string >sm %opaque;
    stale   = "stale"i EQUAL ( "true"i %{ch.stale = true} | "false"i %{ch.stale = false} );
    algo    = "algorithm"i EQUAL
              ( "MD5"i %{ ch.algo = AlgoMD5 } | "MD5-sess"i %{ ch.algo = AlgoMD5sess });
    qop     = "qop"i EQUAL LDQUOT qopval ("," qopval)* RDQUOT;

    digest  = realm | domain | nonce | opaque | stale | algo | qop;

    challenge := "Digest" LWS digest (COMMA digest)*;
}%%

%% write init;
%% write exec;

    if cs >= challenge_first_final {
        return ch, nil
    }
    return nil, ErrorSIPHeader.msg("Invalid challenge: %s", data[m:p])
}
