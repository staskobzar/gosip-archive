// -*-go-*-
//
// Parsing HTTP challenge data
package sipmsg

import "strconv"

// --------------------------------------------------------------------------------
// HTTP Credentials parser
// --------------------------------------------------------------------------------
%% machine credentials;
%% write data;

func parseCredentials (data []byte) (*Credentials, error) {
    cs := 0
    l := ptr(len(data))
    var p, m, pe, eof ptr = 0, 0, l, l
    cr := &Credentials{}

%%{
    action sm        { m = p }
    action username  { cr.username = data[m + 1: p - 1] }
    action realm     { cr.realm = data[m + 1: p - 1] }
    action nonce     { cr.nonce = data[m + 1:p - 1] }
    action duri      { cr.uri = data[m:p] }
    action resp      { cr.response = data[m:p] }
    action cnonce    { cr.cnonce = data[m + 1:p - 1] }
    action opaque    { cr.opaque = data[m + 1:p - 1] }
    action nc        {
        n, err := strconv.ParseUint(string(data[m:p]), 16, 32)
        if err != nil {
            return nil, ErrorSIPHeader.msg("Invalid nonce count: %s", data[m:p])
        }
        cr.nc = uint(n)
    }

    include grammar "grammar.rl";

    qopval  = ("auth"i %{ cr.qop |= QOPAuth } | "auth-int"i %{ cr.qop |= QOPAuthInt });

    username    = "username"i EQUAL quoted_string >sm %username;
    realm       = "realm"i EQUAL quoted_string >sm %realm;
    nonce       = "nonce"i EQUAL quoted_string >sm %nonce;
    digest_uri  = "uri"i EQUAL LDQUOT RequestURI >sm %duri RDQUOT;
    cnonce      = "cnonce"i EQUAL quoted_string >sm %cnonce;
    nonce_count = "nc"i EQUAL LHEX{8} >sm %nc;
    response    = "response"i EQUAL LDQUOT LHEX{32} >sm %resp RDQUOT;
    algo        = "algorithm"i EQUAL
                  ( "MD5"i %{cr.algo = AlgoMD5} | "MD5-sess"i %{cr.algo = AlgoMD5sess} );
    opaque      = "opaque"i EQUAL quoted_string >sm %opaque;
    qop         = "qop"i EQUAL qopval;

    digest      = username | realm | nonce | digest_uri | response | algo |
                  cnonce | opaque | qop | nonce_count;

    credentials := "Digest" LWS digest (COMMA digest)*;
}%%

%% write init;
%% write exec;

    if cs >= credentials_first_final {
        return cr, nil
    }
    return nil, ErrorSIPHeader.msg("Invalid credentials: %s", data[m:p])
}
