// -*-go-*-
//
// SIP(s) URI parser
package sipmsg

%% machine uri;
%% write data;

func URIParse(data []byte) *URI {
    uri := &URI{buf: data}
    p := 0 // data pointer
    cs := 0 // current state. entery point = 0
    pe := len(data)
    eof := len(data)
    m := 0 // marker
%%{
    action sm   { m = p }
    action sips { uri.scheme    = pl{0,p}; uri.id = URIsips; }
    action sip  { uri.scheme    = pl{0,p}; uri.id = URIsip; }
    action abs  { uri.scheme    = pl{0,p}; uri.id = URIabs; }
    action user {
        from := uri.scheme.l + 1
        if uri.id == URIabs { from = m }
        uri.user = pl{ from, p }
    }
    action host { uri.host      = pl{ m, p }}
    action pass { uri.password  = pl{ m, p }}
    action port { uri.port      = pl{ m, p }}
    action parm { uri.params    = pl{ m, p }}
    action head { uri.headers   = pl{ m, p }}

    include grammar "grammar.rl";

    schsip      = ( scheme_sip %sip | scheme_sips %sips );
    l_hostport  = host >sm %host ( ":" port >sm %port )?;
    l_userinfo  = user >sm %user ( ":" password >sm %pass )? "@";

    sipuri      = schsip ":" l_userinfo? l_hostport
                  ( ";" uri_parameter )* >sm %parm
                  ( headers >sm %head )?;

    absuri      = ( scheme_abs - schsip ) ":" %~abs
                  ( hier_part | opaque_part );

    uri := absuri | sipuri;
}%%
    %% write init;
    %% write exec;
    if cs >= uri_first_final {
        return uri
    }
    return nil
}
