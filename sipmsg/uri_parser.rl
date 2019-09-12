// -*-go-*-
//
// SIP(s) URI parser
package sipmsg

%% machine uri;
%% write data;

%%{

    # TODO: pound (#) is not allowed but often used.(?)
    mark            = [\-_.!~*'()];
    unreserved      = alnum | mark;
    escaped         = "%" xdigit xdigit;
    user_unreserved = [&=+$,;?/];
    param_unreserved= [\[\]/:&+$];
    paramchar       = param_unreserved | unreserved | escaped;
    token           = (alnum | [\-.!%*_+`'~])+;
    Method          = "INVITE" | "ACK" | "OPTIONS" | "BYE" | "CANCEL" | "REGISTER"
                      | token;
    user            = ( unreserved | escaped | user_unreserved )+;
    password        = ( unreserved | escaped | [&=+$,] )*;
    hex4            = xdigit{1,4};
    hexseq          = hex4 (":" hex4)*;
    hexpart         = hexseq | hexseq "::" hexseq? | "::" hexseq?;

    domainlabel     = alnum | alnum ( alnum | "-" )* alnum;
    toplabel        = alpha | alpha ( alnum | "-" )* alnum;
    hostname        = ( domainlabel "." )* toplabel "."?;

    IPv4address     = digit{1,3} "." digit{1,3} "." digit{1,3} "." digit{1,3};
    IPv6address     = hexpart (":" IPv4address)?;
    IPv6reference   = "[" IPv6address "]";

    host            = hostname | IPv4address | IPv6reference;
    port            = digit{1,5};

    transport_param = "transport="i ( "udp"i | "tcp"i | "sctp"i | "tls"i | token );
    user_param      = "user="i ("phone"i | "ip"i | token);
    method_param    = "method="i Method;
    ttl_param       = "ttl="i digit{1,3};
    maddr_param     = "maddr="i host;
    lr_param        = "lr"i;
    other_param     = paramchar+ ("=" paramchar+)?;
    uri_parameter   = transport_param | user_param | method_param | ttl_param |
                      maddr_param | lr_param | other_param;

    hnv_unreserved  = (param_unreserved -- "&") | "?";
    hnameval        =  hnv_unreserved | unreserved | escaped;
    header          = hnameval+ "=" hnameval*;
    headers         = "?" header ( "&" header )*;
}%%

func SIPURIParse(data []byte) *URI {
    uri := &URI{buf: data}
    p := 0 // data pointer
    cs := 0 // current state. entery point = 0
    pe := len(data)
    eof := len(data)
    m := 0 // marker
%%{
    action sm   { m = p }
    action schm { uri.scheme    = pl{ 0, p }}
    action user { uri.user      = pl{ uri.scheme.l + 1, p }}
    action host { uri.host      = pl{ m, p }}
    action pass { uri.password  = pl{ m, p }}
    action port { uri.port      = pl{ m, p }}
    action parm { uri.params    = pl{ m, p }}
    action head { uri.headers   = pl{ m, p }}

    scheme      = ("sip" | "sips") %schm;
    userinfo    = user %user ( ":" password >sm %pass)? "@";
    hostport    = host >sm %host ( ":" port >sm %port)?;

    uri := scheme ":" userinfo? hostport
           (";" uri_parameter)* >sm %parm
           (headers >sm %head)?;
}%%
    %% write init;
    %% write exec;
    if cs >= uri_first_final {
        return uri
    }
    return nil
}
