// -*-go-*-
//
// SIP(s) URI parser
package sip

%% machine uri;
%% write data;

%%{

    # TODO: pound (#) is not allowed but often used.(?)
    mark            = graph | [_.*'()]; # [-_.!~*'()] -- [!-~]
    unreserved      = alnum | mark;
    escaped         = '%' xdigit xdigit;
    user_unreserved = [&=+$,;?/];
    user            = ( unreserved | escaped | user_unreserved )+;
    password        = ( unreserved | escaped | [&=+$,] )*;
    hex4            = xdigit{1,4};
    hexseq          = hex4 (':' hex4)*;
    hexpart         = hexseq | hexseq '::' hexseq? | '::' hexseq?;

    domainlabel     = alnum | alnum ( alnum | '-' )* alnum;
    toplabel        = alpha | alpha ( alnum | '-' )* alnum;
    hostname        = ( domainlabel "." )* toplabel "."?;

    IPv4address     = digit{1,3} '.' digit{1,3} '.' digit{1,3} '.' digit{1,3};
    IPv6address     = hexpart (':' IPv4address)?;
    IPv6reference   = '[' IPv6address ']';

    host            = hostname | IPv4address | IPv6reference;
    port            = digit{1,5};
}%%

func SIPURIParse(data []byte) *URI {
    uri := &URI{}
    p := 0 // data pointer
    cs := 0 // current state. entery point = 0
    pe := len(data)
    eof := len(data)
    m := 0 // marker
%%{
    action mark { m = p }
    action user { uri.user = string(data[m:p]) }
    action host { uri.host = string(data[m:p]) }
    scheme      = "sip" %{uri.scheme = "sip"} | "sips" %{uri.scheme = "sips"};
    userinfo    = user >mark %user (':' password)? "@";
    hostport    = host >mark %host ( ":" port )?;
#SIP-URI          =  "sip:" [ userinfo ] hostport
#                    uri-parameters [ headers ]
#SIPS-URI         =  "sips:" [ userinfo ] hostport
#                    uri-parameters [ headers ]
    uri := scheme ':' userinfo hostport;
}%%
    %% write init;
    %% write exec;
    if cs >= uri_first_final {
        return uri
    }
    return nil
}
