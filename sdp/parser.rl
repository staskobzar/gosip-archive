// -*-go-*-
//
// SDP message parser
package sdp

%% machine sdp;
%% write data;

func Parse(data []byte) (*Message, error) {
    var cs, p, pe, m int
    pe = len(data)

    msg := &Message{}

%%{
    # ACTIONS
    action sm { m = p }

    # GRAMMAR
    CRLF          = "\r\n";
    SP            = 0x20;
    VCHAR         = 0x21..0x7E;  # visible (printing) characters
    TOKEN_CHAR    = 0x21 | 0x23..0x27 | 0x2A..0x2B | 0x2D..0x2E | 0x30..0x39 |
                    0x41..0x5A | 0x5E..0x7E;
    TOKEN         = TOKEN_CHAR+;
    TEXT          = (0x01..0x09 | 0x0B..0x0C | 0x0E..0xFF)+; # byte string: any byte except NUL,
                                                            # CR, or LF
    POS_DIGIT     = 0x31..0x39;
    NONE_WS_STR   = ( VCHAR | 0x80..0xFF )+; # string of visible characters
    hex4          = xdigit{1,4};
    hexseq        = hex4 ( ":" hex4 )*;
    hexpart       = hexseq | hexseq "::" hexseq? | "::" hexseq?;
    IP4_ADDR      = digit{1,3} "." digit{1,3} "." digit{1,3} "." digit{1,3};
    IP4_MCAST     = (("22" 0x34..0x39) | ("23" digit)) "." digit{1,3} "." digit{1,3}
                    "." digit{1,3} "/" digit{1,3} ("/" digit)?;
    IP6_ADDR      = hexpart ( ":" IP4_ADDR )?;
    IP6_MCAST     = hexpart ( "/" digit )?;
    FQDN          = (alnum | "-" | "."){4,};
    EXTEN_ADDR    = TOKEN;
    URI           = any+;
    EMAIL         = any+;
    PHONE         = any+;

    username      = NONE_WS_STR >sm %{ msg.Origin.username = data[m:p] };
    sess_id       = digit+ >sm %{ msg.Origin.sessID = data[m:p] };
    sess_ver      = digit+ >sm %{ msg.Origin.sessVer = data[m:p] };
    nettype       = TOKEN >sm %{ msg.Origin.netType = data[m:p] };  # typically "IN"
    addrtype      = TOKEN >sm %{ msg.Origin.addrType = data[m:p] };  # typically "IP4" or "IP6"
    unicast_addr  = IP4_ADDR | IP6_ADDR | FQDN | EXTEN_ADDR;
    mcast_addr    = IP4_MCAST | IP6_MCAST | FQDN | EXTEN_ADDR;
    conn_addr     = mcast_addr | unicast_addr;
    bwtype        = TOKEN;
    bandwidth     = digit+;
    port          = digit+;
    start_time    = digit+;
    stop_time     = digit+;
    typed_time    = digit+ ("d" | "h" | "m" | "s")?;
    ktype_prompt  = "prompt";
    ktype_clear   = "clear:" TEXT;
    ktype_base64  = "base64:" any+;
    ktype_uri     = "uri:" any+;
    key_type      = ktype_prompt | ktype_clear | ktype_base64 | ktype_uri;
    attribute     = (TOKEN ":" TEXT) | TOKEN;
    media         = "audio" | "video" | "text" | "application" | TOKEN;
    proto         = TOKEN ("/" TOKEN)*; # typically "RTP/AVP" or "udp"
    time          = POS_DIGIT digit{9,};


    # SDP members
    proto_ver     = "v=" digit >sm %{msg.ver = data[m]} CRLF;
    origin_field  = "o=" username SP sess_id SP sess_ver SP
                         nettype SP addrtype SP unicast_addr >sm
                         %{ msg.Origin.unicAddr = data[m:p] } CRLF;
    session_name  = "s=" TEXT CRLF;
    info_field    = "i=" TEXT CRLF; # optional
    uri_field     = "u=" URI CRLF;  # optional
    email_field   = "e=" EMAIL CRLF; # zero or more
    phone_field   = "p=" PHONE CRLF; # zero or more
    conn_field    = "c=" nettype SP addrtype SP conn_addr CRLF; # optional
                                    # not required if included in all media
    bwidth_field  = "b=" bwtype ":" bandwidth CRLF; # zero or more bandwidth information lines
    time_field    = "t=" start_time SP stop_time CRLF;
    repeat_field  = "r=" typed_time (SP typed_time)+ CRLF; 
    zone_adjust   = "z=" time SP "-"? typed_time (SP time SP "-"? typed_time)* CRLF;
    key_field     = "k=" key_type CRLF;
    attr_field    = "a=" attribute CRLF; # zero or more session attribute lines
    media_field   = "m=" media SP port ("/" digit+)? SP proto (SP TOKEN)+ CRLF;

    time_fields   = time_field repeat_field* zone_adjust?;
    medias        = media_field
                    info_field?
                    conn_field?
                    bwidth_field*
                    key_field?
                    attr_field*;

    # RFC4566 5#SDP Specification: Some lines in each description are REQUIRED and
    # some are OPTIONAL, but all MUST appear in exactly the order given here:

    main := proto_ver
            origin_field
            session_name
            info_field?
            uri_field?
            email_field*
            phone_field*
            conn_field?
            bwidth_field*
            time_fields
            key_field?
            attr_field*
            medias*;
}%%
%% write init;
%% write exec;
    if cs >= sdp_first_final {
        return msg, nil
    }
    return nil, ErrorSDPParsing.msg("'%s' [%d]", data[:p], p)
}
