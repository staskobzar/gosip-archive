// -*-go-*-
//
// SDP message parser
package sdp

%% machine sdp;
%% write data;

// Parse scan and parse bytes array to SDP Message structure
func Parse(data []byte) (*Message, error) {
    var cs, p, pe, m int
    pe = len(data)

    // when media index is >= then it is media fields context
    // otherwise it is session context
    mediaIdx := -1
    msg := &Message{}

%%{
    # ACTIONS
    action sm        { m = p }
    action media_set {
        if mediaIdx == -1 {
            msg.Medias = make(Medias, 1)
            mediaIdx = 0
        } else {
            mediaIdx++
            msg.Medias = append(msg.Medias, Media{})
        }
    }
    action attr_fkey {
        if mediaIdx == -1 {
            msg.Attr = append(msg.Attr, Attribute{})
            i := len(msg.Attr) - 1
            msg.Attr[i].key = data[m:p]
        } else {
            msg.Medias[mediaIdx].attr = append(msg.Medias[mediaIdx].attr, Attribute{})
            i := len(msg.Medias[mediaIdx].attr) - 1
            msg.Medias[mediaIdx].attr[i].key = data[m:p]
        }
    }
    action attr_fval {
        if mediaIdx == -1 {
            i := len(msg.Attr) - 1
            msg.Attr[i].value = data[m:p]
        } else {
            i := len(msg.Medias[mediaIdx].attr) - 1
            msg.Medias[mediaIdx].attr[i].value = data[m:p]
        }
    }
    action attr_flag {
        if mediaIdx == -1 {
            msg.Attr = append(msg.Attr, Attribute{})
            i := len(msg.Attr) - 1
            msg.Attr[i].flag = data[m:p]
            msg.Attr[i].isFlag = true
        } else {
            msg.Medias[mediaIdx].attr = append(msg.Medias[mediaIdx].attr, Attribute{})
            i := len(msg.Medias[mediaIdx].attr) - 1
            msg.Medias[mediaIdx].attr[i].flag = data[m:p]
            msg.Medias[mediaIdx].attr[i].isFlag = true
        }
    }
    action start_time {
        msg.Time = append(msg.Time, TimeDesc{start: data[m:p]})
    }
    action stop_time {
        i := len(msg.Time) - 1
        msg.Time[i].stop = data[m:p]
    }
    action repeat {
        i := len(msg.Time) - 1
        msg.Time[i].Repeat = append(msg.Time[i].Repeat, data[m:p])
    }
    action bw_set {
        msg.BandWidth = append(msg.BandWidth, BandWidth{bt: data[m:p]})
    }
    action bw_val {
        i := len(msg.BandWidth) - 1
        msg.BandWidth[i].bw = data[m:p]
    }

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
    URI           = TEXT;
    EMAIL         = TEXT;
    PHONE         = TEXT;

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
    ktype_base64  = "base64:" TEXT;
    ktype_uri     = "uri:" TEXT;
    key_type      = ktype_prompt | ktype_clear | ktype_base64 | ktype_uri;
    attr_kv       = TOKEN >sm %attr_fkey ":" TEXT >sm %attr_fval;
    attr_flag     = TOKEN >sm %attr_flag;
    attribute     = attr_kv | attr_flag;
    media         = "audio" | "video" | "text" | "application" | TOKEN;
    proto         = TOKEN ("/" TOKEN)*; # typically "RTP/AVP" or "udp"
    time          = POS_DIGIT digit{9,};


    # SDP members
    proto_ver     = "v=" digit >sm %{ msg.ver = data[m] } CRLF;
    origin_field  = "o=" username SP sess_id SP sess_ver SP
                         nettype SP addrtype SP unicast_addr >sm
                         %{ msg.Origin.unicAddr = data[m:p] } CRLF;
    session_name  = "s=" TEXT >sm %{ msg.subject = data[m:p] } CRLF;
    # TODO: unit test
    info_field    = "i=" TEXT >sm %{ msg.info = data[m:p] } CRLF; # optional
    uri_field     = "u=" URI  >sm %{ msg.uri = data[m:p] } CRLF;  # optional
    # zero or more email fields
    email_field   = "e=" EMAIL >sm %{ msg.Email = append(msg.Email, data[m:p]) } CRLF;
    # zero or more phone fields
    phone_field   = "p=" PHONE >sm %{ msg.Phone = append(msg.Phone, data[m:p]) } CRLF;
    conn_field    = "c=" TOKEN >sm %{ msg.Conn.netType = data[m:p] } SP
                         TOKEN >sm %{ msg.Conn.addrType = data[m:p] } SP
                         conn_addr >sm %{ msg.Conn.address = data[m:p] } CRLF; # optional
                         # not required if included in all media
    # TODO: unit test
    # zero or more bandwidth information lines
    bwidth_field  = "b=" bwtype >sm %bw_set ":" bandwidth >sm %bw_val CRLF;
    time_field    = "t=" start_time >sm %start_time SP stop_time >sm %stop_time CRLF;
    repeat_field  = "r=" typed_time >sm (SP typed_time)+ %repeat CRLF;
    zone_adjust   = "z=" time >sm SP "-"? typed_time (SP time SP "-"? typed_time)*
                    %{ msg.tzones = data[m:p] } CRLF;
    # TODO: unit test
    key_field     = "k=" key_type CRLF;
    attr_field    = "a=" attribute CRLF; # zero or more session attribute lines
    media_field   = "m=" media >sm %{ msg.Medias[mediaIdx].mtype = data[m:p] } SP
                    port >sm %{ msg.Medias[mediaIdx].port = data[m:p] }
                    ("/" digit+ >sm %{ msg.Medias[mediaIdx].nport = data[m:p] })? SP
                    proto >sm %{ msg.Medias[mediaIdx].proto = data[m:p] }
                    (SP TOKEN)+ >sm %{ msg.Medias[mediaIdx].fmt = data[m:p] } CRLF;

    time_fields   = time_field repeat_field*;
    medias        = media_field >media_set
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
            time_fields+
            zone_adjust?
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
