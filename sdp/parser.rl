// -*-go-*-
//
// SDP message parser
package sdp

import "bytes"

%% machine sdp;
%% write data;

// Parse scan and parse bytes array to SDP Message structure
func Parse(data []byte) (*Message, error) {
    var cs, p, pe, m int
    pe = len(data)

    msg := &Message{}
    // when media index is >= then it is media fields context
    // otherwise it is session context
    msg.mediaIdx = -1

%%{
    # ACTIONS
    action sm            { m = p }
    action info_field    { msg.setInfo(data[m:p]) }
    action conn_nettype  { msg.setConnNetType(data[m:p]) }
    action conn_addrtype { msg.setConnAddrType(data[m:p]) }
    action conn_addr     { msg.setConnAddress(data[m:p]) }
    action media_set     { msg.setMedia() }
    action attr_fkey     { msg.setAttrKey(data[m:p]) }
    action attr_fval     { msg.setAttrValue(data[m:p]) }
    action attr_flag     { msg.setAttrFlag(data[m:p]) }
    action start_time    { msg.setStartTime(data[m:p]) }
    action stop_time     { msg.setStopTime(data[m:p]) }
    action repeat        { msg.setRepeatField(data[m:p]) }
    action bw_set        { msg.setBandwidth(data[m:p]) }
    action bw_val        { msg.setBwidthValue(data[m:p]) }
    action enc_key       { msg.setEncKey(data[m:p]) }
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
    info_field    = "i=" TEXT >sm %info_field CRLF; # optional
    uri_field     = "u=" URI  >sm %{ msg.uri = data[m:p] } CRLF;  # optional
    # zero or more email fields
    email_field   = "e=" EMAIL >sm %{ msg.Email = append(msg.Email, data[m:p]) } CRLF;
    # zero or more phone fields
    phone_field   = "p=" PHONE >sm %{ msg.Phone = append(msg.Phone, data[m:p]) } CRLF;
    conn_field    = "c=" TOKEN >sm %conn_nettype SP TOKEN >sm %conn_addrtype SP
                         conn_addr >sm %conn_addr CRLF; # optional
                         # not required if included in all media
    # zero or more bandwidth information lines
    bwidth_field  = "b=" bwtype >sm %bw_set ":" bandwidth >sm %bw_val CRLF;
    time_field    = "t=" start_time >sm %start_time SP stop_time >sm %stop_time CRLF;
    repeat_field  = "r=" typed_time >sm (SP typed_time)+ %repeat CRLF;
    zone_adjust   = "z=" time >sm SP "-"? typed_time (SP time SP "-"? typed_time)*
                    %{ msg.tzones = data[m:p] } CRLF;
    # does anyone use this anyway???!!!
    key_field     = "k=" TEXT >sm %enc_key CRLF;
    attr_field    = "a=" attribute CRLF; # zero or more session attribute lines
    media_field   = "m=" media >sm %{ msg.Medias[msg.mediaIdx].mtype = data[m:p] } SP
                    port >sm %{ msg.Medias[msg.mediaIdx].port = data[m:p] }
                    ("/" digit+ >sm %{ msg.Medias[msg.mediaIdx].nport = data[m:p] })? SP
                    proto >sm %{ msg.Medias[msg.mediaIdx].proto = data[m:p] } (SP TOKEN)+ >sm
                    %{ msg.Medias[msg.mediaIdx].fmt = bytes.TrimSpace(data[m:p]) } CRLF;

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
    // improve error message
    e := pe
    if (p + 12) < e {
        e = p + 12
    }
    s := 0
    if (p - 24) > 0 {
        s  = p - 24
    }
    return nil, ErrorSDPParsing.msg("%q... [position=%d]", data[s:e], p)
}
