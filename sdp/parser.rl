// -*-go-*-
//
// SDP message parser
package sdp

%% machine sdp;
%% write data;

func parse(data []byte) (*Message, error) {

%%{
    CRLF          = "\r\n";
    SP            = 0x20;
    VCHAR         = 0x21..0x7E;  # visible (printing) characters
    TOKEN_CHAR    = 0x21 | 0x23..0x27 | 0x2A..0x2B | 0x2D..0x2E | 0x30..0x39 |
                    0x41..0x5A | 0x5E..0x7E;
    TOKEN         = TOKEN_CHAR+;
    TEXT          = (0x01..0x09 | 0x0B..0x0C | 0x0E..0xFF)+; # any byte except NUL, CR, or LF
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

    username      = NONE_WS_STR;
    sess_id       = digit+;
    sess_ver      = digit+;
    nettype       = TOKEN;  # typically "IN"
    addrtype      = TOKEN;  # typically "IP4" or "IP6"
    unicast_addr  = IP4_ADDR | IP6_ADDR | FQDN | EXTEN_ADDR;
    mcast_addr    = IP4_MCAST | IP6_MCAST | FQDN | EXTEN_ADDR;
    conn_addr     = mcast_addr | unicast_addr;
    bwtype        = TOKEN;
    bandwidth     = digit+;
    start_time    = digit+;
    stop_time     = digit+;
    repeat_val    = digit | "d" | "h" | "m" | "s";

    proto_ver     = "v=" digit CRLF;
    origin_field  = "o=" username SP sess_id SP sess_ver SP
                         nettype SP addrtype SP unicast_addr CRLF;
    session_name  = "s=" TEXT CRLF;
    info_field    = "i=" TEXT CRLF; # optional
    uri_field     = "u=" URI CRLF;  # optional
    email_fields  = "e=" EMAIL CRLF; # zero or more
    phone_fields  = "e=" PHONE CRLF; # zero or more
    conn_field    = "c=" nettype SP addrtype SP conn_addr CRLF; # optional
                                    # not required if included in all media
    bwidth_fields = "b=" bwtype ":" bandwidth CRLF; # zero or more bandwidth information lines
    time_fields   = "t=" start_time SP stop_time CRLF;
    repeat_fields = "r=" repeat_val+ (SP repeat_val)+; 
    zone_adjust   = "z="

    # RFC4566 5#SDP Specification: Some lines in each description are REQUIRED and
    # some are OPTIONAL, but all MUST appear in exactly the order given here:

}%%
    return nil, nil
}
