// -*-go-*-
//
// SIP headers and first line parser
package sipmsg

import (
    "bytes"
)

var ErrorSIPHeader = errorNew("Invalid SIP Header")

%% machine msg;
%% write data;

func parseHeader(msg *Message, data []byte) (HdrType, error) {
    cs := 0 // current state. entery point = 0
    l := ptr(len(data))
    pos := make([]pl, 0, 12)
    params := make([]pl, 0, 12)
    var p, // data pointer
        m, // marker
        pe ptr = 0, 0, l
    var dname,         // display name
        trans,
        addr,
        port,
        ttl,
        maddr,
        recvd,
        branch,
        tag pl;        // to/from tag

    hidx := 0 // header value index

    var id HdrType

    if bytes.Equal(data, []byte("\r\n")) {
        return MsgEOF, nil
    }
%%{

    action sm        { m = p }
    action push      { pos = append(pos, pl{m, p}) }
    action tag       { tag = pl{m, p} }
    action dname     { dname.p =m; dname.l = p }
    action addr      { addr.p = m; addr.l = p }
    action port      { port.p = m; port.l = p }
    action trans     { trans.p = m; trans.l = p }
    action param     { params = append(params, pl{m, p}) }
    action reset_cnt { hidx = msg.Contacts.Count(); params = make([]pl, 0, 12) }
    action init_via  { hidx = msg.Vias.Count() }
    action reset_via {
        branch.p = 0; branch.l = 0
        ttl.p    = 0; ttl.l    = 0
        maddr.p  = 0; maddr.l  = 0
        recvd.p  = 0; recvd.l  = 0
    }
    action contact   { msg.setContact(data[:], pos[0], dname, addr, params, hidx) }
    action via       {
        msg.setVia(data[:], pos[0], trans, addr, port, branch, ttl, maddr, recvd, hidx)
    }
    action reset_route { params = make([]pl, 0, 12) }
    action route     { msg.setRoute(id, data[:], pos[0], dname, addr, params) }

    include grammar "grammar.rl";

    # -- COMMA decreases machines but fails to parse , in To header username
    addr_spec       = (SIP_URI | ABS_URI) >sm %addr;
    tag_param       = "tag"i EQUAL token >sm %tag;
    fromto_gparam   = (token -- "tag"i) >sm ( EQUAL gen_value )? %param;
    name_addr       = (display_name >sm %dname)? LAQUOT addr_spec RAQUOT;
    param_tofrom    = tag_param | fromto_gparam;
    tofrom_value    = ( name_addr | (addr_spec -- SEMI) ) ( SEMI param_tofrom )*;
    contact_value   = (( name_addr | (addr_spec -- SEMI)) ( SEMI contact_params >sm %param )* )
                      >reset_cnt %contact;

    via_ttl         = "ttl"i EQUAL digit{1,3} >sm %{ ttl.p = m; ttl.l = p };
    via_maddr       = "maddr"i EQUAL host >sm %{ maddr.p = m; maddr.l = p };
    via_received    = "received"i EQUAL (IPv4address | IPv6address) >sm %{ recvd.p = m; recvd.l = p};
    via_branch      = "branch"i EQUAL (branch_cookie token) >sm %{ branch.p = m; branch.l = p };
    via_params      = via_ttl | via_maddr | via_received | via_branch | via_generic;
    via_sent_proto  = "SIP" SLASH digit "." digit SLASH >init_via transport >sm %trans;
    sent_by         = host >sm %addr (COLON port >sm %port)?;
    via_parm        = ( via_sent_proto LWS sent_by (SEMI via_params)* )
                      >reset_via %via;
    route_param     = ( name_addr ( SEMI generic_param >sm %param )* ) >reset_route %route;

    # @Status-Line@
    StatusLine  = SIP_Version >sm %push SP digit{3} >sm %push SP
                  Reason_Phrase >sm %push CRLF @{ id = msg.setStatusLine(data, pos) };
    # @Request-Line@
    RequestLine = Method >sm %push SP RequestURI >sm %push SP
                  SIP_Version >sm %push CRLF @{ id = msg.setRequestLine(data, pos) };
    # @CSeq@
    CSeq        = name_cseq >sm %push HCOLON digit{1,10} >sm %push
                  LWS Method >sm %push CRLF @{ id = msg.setCSeq(data, pos) };
    # @Call-ID@
    CallID      = name_callid >sm %push HCOLON
                  ( word ( "@" word )? ) >sm %push CRLF @{ id = msg.setCallID(data, pos) };
    # @Content-Length@
    ContentLen  = name_cnt_len >sm %push HCOLON
                  digit{1,10} >sm %push CRLF @{ id = msg.setContentLen(data, pos) };
    # @From@
    From        = name_from >sm %push HCOLON tofrom_value CRLF
                  @{ id = msg.setFrom(data, params, pos[0], dname, addr, tag) };
    # @To@
    To          = name_to >sm %push HCOLON tofrom_value CRLF
                  @{ id = msg.setTo(data, params, pos[0], dname, addr, tag) };
    # @Contact@
    Contact     = name_contact >sm %push HCOLON
                  ( STAR %{ msg.setContactStar() } | 
                  ( contact_value ( COMMA contact_value )* )) CRLF
                  @{ id = SIPHdrContact; };
    # @Via@
    Via         = name_via >sm %push HCOLON via_parm
                  ( COMMA via_parm )* CRLF @{ id = SIPHdrVia }; 
    # @Route@
    Route       = name_route >sm %push HCOLON %{id = SIPHdrRoute}
                  route_param (COMMA route_param)* CRLF;
    # @Record-Route@
    RecordRoute = name_rroute >sm %push HCOLON %{id = SIPHdrRecordRoute}
                  route_param (COMMA route_param)* CRLF;
    # @Expires@
    Expires     = name_expires HCOLON digit{1,10} >sm %{ id = msg.setExpires(data[m:p]) } CRLF;
    # @Max-Forwards@
    MaxForwards = name_maxfwd HCOLON digit{1,6} >sm %{ id = msg.setMaxFwd(data[m:p]) } CRLF;
    # Other headers (generic)
    OtherHeader = header_name >sm %push HCOLON %sm header_value %push CRLF
                  @{ id = msg.setGenericHeader(data, pos) };

    siphdr :=   StatusLine
              | CSeq
              | CallID
              | Contact
              | ContentLen
              | Expires
              | From
              | MaxForwards
              | RecordRoute
              | RequestLine
              | Route
              | To
              | Via
              | OtherHeader;
}%%
    %% write init;
    %% write exec;
    if cs >= msg_first_final {
        return id, nil
    }
    return -1, ErrorSIPHeader.msg("%s", data)
}
