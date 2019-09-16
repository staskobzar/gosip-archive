// -*-go-*-
//
// SIP headers and first line parser
package sipmsg

import "errors"

%% machine msg;
%% write data;

func parseHeader(msg *Message, data []byte) (HdrType, error) {
	cs := 0 // current state. entery point = 0
	l := ptr(len(data))
	var pos []pl
	var p, // data pointer
		m, // marker
		pe ptr = 0, 0, l
	var dname, 		// display name
		addr,
		tag pl;		// to/from tag
	var params []pl;
	
	var id HdrType
%%{

	action sm	  { m = p }
	action push   { pos = append(pos, pl{m, p}) }
	action tag    { tag = pl{m, p} }
	action dname  { dname.p =m; dname.l = p }
	action addr   { if addr.p == 0 {addr.p = m; addr.l = p}}
	action param  { params = append(params, pl{m, p})}

	include grammar "grammar.rl";
	
    addr_spec       = (SIP_URI | ABS_URI) >sm %addr;
    tag_param       = "tag"i EQUAL token >sm %tag;
    generic_param   = (token -- "tag"i) >sm ( EQUAL gen_value )? %param;
	name_addr 		= (display_name >sm %dname)? LAQUOT addr_spec RAQUOT;
	param_tofrom 	= tag_param | generic_param;
	tofrom_value    = ( name_addr | addr_spec ) ( SEMI param_tofrom )*;
	# @Contact, @Date,
	# @Expires, @Route, @RecordRoute, and @Via

	# @Status-Line@
	StatusLine 	= SIP_Version >sm %push SP digit{3} >sm %push SP
				  Reason_Phrase >sm %push CRLF @{id = msg.setStatusLine(data, pos) };
	# @Request-Line@
	RequestLine = Method >sm %push SP RequestURI >sm %push SP
				  SIP_Version >sm %push CRLF @{id = msg.setRequestLine(data, pos)};
	# @CSeq@
	CSeq		= "CSeq"i >sm %push HCOLON digit+ >sm %push
				  LWS Method >sm %push CRLF @{id = msg.setCSeq(data, pos)};
	# @Call-ID@
	CallID 		= ( "Call-ID"i | "i"i ) >sm %push HCOLON
				  ( word ( "@" word )? ) >sm %push CRLF @{id = msg.setCallID(data, pos)};
	# @Content-Length@
	ContentLen  = ( "Content-Length"i | "l"i ) >sm %push HCOLON
				  digit+ >sm %push CRLF @{id = msg.setContentLen(data, pos)};
	# @From@
	From        = ( "From"i | "f"i ) >sm %push HCOLON tofrom_value CRLF
				  @{id = msg.setFrom(data, params, pos[0], dname, addr, tag)};
	# @To@
	To          = ( "To"i | "t"i ) >sm %push HCOLON tofrom_value CRLF
				  @{id = msg.setTo(data, params, pos[0], dname, addr, tag)};

	siphdr :=   StatusLine
			  | RequestLine
			  | CSeq
			  | CallID
			  | ContentLen
			  | To
			  | From;
}%%
	%% write init;
	%% write exec;
	if cs >= msg_first_final {
		return id, nil
	}
	return -1, errors.New("Invalid SIP message header: " + string(data))
}
