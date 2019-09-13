// -*-go-*-
//
// SIP(s) URI parser
package sipmsg

%% machine msg;
%% write data;

func parseHeader(data []byte) *header {
	h := &header{buf: data}
	cs := 0 // current state. entery point = 0
	l := ptr(len(data))
	var p, // data pointer
		m, // marker
		pe, eof ptr = 0, 0, l, l
	var pos []pl
%%{

	action sm	{ m = p }
	action push { pos = append(pos, pl{m, p}) }

	include grammar "grammar.rl";

	StatusLine = SIP_Version >sm %push SP digit{3} >sm %push SP
				 Reason_Phrase >sm %push CRLF @{setStatusLine(h, pos)};
	msg := StatusLine;
}%%
	%% write init;
	%% write exec;
	if cs >= msg_first_final {
		println(m, eof)
		return h
	}
	return nil
}

func setStatusLine(h *header, pos []pl) {
	h.resp = statusLine{
		ver: pos[0],
		code: pos[1],
		reason: pos[2],
	}
}
