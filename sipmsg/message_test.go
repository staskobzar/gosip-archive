package sipmsg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessageParse(t *testing.T) {
	str := "REGISTER sip:registrar.biloxi.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP bobspc.biloxi.com:5060;branch=z9hG4bKnashds7\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: Bob <sip:bob@biloxi.com>\r\n" +
		"From: Bob <sip:bob@biloxi.com>;tag=456248\r\n" +
		"Call-ID: 843817637684230@998sdasdh09\r\n" +
		"CSeq: 1826 REGISTER\r\n" +
		"Contact: <sip:bob@192.0.2.4>\r\n" +
		"Expires: 7200\r\n" +
		"Content-Length: 0\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)
	assert.True(t, msg.IsRequest())
	assert.False(t, msg.IsInvite())
	assert.False(t, msg.IsResponse())
	assert.Equal(t, "sip:registrar.biloxi.com", msg.ReqLine.RequestURI())
	assert.EqualValues(t, 7200, msg.Expires)
	assert.Equal(t, 1, msg.Vias.Count())
	assert.EqualValues(t, 1826, msg.CSeq.Num)
	assert.EqualValues(t, "REGISTER", msg.CSeq.Method)
	assert.Equal(t, "843817637684230@998sdasdh09", msg.CallID)
	assert.Equal(t, 0, msg.Code())
}

func TestMessageParseMultiLineHeaders(t *testing.T) {
	str := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/TLS ss1.example.com:5061\r\n" +
		"     ;branch=z9hG4bK83754\r\n" +
		"Via: SIP/2.0/TLS client4.biloxi.example.com:5061\r\n" +
		" ;branch=z9hG4bKnashds7\r\n" +
		"\t ;received=192.0.2.105\r\n" +
		"Max-Forwards: 69\r\n" +
		"From: Bob <sips:bob@biloxi.example.com>;tag=7137136\r\n" +
		"To: Alice <sips:alice@atlanta.example.com>;tag=1234567\r\n" +
		"Call-ID: 12345600@atlanta.example.com\r\n" +
		"CSeq: 1 BYE\r\n" +
		"Content-Length: 0\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)
	assert.False(t, msg.IsRequest())
	assert.False(t, msg.IsInvite())
	assert.True(t, msg.IsResponse())
	assert.EqualValues(t, 1, msg.CSeq.Num)
	assert.Equal(t, "BYE", msg.CSeq.Method)
	assert.EqualValues(t, 69, msg.MaxFwd)
	assert.Equal(t, 2, msg.Vias.Count())
	assert.Equal(t, "12345600@atlanta.example.com", msg.CallID)
	assert.Equal(t, 0, msg.Contacts.Count())
	assert.Equal(t, 200, msg.Code())

	// find all via headers
	vias := msg.Headers.FindAll(SIPHdrVia)
	assert.Equal(t, 2, len(vias))
}

func TestMessageParseInvalidMsg(t *testing.T) {
	msg, err := MsgParse([]byte("Not valid string\r\nWith: newline\r\n"))
	assert.NotNil(t, err)
	assert.Equal(t, ErrorSIPHeader, err)
	assert.Nil(t, msg)

	_, err = MsgParse([]byte("Invalid SIP"))
	assert.NotNil(t, err)
	assert.Equal(t, ErrorSIPMsgParse, err)

	_, err = MsgParse([]byte("Max-Forwards: 70\r\nCSeq: 1826 REGISTER\r\n\r\n"))
	assert.NotNil(t, err)
	assert.Equal(t, ErrorSIPMsgParse, err)
	assert.Contains(t, err.Error(), "Missing Request/Status line")

	// no terminating CRLF
	str := "SIP/2.0 200 OK\r\n" +
		"From: Bob <sips:bob@biloxi.example.com>;tag=7137136\r\n" +
		"To: Alice <sips:alice@atlanta.example.com>;tag=1234567\r\n" +
		"Call-ID: 123456@abcd\r\n" +
		"CSeq: 1 BYE\r\n"
	_, err = MsgParse([]byte(str))
	assert.NotNil(t, err)
	assert.Equal(t, ErrorSIPMsgParse, err)
}

func TestMessageParseInvalidHeader(t *testing.T) {
	// invalid header
	str := "SIP/2.0 200 OK\r\n" +
		"From: Bob <sips:bob@biloxi.example.com>;tag=7137136\r\n" +
		"To: Alice <sips:alice@atlanta.example.com>;tag=1234567\r\n" +
		"Call-ID:\r\n" +
		"CSeq: 1 BYE\r\n\r\n"
	_, err := MsgParse([]byte(str))
	assert.NotNil(t, err)
	assert.Equal(t, ErrorSIPHeader, err)
	assert.Contains(t, err.Error(), "Call-ID:\r\n")
}

func TestMessageParseHeadersList(t *testing.T) {
	str := "REGISTER sips:ss2.biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TLS client.biloxi.example.com:5061;branch=z9hG4bKnashds7\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: Bob <sips:bob@biloxi.example.com>;tag=a73kszlfl\r\n" +
		"To: Bob <sips:bob@biloxi.example.com>\r\n" +
		"Call-ID: 1j9FpLxk3uxtm8tn@biloxi.example.com\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sips:bob@client.biloxi.example.com>\r\n" +
		"City: Santa-Foo\r\n" +
		"Expires: 1235\r\n" +
		"Address: 555-21 St-Maria\r\n" +
		"Post-Code: 889-774\r\n" +
		"Content-Length: 0\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)
	assert.True(t, msg.IsRequest())

	h := msg.Headers.FindByName("city")
	assert.NotNil(t, h)
	assert.Equal(t, "Santa-Foo", h.Value())

	h = msg.Headers.FindByName("Address")
	assert.NotNil(t, h)
	assert.Equal(t, "555-21 St-Maria", h.Value())

	h = msg.Headers.FindByName("Post-code")
	assert.NotNil(t, h)
	assert.Equal(t, "889-774", h.Value())

	h = msg.Headers.FindByName("cseq")
	assert.NotNil(t, h)
	assert.Equal(t, "1 REGISTER", h.Value())

	h = msg.Headers.Find(SIPHdrContentLength)
	assert.NotNil(t, h)
	assert.Equal(t, "0", h.Value())

	assert.Equal(t, 12, msg.Headers.Count())
}

func TestMessageParseWithBody(t *testing.T) {
	sipmsg := "INVITE sips:bob@biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TLS client.atlanta.example.com:5061;branch=z9hG4bK74bf9\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: Alice <sips:alice@atlanta.example.com>;tag=1234567\r\n" +
		"To: Bob <sips:bob@biloxi.example.com>\r\n" +
		"Call-ID: 12345601@atlanta.example.com\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sips:alice@client.atlanta.example.com>\r\n" +
		"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY\r\n" +
		"Supported: replaces\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 165\r\n\r\n"

	sdpmsg := "v=0\r\n" +
		"o=alice 2890844526 2890844526 IN IP4 client.atlanta.example.com\r\n" +
		"s=\r\n" +
		"c=IN IP4 client.atlanta.example.com\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n"

	msg, err := MsgParse([]byte(sipmsg + sdpmsg))
	assert.Nil(t, err)
	assert.Equal(t, uint(165), msg.ContentLen)
	assert.Equal(t, sdpmsg, string(msg.Body))
	assert.Equal(t, int(msg.ContentLen), len(msg.Body))
	assert.True(t, msg.IsInvite())
}

func TestMessageRequestToBytes(t *testing.T) {
	str := "REGISTER sips:ss2.biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TLS client.biloxi.example.com:5061;branch=z9hG4bKnashds7\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: Bob <sips:bob@biloxi.example.com>;tag=a73kszlfl\r\n" +
		"To: Bob <sips:bob@biloxi.example.com>\r\n" +
		"Call-ID: 1j9FpLxk3uxtm8tn@biloxi.example.com\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sips:bob@client.biloxi.example.com>\r\n" +
		"City: Santa-Foo\r\n" +
		"Expires: 1235\r\n" +
		"Address: 555-21 St-Maria\r\n" +
		"Post-Code: 889-774\r\n" +
		"Content-Length: 0\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)

	assert.Equal(t, []byte(str), msg.Bytes())
}

func TestMessageResponseToBytes(t *testing.T) {
	str := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/TLS ss1.example.com:5061\r\n" +
		"     ;branch=z9hG4bK83754\r\n" +
		"Via: SIP/2.0/TLS client4.biloxi.example.com:5061\r\n" +
		" ;branch=z9hG4bKnashds7\r\n" +
		"\t ;received=192.0.2.105\r\n" +
		"Max-Forwards: 69\r\n" +
		"From: Bob <sips:bob@biloxi.example.com>;tag=7137136\r\n" +
		"To: Alice <sips:alice@atlanta.example.com>;tag=1234567\r\n" +
		"Call-ID: 12345600@atlanta.example.com\r\n" +
		"CSeq: 1 BYE\r\n" +
		"Content-Length: 0\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)

	assert.Equal(t, []byte(str), msg.Bytes())
}

func TestMessageCreateRequest(t *testing.T) {
	via, err := NewHdrVia("UDP", "10.100.0.1", 5060, nil)
	assert.Nil(t, err)
	branch := via.Branch()

	from := NewHdrFrom("Bob Smith", "sip:bob@voip.com", nil)

	to := NewHdrTo("", "sip:alice@voip.com", nil)

	msg, err := NewRequest("INVITE", "sip:alice@atlanta.com", via, to, from, 102, 70)
	assert.Nil(t, err)

	fromTag := from.Tag()
	str := "INVITE sip:alice@atlanta.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.100.0.1:5060;branch=" + branch + "\r\n" +
		"From: \"Bob Smith\" <sip:bob@voip.com>;tag=" + fromTag + "\r\n" +
		"To: <sip:alice@voip.com>\r\n" +
		"Call-ID: " + msg.CallID + "\r\n" +
		"CSeq: 102 INVITE\r\n" +
		"Max-Forwards: 70\r\n\r\n"

	assert.Equal(t, str, msg.String())

	msg, err = NewRequest("INVITE", "sip:alice@atlanta.com", via, to, from, -1, 70)
	assert.NotNil(t, err)

	msg, err = NewRequest("INVITE", "sip:alice@atlanta.com", via, to, from, 102, 700)
	assert.NotNil(t, err)
}

func TestMessageCreateResponse(t *testing.T) {
	str := "REGISTER sip:registrar.biloxi.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP bobspc.biloxi.com:5060;branch=z9hG4bKnashds7\r\n" +
		"Via: SIP/2.0/TLS ss1.example.com:5061\r\n" +
		"     ;branch=z9hG4bK83754\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: Bob <sip:bob@biloxi.com>\r\n" +
		"From: Bob <sip:bob@biloxi.com>;tag=456248\r\n" +
		"Call-ID: 843817637684230@998sdasdh09\r\n" +
		"CSeq: 1826 REGISTER\r\n" +
		"Contact: <sip:bob@192.0.2.4>\r\n" +
		"Expires: 7200\r\n" +
		"Content-Length: 0\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)

	resp, err := msg.NewResponse(100, "Trying")
	assert.Nil(t, err)
	respStr := "SIP/2.0 100 Trying\r\n" +
		"Via: SIP/2.0/UDP bobspc.biloxi.com:5060;branch=z9hG4bKnashds7\r\n" +
		"Via: SIP/2.0/TLS ss1.example.com:5061\r\n" +
		"     ;branch=z9hG4bK83754\r\n" +
		"To: Bob <sip:bob@biloxi.com>\r\n" +
		"From: Bob <sip:bob@biloxi.com>;tag=456248\r\n" +
		"Call-ID: 843817637684230@998sdasdh09\r\n" +
		"CSeq: 1826 REGISTER\r\n\r\n"
	assert.Equal(t, respStr, resp.String())
	assert.Empty(t, resp.To.Tag())
	assert.Equal(t, 100, resp.Code())

	resp, err = msg.NewResponse(200, "OK")
	assert.Nil(t, err)
	err = resp.AddToTag()
	assert.Nil(t, err)
	tag := resp.To.Tag()
	assert.Nil(t, err)
	assert.Equal(t, 2, resp.Vias.Count())
	assert.Equal(t, 6, resp.Headers.Count())
	assert.Equal(t, "To: Bob <sip:bob@biloxi.com>;tag="+tag+"\r\n", resp.To.String())
	assert.Equal(t, "From: Bob <sip:bob@biloxi.com>;tag=456248\r\n", resp.From.String())
	assert.Equal(t, "843817637684230@998sdasdh09", resp.CallID)
	assert.Equal(t, uint(1826), resp.CSeq.Num)
	assert.Equal(t, "REGISTER", resp.CSeq.Method)
	respStr = "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP bobspc.biloxi.com:5060;branch=z9hG4bKnashds7\r\n" +
		"Via: SIP/2.0/TLS ss1.example.com:5061\r\n" +
		"     ;branch=z9hG4bK83754\r\n" +
		"To: Bob <sip:bob@biloxi.com>;tag=" + tag + "\r\n" +
		"From: Bob <sip:bob@biloxi.com>;tag=456248\r\n" +
		"Call-ID: 843817637684230@998sdasdh09\r\n" +
		"CSeq: 1826 REGISTER\r\n\r\n"
	assert.Equal(t, respStr, resp.String())
	err = resp.AddToTag()
	assert.NotNil(t, err)

	// can not generate response on response
	resp, err = resp.NewResponse(200, "Ok")
	assert.NotNil(t, err)

	resp, err = msg.NewResponse(10, "Too small")
	assert.NotNil(t, err)

	resp, err = msg.NewResponse(710, "Too big")
	assert.NotNil(t, err)

	// can not generate response on nil
	resp, err = resp.NewResponse(200, "Ok")
	assert.NotNil(t, err)
}

func TestMessageCreateAddHeader(t *testing.T) {
	str := "CANCEL sips:bob@client.biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TLS ss1.example.com:5061;branch=z9hG4bK83749.1\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: Alice <sips:alice@atlanta.example.com>;tag=1234567\r\n" +
		"To: Bob <sips:bob@biloxi.example.com>\r\n" +
		"Call-ID: 12345600@atlanta.example.com\r\n" +
		"CSeq: 1 CANCEL\r\n" +
		"Content-Length: 0\r\n"
	msg, err := MsgParse([]byte(str + "\r\n"))
	assert.Nil(t, err)

	msg.AddHeader("Subject", "Call canceled")
	assert.Equal(t, str+"Subject: Call canceled\r\n\r\n", msg.String())
}

func TestMessageCreateRemoveHeader(t *testing.T) {
	str := "CANCEL sips:bob@client.biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TLS ss1.example.com:5061;branch=z9hG4bK83749.1\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: Alice <sips:alice@atlanta.example.com>;tag=1234567\r\n" +
		"To: Bob <sips:bob@biloxi.example.com>\r\n" +
		"Call-ID: 12345600@atlanta.example.com\r\n" +
		"Subject: Cancel call to alice\r\n" +
		"CSeq: 1 CANCEL\r\n" +
		"Content-Length: 0\r\n\r\n"
	msg, err := MsgParse([]byte(str))
	assert.Nil(t, err)

	removed := msg.RemoveHeader("subject")
	assert.True(t, removed)
	str = "CANCEL sips:bob@client.biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TLS ss1.example.com:5061;branch=z9hG4bK83749.1\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: Alice <sips:alice@atlanta.example.com>;tag=1234567\r\n" +
		"To: Bob <sips:bob@biloxi.example.com>\r\n" +
		"Call-ID: 12345600@atlanta.example.com\r\n" +
		"CSeq: 1 CANCEL\r\n" +
		"Content-Length: 0\r\n\r\n"
	assert.Equal(t, str, msg.String())

	removed = msg.RemoveHeader("subject")
	assert.False(t, removed)
}

func TestMessageContentType(t *testing.T) {
	sipmsg := "INVITE sips:bob@biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TLS client.atlanta.example.com:5061;branch=z9hG4bK74bf9\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: Alice <sips:alice@atlanta.example.com>;tag=1234567\r\n" +
		"To: Bob <sips:bob@biloxi.example.com>\r\n" +
		"Call-ID: 12345601@atlanta.example.com\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sips:alice@client.atlanta.example.com>\r\n" +
		"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY\r\n" +
		"Supported: replaces\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 165\r\n\r\n"

	sdpmsg := "v=0\r\n" +
		"o=alice 2890844526 2890844526 IN IP4 client.atlanta.example.com\r\n" +
		"s=\r\n" +
		"c=IN IP4 client.atlanta.example.com\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n"
	msg, err := MsgParse([]byte(sipmsg + sdpmsg))
	assert.Nil(t, err)

	assert.True(t, msg.HasSDP())
}

func TestMessageTxnACK(t *testing.T) {
	reqstr := "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP client.atlanta.example.com:5060;branch=z9hG4bKbf9f44\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: Alice <sip:alice@atlanta.example.com>;tag=9fxced76sl\r\n" +
		"To: Bob <sip:bob@biloxi.example.com>\r\n" +
		"Call-ID: 2xTb9vxSit55XU7p8@atlanta.example.com\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:alice@client.atlanta.example.com>\r\n" +
		"Content-Length: 0\r\n\r\n"

	respstr := "SIP/2.0 302 Moved Temporarily\r\n" +
		"Via: SIP/2.0/UDP client.atlanta.example.com:5060;" +
		"branch=z9hG4bKbf9f44;received=192.0.2.101\r\n" +
		"From: Alice <sip:alice@atlanta.example.com>;tag=9fxced76sl\r\n" +
		"To: Bob <sip:bob@biloxi.example.com>;tag=53fHlqlQ2\r\n" +
		"Call-ID: 2xTb9vxSit55XU7p8@atlanta.example.com\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Contact: <sip:bob@chicago.example.com;transport=tcp>\r\n" +
		"Content-Length: 0\r\n\r\n"

	ackstr := "ACK sip:bob@biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP client.atlanta.example.com:5060;branch=z9hG4bKbf9f44\r\n" +
		"Max-Forwards: 70\r\n" +
		"Call-ID: 2xTb9vxSit55XU7p8@atlanta.example.com\r\n" +
		"From: Alice <sip:alice@atlanta.example.com>;tag=9fxced76sl\r\n" +
		"To: Bob <sip:bob@biloxi.example.com>;tag=53fHlqlQ2\r\n" +
		"CSeq: 1 ACK\r\n\r\n"

	req, err := MsgParse([]byte(reqstr))
	assert.Nil(t, err)

	resp, err := MsgParse([]byte(respstr))
	assert.Nil(t, err)

	ack, err := req.NewACK(resp)
	assert.Nil(t, err)

	assert.Equal(t, ackstr, ack.String())
}

func BenchmarkMessageParse(b *testing.B) {
	str := "REGISTER sip:registrar.biloxi.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP bobspc.biloxi.com:5060;branch=z9hG4bKnashds7\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: Bob <sip:bob@biloxi.com>\r\n" +
		"From: Bob <sip:bob@biloxi.com>;tag=456248\r\n" +
		"Call-ID: 843817637684230@998sdasdh09\r\n" +
		"CSeq: 1826 REGISTER\r\n" +
		"Contact: <sip:bob@192.0.2.4>\r\n" +
		"Expires: 7200\r\n" +
		"Content-Length: 0\r\n\r\n"
	for i := 0; i < b.N; i++ {
		MsgParse([]byte(str))
	}
}
