package sipmsg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHdrStatusLineParse(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("SIP/2.0 180 Ringing\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrStatusLine, h)
	assert.Equal(t, "SIP/2.0", msg.StatusLine.Version())
	assert.Equal(t, "180", msg.StatusLine.Code())
	assert.Equal(t, "Ringing", msg.StatusLine.Reason())
}

func TestHdrRequestLineParse(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("INVITE sip:bob@biloxi.com SIP/2.0\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrRequestLine, h)
	assert.Equal(t, "INVITE", msg.ReqLine.Method())
	assert.Equal(t, "sip:bob@biloxi.com", msg.ReqLine.RequestURI())
	assert.Equal(t, "SIP/2.0", msg.ReqLine.Version())
}

func TestHdrParseCSeq(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("CSeq: 4711 INVITE\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrCSeq, h)
	assert.EqualValues(t, 4711, msg.CSeq.Num)
	assert.EqualValues(t, "INVITE", msg.CSeq.Method)
}

func TestHdrParseCallID(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Call-ID: 12345601@atlanta.example.com\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrCallID, h)
	assert.Equal(t, "12345601@atlanta.example.com", msg.CallID)

	h, err = parseHeader(msg, []byte("i :167b9a61dabe815567f422a4944b61c0\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrCallID, h)
	assert.Equal(t, "167b9a61dabe815567f422a4944b61c0", msg.CallID)
}

func TestHdrParseContentLength(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Content-Length:   543\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContentLength, h)
	assert.EqualValues(t, 543, msg.ContentLen)

	h, err = parseHeader(msg, []byte("L   :   1024\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContentLength, h)
	assert.EqualValues(t, 1024, msg.ContentLen)
}

func TestHdrParseFrom(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("From: sip:+12125551212@phone2net.com;tag=887s\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrFrom, h)
	assert.Equal(t, "", msg.From.DisplayName())
	assert.Equal(t, "sip:+12125551212@phone2net.com", msg.From.Addr())
	assert.Equal(t, "887s", msg.From.Tag())

	h, err = parseHeader(msg, []byte("f : Alice <sips:alice@atlanta.example.com;lr>;tag=837348234\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrFrom, h)
	assert.Equal(t, "Alice", msg.From.DisplayName())
	assert.Equal(t, "sips:alice@atlanta.example.com;lr", msg.From.Addr())
	assert.Equal(t, "837348234", msg.From.Tag())

	h, err = parseHeader(msg, []byte("From: \"Alice Jones\" <sips:51472@atlanta.com>;tag=8234afd;rl;user=phone\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrFrom, h)
	assert.Equal(t, "\"Alice Jones\"", msg.From.DisplayName())
	assert.Equal(t, "sips:51472@atlanta.com", msg.From.Addr())
	assert.Equal(t, "8234afd", msg.From.Tag())
	p, ok := msg.From.Param("rl")
	assert.True(t, ok)
	assert.Equal(t, "", p)
	p, ok = msg.From.Param("user")
	assert.True(t, ok)
	assert.Equal(t, "phone", p)
	_, ok = msg.From.Param("foo")
	assert.False(t, ok)

	h, err = parseHeader(msg, []byte("F: <sips:alice@example.com>;foo=bar;tag=9871ab;rl;user=phone\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrFrom, h)
	assert.Equal(t, "", msg.From.DisplayName())
	assert.Equal(t, "sips:alice@example.com", msg.From.Addr())
	assert.Equal(t, "9871ab", msg.From.Tag())
	p, ok = msg.From.Param("rl")
	assert.True(t, ok)
	assert.Equal(t, "", p)
	p, ok = msg.From.Param("user")
	assert.True(t, ok)
	assert.Equal(t, "phone", p)
	p, ok = msg.From.Param("foo")
	assert.True(t, ok)
	assert.Equal(t, "bar", p)
}

func TestHdrParseTo(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("To: Carol 212 <sip:212@chicago.com>\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrTo, h)
	assert.Equal(t, "Carol 212", msg.To.DisplayName())
	assert.Equal(t, "sip:212@chicago.com", msg.To.Addr())
	assert.Equal(t, "", msg.To.Tag())

	h, err = parseHeader(msg, []byte("t :   <sip:55543@voip.com>;tag=85471af;cic=+1-800;part;l=5a\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrTo, h)
	assert.Equal(t, "", msg.To.DisplayName())
	assert.Equal(t, "sip:55543@voip.com", msg.To.Addr())
	assert.Equal(t, "85471af", msg.To.Tag())
	p, ok := msg.To.Param("cic")
	assert.True(t, ok)
	assert.Equal(t, "+1-800", p)
	p, ok = msg.To.Param("part")
	assert.True(t, ok)
	assert.Equal(t, "", p)
	p, ok = msg.To.Param("l")
	assert.True(t, ok)
	assert.Equal(t, "5a", p)
}

func TestHdrParseContact(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Contact: sip:2234@10.0.114.12:12543\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContact, h)
	cnt := msg.Contacts
	assert.False(t, cnt.IsStar())
	assert.Equal(t, 1, cnt.Count())
	c := cnt.First()
	assert.Equal(t, "sip:2234@10.0.114.12:12543", c.Location())

	msg = &Message{}
	h, err = parseHeader(msg, []byte("m  :\"Mr. Watson\" <sip:watson@bell-telephone.com>;q=0.7; expires=3600\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContact, h)
	c = msg.Contacts.First()
	assert.Equal(t, "\"Mr. Watson\"", c.DisplayName())
	assert.Equal(t, "sip:watson@bell-telephone.com", c.Location())
	p, ok := c.Param("q")
	assert.True(t, ok)
	assert.Equal(t, "0.7", p)
	p, ok = c.Param("expires")
	assert.True(t, ok)
	assert.Equal(t, "3600", p)

	// Star contact
	msg = &Message{}
	h, err = parseHeader(msg, []byte("Contact: * \r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContact, h)
	assert.True(t, msg.Contacts.IsStar())
}

func TestHdrParseMultiContacts(t *testing.T) {
	msg := &Message{}
	str := "Contact: Alice <sip:2234@10.0.114.12:12543>;\r\n" +
		" user=phone, sips:bob@voip.com;  lr ; cic=514284," +
		" \"123, rue Jones\" <sip:jones@sip.ca> ; par =\r\n  foo\r\n"
	h, err := parseHeader(msg, []byte(str))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContact, h)
	cnt := msg.Contacts
	assert.Equal(t, 3, cnt.Count())

	// iterate contacts
	c := cnt.First()
	assert.NotNil(t, c)
	assert.Equal(t, "Alice", c.DisplayName())
	assert.Equal(t, "sip:2234@10.0.114.12:12543", c.Location())
	p, ok := c.Param("user")
	assert.True(t, ok)
	assert.Equal(t, "phone", p)

	c = cnt.Next()
	assert.NotNil(t, c)
	assert.Equal(t, "", c.DisplayName())
	assert.Equal(t, "sips:bob@voip.com", c.Location())
	p, ok = c.Param("lr")
	assert.True(t, ok)
	assert.Equal(t, "", p)
	p, ok = c.Param("cic")
	assert.True(t, ok)
	assert.Equal(t, "514284", p)

	c = cnt.Next()
	assert.NotNil(t, c)
	assert.Equal(t, "\"123, rue Jones\"", c.DisplayName())
	assert.Equal(t, "sip:jones@sip.ca", c.Location())

	c = cnt.Next()
	assert.Nil(t, c)
}

func TestHdrParseMultiHeaderContacts(t *testing.T) {
	m := &Message{}
	hs := "Contact: \"Mr. Watson\" <sip:watson@worcester.bell-telephone.com>\r\n" +
		" ;q=0.7; expires=3600,\r\n" +
		" \"Mr. Watson\" <mailto:watson@bell-telephone.com> ;q=0.1\r\n"
	h, err := parseHeader(m, []byte(hs))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContact, h)
	assert.Equal(t, 2, m.Contacts.Count())
}

func TestHdrParseVia(t *testing.T) {
	msg := &Message{}
	str := "Via: SIP/2.0/TLS ss1.example.com:5061;branch=z9hG4bK83749.1" +
		";received=192.0.2.54;ttl=60;maddr=224.2.0.1;lr\r\n"
	h, err := parseHeader(msg, []byte(str))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrVia, h)
	via := msg.Vias
	assert.Equal(t, 1, via.Count())
	assert.Equal(t, "TLS", via[0].Transport())
	assert.Equal(t, "ss1.example.com", via[0].Host())
	assert.Equal(t, "5061", via[0].Port())
	assert.Equal(t, "z9hG4bK83749.1", via[0].Branch())
	assert.Equal(t, "192.0.2.54", via[0].Received())
	assert.Equal(t, "60", via[0].TTL())
	assert.Equal(t, "224.2.0.1", via[0].MAddr())

	str = "V : SIP / 2.0 / UDP first.example.com: 4000;ttl=16\r\n" +
		" ;maddr=224.2.0.1 ;branch=z9hG4bKa7c6a8dlze.1\r\n"
	msg = &Message{}
	h, err = parseHeader(msg, []byte(str))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrVia, h)
	via = msg.Vias
	assert.Equal(t, "UDP", via[0].Transport())
	assert.Equal(t, "first.example.com", via[0].Host())
	assert.Equal(t, "4000", via[0].Port())
	assert.Equal(t, "z9hG4bKa7c6a8dlze.1", via[0].Branch())
	assert.Equal(t, "16", via[0].TTL())
	assert.Equal(t, "224.2.0.1", via[0].MAddr())
}

func TestHdrParseViaComma(t *testing.T) {
	msg := &Message{}
	str := "Via: SIP/ 2.0 / UDP erlang.bell-telephone.com : 5060\r\n" +
		" ;branch=z9hG4bK87asdks7, SIP/2.0/TCP foo.com " +
		":8080;branch=z9hG4bK87as111;maddr=10.0.0.1\r\n"
	h, err := parseHeader(msg, []byte(str))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrVia, h)

	via := msg.Vias
	assert.Equal(t, 2, via.Count())

	assert.Equal(t, "UDP", via[0].Transport())
	assert.Equal(t, "erlang.bell-telephone.com", via[0].Host())
	assert.Equal(t, "5060", via[0].Port())
	assert.Equal(t, "z9hG4bK87asdks7", via[0].Branch())
	assert.Equal(t, "", via[0].MAddr())
	assert.Equal(t, "", via[0].Received())

	assert.Equal(t, "TCP", via[1].Transport())
	assert.Equal(t, "foo.com", via[1].Host())
	assert.Equal(t, "8080", via[1].Port())
	assert.Equal(t, "z9hG4bK87as111", via[1].Branch())
	assert.Equal(t, "10.0.0.1", via[1].MAddr())
	assert.Equal(t, "", via[1].Received())
}

func TestHdrParseViaMultiHeaders(t *testing.T) {
	msg := &Message{}
	str := "Via: SIP/2.0/UDP bell.com : 5060;branch=z9hG4bK87asdks7.2\r\n"
	h, err := parseHeader(msg, []byte(str))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrVia, h)
	str = "v: SIP/2.0/TCP ssl.bell.com;branch=z9hG4bKa7c6a8dlze.1\r\n"
	h, err = parseHeader(msg, []byte(str))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrVia, h)

	via := msg.Vias
	assert.Equal(t, 2, via.Count())
	assert.Equal(t, "bell.com", via[0].Host())
	assert.Equal(t, "z9hG4bK87asdks7.2", via[0].Branch())
	assert.Equal(t, "ssl.bell.com", via[1].Host())
	assert.Equal(t, "z9hG4bKa7c6a8dlze.1", via[1].Branch())
}

func TestHdrParseRoute(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Route: <sips:ss1.example.com>\r\n"))
	assert.Equal(t, SIPHdrRoute, h)
	assert.Nil(t, err)

	r := msg.Routes
	assert.Equal(t, 1, r.Count())
	rh := r[0]
	assert.Equal(t, "sips:ss1.example.com", rh.Addr())

	msg = &Message{}
	h, err = parseHeader(msg, []byte("Route: Deli <sip:p1.voip.com;lr>;nat=yes;wr\r\n"))
	assert.Equal(t, SIPHdrRoute, h)
	assert.Nil(t, err)

	r = msg.Routes
	assert.Equal(t, 1, r.Count())
	rh = r[0]
	assert.Equal(t, "sip:p1.voip.com;lr", rh.Addr())
	p, ok := rh.Param("nat")
	assert.True(t, ok)
	assert.Equal(t, "yes", p)
	p, ok = rh.Param("wr")
	assert.True(t, ok)
	assert.Equal(t, "", p)

	uri := rh.AddrURI()
	assert.NotNil(t, uri)
	p, ok = uri.Param("lr")
	assert.True(t, ok)
	assert.Equal(t, "", p)
}

func TestHdrParseRouteComma(t *testing.T) {
	msg := &Message{}
	str := "Route: <sips:bigbox3.site3.atlanta.com;lr>;ssl=true," +
		" <sip:server10.biloxi.com;lr>\r\n"
	h, err := parseHeader(msg, []byte(str))
	assert.Equal(t, SIPHdrRoute, h)
	assert.Nil(t, err)

	r := msg.Routes
	assert.Equal(t, 2, r.Count())
	rh := r[0]
	assert.Equal(t, "sips:bigbox3.site3.atlanta.com;lr", rh.Addr())
	p, ok := rh.Param("ssl")
	assert.True(t, ok)
	assert.Equal(t, "true", p)
	rh = r[1]
	assert.Equal(t, "sip:server10.biloxi.com;lr", rh.Addr())

	msg = &Message{}
	str = "Route: <sip:site3.atlanta.com;lr>,\r\n" +
		" <sip:biloxi.com;lr>,\r\n <sips:ssl.voip.fr>\r\n"
	h, err = parseHeader(msg, []byte(str))
	assert.Equal(t, SIPHdrRoute, h)
	assert.Nil(t, err)

	r = msg.Routes
	assert.Equal(t, 3, r.Count())
	assert.Equal(t, "sip:site3.atlanta.com;lr", r[0].Addr())
	assert.Equal(t, "sip:biloxi.com;lr", r[1].Addr())
	assert.Equal(t, "sips:ssl.voip.fr", r[2].Addr())
}

func TestHdrParseRouteMulti(t *testing.T) {
	msg := &Message{}
	str := "Route: <sips:s3.atlanta.com;lr>," +
		" <sip:server10.biloxi.com;lr>\r\n"
	h, err := parseHeader(msg, []byte(str))
	assert.Equal(t, SIPHdrRoute, h)
	assert.Nil(t, err)

	str = "Route: <sip:199.100.21.33:8809;lr>\r\n"
	h, err = parseHeader(msg, []byte(str))
	assert.Equal(t, SIPHdrRoute, h)
	assert.Nil(t, err)

	str = "Route: <sip:10.225.1.2>,\r\n <sip:10.225.1.1;lr>\r\n"
	h, err = parseHeader(msg, []byte(str))
	assert.Equal(t, SIPHdrRoute, h)
	assert.Nil(t, err)

	r := msg.Routes
	assert.Equal(t, 5, r.Count())
}

func TestHdrParseRecordRoute(t *testing.T) {
	msg := &Message{}
	str := "Record-Route: <sip:server10.biloxi.com;lr>,\r\n" +
		"   <sip:bigbox3.site3.atlanta.com;lr>\r\n"
	h, err := parseHeader(msg, []byte(str))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrRecordRoute, h)
	r := msg.RecRoutes
	assert.Equal(t, 2, r.Count())
}

func TestHdrMaxForwards(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Max-Forwards: 70\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrMaxForwards, h)
	assert.EqualValues(t, 70, msg.MaxFwd)
}

func TestHdrExpires(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Expires: 1800\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrExpires, h)
	assert.EqualValues(t, 1800, msg.Expires)
}

func TestHdrGenericHeaders(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Foo: 70 BAR\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrGeneric, h)
}

func TestHdrAccept(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("accept:  application/sdp;level=1, application/x-private\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrAccept, hid)
	assert.Equal(t, "application/sdp;level=1, application/x-private",
		msg.Headers.Find(SIPHdrAccept).Value())
}

func TestHdrAcceptEncoding(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Accept-Encoding: gzip\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrAcceptEncoding, hid)
	assert.Equal(t, "gzip", msg.Headers.Find(SIPHdrAcceptEncoding).Value())
}

func TestHdrAcceptLanguage(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Accept-Language: da, en-gb;q=0.8, en;q=0.7\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrAcceptLanguage, hid)
	assert.Equal(t, "da, en-gb;q=0.8, en;q=0.7", msg.Headers.Find(SIPHdrAcceptLanguage).Value())
}

func TestHdrAlertInfo(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg,
		[]byte("Alert-Info: <http://www.example.com/sounds/moo.wav>\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrAlertInfo, hid)
	assert.Equal(t, "<http://www.example.com/sounds/moo.wav>",
		msg.Headers.Find(SIPHdrAlertInfo).Value())
}

func TestHdrAllow(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("allow : INVITE, ACK, OPTIONS, CANCEL, BYE\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrAllow, hid)
	assert.Equal(t, "INVITE, ACK, OPTIONS, CANCEL, BYE", msg.Headers.Find(SIPHdrAllow).Value())
}

func TestHdrAuthInfo(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg,
		[]byte("Authentication-Info: nextnonce=\"47364c23432d2e131a5fb210812c\"\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrAuthenticationInfo, hid)
	assert.Equal(t, "nextnonce=\"47364c23432d2e131a5fb210812c\"",
		msg.Headers.Find(SIPHdrAuthenticationInfo).Value())
}

func TestHdrAuthorization(t *testing.T) {
	msg := &Message{}
	str := "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\",\r\n" +
		" nonce=\"84a4cc6f3082121f32b42a2187831a9e\",\r\n" +
		" response=\"7587245234b3434cc3412213e5f113a5432\"\r\n"
	hid, err := parseHeader(msg, []byte(str))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrAuthorization, hid)
	assert.Equal(t, "Digest username=\"Alice\", realm=\"atlanta.com\",\r\n"+
		" nonce=\"84a4cc6f3082121f32b42a2187831a9e\",\r\n"+
		" response=\"7587245234b3434cc3412213e5f113a5432\"",
		msg.Headers.Find(SIPHdrAuthorization).Value())
}

func TestHdrCallInfo(t *testing.T) {
	msg := &Message{}
	str := "Call-Info: <http://wwww.example.com/alice/photo.jpg> ;purpose=icon,\r\n" +
		" <http://www.example.com/alice/> ;purpose=info\r\n"
	hid, err := parseHeader(msg, []byte(str))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrCallInfo, hid)
	assert.Equal(t, "<http://wwww.example.com/alice/photo.jpg> ;purpose=icon,\r\n"+
		" <http://www.example.com/alice/> ;purpose=info",
		msg.Headers.Find(SIPHdrCallInfo).Value())
}

func TestHdrContentDispo(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Content-Disposition: session\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContentDisposition, hid)
	assert.Equal(t, "session", msg.Headers.Find(SIPHdrContentDisposition).Value())
}

func TestHdrContentEncoding(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("e  : tar\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContentEncoding, hid)
	assert.Equal(t, "tar", msg.Headers.Find(SIPHdrContentEncoding).Value())
}

func TestHdrContentLanguage(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Content-Language: fr\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContentLanguage, hid)
	assert.Equal(t, "fr", msg.Headers.Find(SIPHdrContentLanguage).Value())
}

func TestHdrContentType(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("C : text/html; charset=ISO-8859-4\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContentType, hid)
	assert.Equal(t, "text/html; charset=ISO-8859-4",
		msg.Headers.Find(SIPHdrContentType).Value())
}

func TestHdrDate(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Date: Sat, 13 Nov 2010 23:29:00 GMT\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrDate, hid)
	assert.Equal(t, "Sat, 13 Nov 2010 23:29:00 GMT", msg.Headers.Find(SIPHdrDate).Value())
}

func TestHdrErrorInfo(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Error-Info: <sip:not-in-service-recording@atlanta.com>\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrErrorInfo, hid)
	assert.Equal(t, "<sip:not-in-service-recording@atlanta.com>",
		msg.Headers.Find(SIPHdrErrorInfo).Value())
}

func TestHdrInReplyTo(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("In-Reply-To: 70710@saturn.bell-tel.com, 17320@saturn.bell-tel.com\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrInReplyTo, hid)
	assert.Equal(t, "70710@saturn.bell-tel.com, 17320@saturn.bell-tel.com", msg.Headers.Find(SIPHdrInReplyTo).Value())
}

func TestHdrMIMEVersion(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("MIME-Version: 1.0\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrMIMEVersion, hid)
	assert.Equal(t, "1.0", msg.Headers.Find(SIPHdrMIMEVersion).Value())
}

func TestHdrMinExpires(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Min-Expires: 60\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrMinExpires, hid)
	assert.Equal(t, "60", msg.Headers.Find(SIPHdrMinExpires).Value())
}

func TestHdrOrganization(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Organization: Boxes by Bob\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrOrganization, hid)
	assert.Equal(t, "Boxes by Bob", msg.Headers.Find(SIPHdrOrganization).Value())
}

func TestHdrPriority(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Priority: non-urgent\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrPriority, hid)
	assert.Equal(t, "non-urgent", msg.Headers.Find(SIPHdrPriority).Value())
}

func TestHdrProxyAuthenticate(t *testing.T) {
	msg := &Message{}
	str := "Digest realm=\"atlanta.com\",\r\n" +
		" domain=\"sip:ss1.carrier.com\", qop=\"auth\",\r\n" +
		" nonce=\"f84f1cec41e6cbe5aea9c8e88d359\",\r\n" +
		" opaque=\"\", stale=FALSE, algorithm=MD5"
	hid, err := parseHeader(msg, []byte("Proxy-Authenticate: "+str+"\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrProxyAuthenticate, hid)
	assert.Equal(t, str, msg.Headers.Find(SIPHdrProxyAuthenticate).Value())
}

func TestHdrProxyAuthorization(t *testing.T) {
	msg := &Message{}
	str := "Digest username=\"Alice\", realm=\"atlanta.com\",\r\n" +
		"   nonce=\"c60f3082ee1212b402a21831ae\",\r\n" +
		"   response=\"245f23415f11432b3434341c022\""
	hid, err := parseHeader(msg, []byte("Proxy-Authorization:"+str+"\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrProxyAuthorization, hid)
	assert.Equal(t, str, msg.Headers.Find(SIPHdrProxyAuthorization).Value())
}

func TestHdrProxyRequired(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Proxy-Require: foo\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrProxyRequire, hid)
	assert.Equal(t, "foo", msg.Headers.Find(SIPHdrProxyRequire).Value())
}

func TestHdrReplyTo(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Reply-To: Bob <sip:bob@biloxi.com>\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrReplyTo, hid)
	assert.Equal(t, "Bob <sip:bob@biloxi.com>", msg.Headers.Find(SIPHdrReplyTo).Value())
}

func TestHdrRequire(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Require: 100rel\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrRequire, hid)
	assert.Equal(t, "100rel", msg.Headers.Find(SIPHdrRequire).Value())
}

func TestHdrRetryAfter(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Retry-After: 18000;duration=3600\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrRetryAfter, hid)
	assert.Equal(t, "18000;duration=3600", msg.Headers.Find(SIPHdrRetryAfter).Value())
}

func TestHdrServer(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Server: HomeServer v2\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrServer, hid)
	assert.Equal(t, "HomeServer v2", msg.Headers.Find(SIPHdrServer).Value())
}

func TestHdrSubject(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("S : Tech Support\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrSubject, hid)
	assert.Equal(t, "Tech Support", msg.Headers.Find(SIPHdrSubject).Value())
}

func TestHdrSupported(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Supported: 100rel\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrSupported, hid)
	assert.Equal(t, "100rel", msg.Headers.Find(SIPHdrSupported).Value())
}

func TestHdrTimestamp(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Timestamp: 54\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrTimestamp, hid)
	assert.Equal(t, "54", msg.Headers.Find(SIPHdrTimestamp).Value())
}

func TestHdrUnsupported(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("Unsupported: foo\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrUnsupported, hid)
	assert.Equal(t, "foo", msg.Headers.Find(SIPHdrUnsupported).Value())
}

func TestHdrUserAgent(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("User-Agent: Softphone Beta1.5\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrUserAgent, hid)
	assert.Equal(t, "Softphone Beta1.5", msg.Headers.Find(SIPHdrUserAgent).Value())
}

func TestHdrWarning(t *testing.T) {
	msg := &Message{}
	hid, err := parseHeader(msg,
		[]byte("Warning: 301 isi.edu \"Incompatible network address type 'E.164'\"\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrWarning, hid)
	assert.Equal(t, "301 isi.edu \"Incompatible network address type 'E.164'\"",
		msg.Headers.Find(SIPHdrWarning).Value())
}

func TestHdrWWWAuth(t *testing.T) {
	str := "Digest realm=\"atlanta.com\",\r\n" +
		" domain=\"sip:boxesbybob.com\", qop=\"auth\",\r\n" +
		" nonce=\"f84f1cec41e6cbe5aea9c8e88d359\",\r\n" +
		" opaque=\"\", stale=FALSE, algorithm=MD5"
	msg := &Message{}
	hid, err := parseHeader(msg, []byte("WWW-Authenticate: "+str+"\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrWWWAuthenticate, hid)
	assert.Equal(t, str, msg.Headers.Find(SIPHdrWWWAuthenticate).Value())
}
