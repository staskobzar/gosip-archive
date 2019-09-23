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
	assert.EqualValues(t, 4711, msg.CSeq)
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
	h, err := parseHeader(msg, []byte("To: Carol <sip:212@chicago.com>\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrTo, h)
	assert.Equal(t, "Carol", msg.To.DisplayName())
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
	h, err := parseHeader(msg, []byte("Contact: Alice <sip:2234@10.0.114.12:12543>;user=phone, sips:bob@voip.com;lr;cic=514284, \"123, rue Jones\" <sip:jones@sip.ca>\r\n"))
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

	/* TODO: header with CRLF
	m := &Message{}
	hs := "Contact: \"Mr. Watson\" <sip:watson@worcester.bell-telephone.com>\r\n" +
		" ;q=0.7; expires=3600,\r\n" +
		" \"Mr. Watson\" <mailto:watson@bell-telephone.com> ;q=0.1\r\n"
	h, err = parseHeader(m, []byte(hs))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContact, h)
	cnt = m.Contacts()
	assert.Equal(t, 2, cnt.Count())
	fmt.Printf("%s\n", cnt.cnt[3].buf)
	*/
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

func TestHdrOtherHeaders(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Foo: 70 BAR\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrOther, h)
}
