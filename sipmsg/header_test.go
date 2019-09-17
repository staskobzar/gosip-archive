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
	sl := msg.StatusLine()
	assert.Equal(t, "SIP/2.0", sl.Version())
	assert.Equal(t, "180", sl.Code())
	assert.Equal(t, "Ringing", sl.Reason())
}

func TestHdrRequestLineParse(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("INVITE sip:bob@biloxi.com SIP/2.0\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrRequestLine, h)
	rl := msg.RequestLine()
	assert.Equal(t, "INVITE", rl.Method())
	assert.Equal(t, "sip:bob@biloxi.com", rl.RequestURI())
	assert.Equal(t, "SIP/2.0", rl.Version())
}

func TestHdrParseCSeq(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("CSeq: 4711 INVITE\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrCSeq, h)
	assert.EqualValues(t, 4711, msg.CSeq())
}

func TestHdrParseCallID(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Call-ID: 12345601@atlanta.example.com\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrCallID, h)
	assert.Equal(t, "12345601@atlanta.example.com", msg.CallID())

	h, err = parseHeader(msg, []byte("i :167b9a61dabe815567f422a4944b61c0\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrCallID, h)
	assert.Equal(t, "167b9a61dabe815567f422a4944b61c0", msg.CallID())
}

func TestHdrParseContentLength(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Content-Length:   543\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContentLength, h)
	assert.EqualValues(t, 543, msg.ContentLen())

	h, err = parseHeader(msg, []byte("L   :   1024\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContentLength, h)
	assert.EqualValues(t, 1024, msg.ContentLen())
}

func TestHdrParseFrom(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("From: sip:+12125551212@phone2net.com;tag=887s\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrFrom, h)
	f := msg.From()
	assert.Equal(t, "", f.DisplayName())
	assert.Equal(t, "sip:+12125551212@phone2net.com", f.Addr())
	assert.Equal(t, "887s", f.Tag())

	h, err = parseHeader(msg, []byte("f : Alice <sips:alice@atlanta.example.com;lr>;tag=837348234\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrFrom, h)
	f = msg.From()
	assert.Equal(t, "Alice", f.DisplayName())
	assert.Equal(t, "sips:alice@atlanta.example.com;lr", f.Addr())
	assert.Equal(t, "837348234", f.Tag())

	h, err = parseHeader(msg, []byte("From: \"Alice Jones\" <sips:51472@atlanta.com>;tag=8234afd;rl;user=phone\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrFrom, h)
	f = msg.From()
	assert.Equal(t, "\"Alice Jones\"", f.DisplayName())
	assert.Equal(t, "sips:51472@atlanta.com", f.Addr())
	assert.Equal(t, "8234afd", f.Tag())
	p, ok := f.Param("rl")
	assert.True(t, ok)
	assert.Equal(t, "", p)
	p, ok = f.Param("user")
	assert.True(t, ok)
	assert.Equal(t, "phone", p)
	_, ok = f.Param("foo")
	assert.False(t, ok)

	h, err = parseHeader(msg, []byte("F: <sips:alice@example.com>;foo=bar;tag=9871ab;rl;user=phone\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrFrom, h)
	f = msg.From()
	assert.Equal(t, "", f.DisplayName())
	assert.Equal(t, "sips:alice@example.com", f.Addr())
	assert.Equal(t, "9871ab", f.Tag())
	p, ok = f.Param("rl")
	assert.True(t, ok)
	assert.Equal(t, "", p)
	p, ok = f.Param("user")
	assert.True(t, ok)
	assert.Equal(t, "phone", p)
	p, ok = f.Param("foo")
	assert.True(t, ok)
	assert.Equal(t, "bar", p)
}

func TestHdrParseTo(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("To: Carol <sip:212@chicago.com>\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrTo, h)
	to := msg.To()
	assert.Equal(t, "Carol", to.DisplayName())
	assert.Equal(t, "sip:212@chicago.com", to.Addr())
	assert.Equal(t, "", to.Tag())

	h, err = parseHeader(msg, []byte("t :   <sip:55543@voip.com>;tag=85471af;cic=+1-800;part;l=5a\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrTo, h)
	to = msg.To()
	assert.Equal(t, "", to.DisplayName())
	assert.Equal(t, "sip:55543@voip.com", to.Addr())
	assert.Equal(t, "85471af", to.Tag())
	p, ok := to.Param("cic")
	assert.True(t, ok)
	assert.Equal(t, "+1-800", p)
	p, ok = to.Param("part")
	assert.True(t, ok)
	assert.Equal(t, "", p)
	p, ok = to.Param("l")
	assert.True(t, ok)
	assert.Equal(t, "5a", p)
}

func TestHdrParseContact(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Contact: sip:2234@10.0.114.12:12543\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContact, h)
	cnt := msg.Contacts()
	assert.False(t, cnt.IsStar())
	assert.Equal(t, 1, cnt.Count())
	c := cnt.First()
	assert.Equal(t, "sip:2234@10.0.114.12:12543", c.Location())

	msg = &Message{}
	h, err = parseHeader(msg, []byte("m  :\"Mr. Watson\" <sip:watson@bell-telephone.com>;q=0.7; expires=3600\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContact, h)
	c = msg.Contacts().First()
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
	assert.True(t, msg.Contacts().IsStar())
}

func TestHdrParseMultiContacts(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("Contact: Alice <sip:2234@10.0.114.12:12543>;user=phone, sips:bob@voip.com;lr;cic=514284, \"123, rue Jones\" <sip:jones@sip.ca>\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrContact, h)
	cnt := msg.Contacts()
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
