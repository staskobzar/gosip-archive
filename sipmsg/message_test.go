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
	assert.False(t, msg.IsResponse())
	assert.Equal(t, "sip:registrar.biloxi.com", msg.ReqLine.RequestURI())
	assert.EqualValues(t, 7200, msg.Expires)
	assert.Equal(t, 1, msg.Vias.Count())
	assert.EqualValues(t, 1826, msg.CSeq)
	assert.Equal(t, "843817637684230@998sdasdh09", msg.CallID)
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
	assert.True(t, msg.IsResponse())
	assert.EqualValues(t, 1, msg.CSeq)
	assert.EqualValues(t, 69, msg.MaxFwd)
	assert.Equal(t, 2, msg.Vias.Count())
	assert.Equal(t, "12345600@atlanta.example.com", msg.CallID)
	assert.Nil(t, msg.Contacts)
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
