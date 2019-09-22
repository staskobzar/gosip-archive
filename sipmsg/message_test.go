package sipmsg

import (
	"fmt"
	"testing"
)

func TestMessageParse(t *testing.T) {
	// REGISTER sip:registrar.biloxi.com SIP/2.0\r\n" +
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
	msg := MsgParse([]byte(str))
	fmt.Println(msg.From())
}
