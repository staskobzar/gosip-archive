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
	assert.Equal(t, []byte("SIP/2.0 180 Ringing\r\n"), msg.StatusLine.Bytes())
}

func TestHdrRequestLineParse(t *testing.T) {
	msg := &Message{}
	h, err := parseHeader(msg, []byte("INVITE sip:bob@biloxi.com SIP/2.0\r\n"))
	assert.Nil(t, err)
	assert.Equal(t, SIPHdrRequestLine, h)
	assert.Equal(t, "INVITE", msg.ReqLine.Method())
	assert.Equal(t, "sip:bob@biloxi.com", msg.ReqLine.RequestURI())
	assert.Equal(t, "SIP/2.0", msg.ReqLine.Version())
	assert.Equal(t, []byte("INVITE sip:bob@biloxi.com SIP/2.0\r\n"), msg.ReqLine.Bytes())
	assert.True(t, msg.ReqLine.IsInvite())
}

func TestHdrRequestLineCreate(t *testing.T) {
	r := NewReqLine("INVITE", "sip:515@10.0.0.1")

	assert.Equal(t, []byte("INVITE sip:515@10.0.0.1 SIP/2.0\r\n"), r.Bytes())
}

func TestHdrStatusLineCreate(t *testing.T) {
	s := NewStatusLine("200", "Ok")

	assert.Equal(t, []byte("SIP/2.0 200 Ok\r\n"), s.Bytes())
}
