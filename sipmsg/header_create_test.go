package sipmsg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHdrCreateVia(t *testing.T) {
	h, err := NewHdrVia("UDP", "voip.com", 0, nil)
	assert.Nil(t, err)
	assert.Equal(t, "UDP", h.Transport())
	assert.Equal(t, "voip.com", h.Host())
	assert.Equal(t, "Via: SIP/2.0/UDP voip.com;branch="+h.Branch()+"\r\n",
		string(h.buf))

	h, err = NewHdrVia("TCP", "sip.info", 8060, nil)
	assert.Nil(t, err)
	assert.Equal(t, "TCP", h.Transport())
	assert.Equal(t, "sip.info", h.Host())
	assert.Equal(t, "8060", h.Port())
	assert.Equal(t, "Via: SIP/2.0/TCP sip.info:8060;branch="+h.Branch()+"\r\n",
		string(h.buf))

	h, err = NewHdrVia("TCP", "sip.info", 69537, nil)
	assert.NotNil(t, err)

	p := map[string]string{
		"ttl":      "665",
		"MAddr":    "ssl.voip.com",
		"received": "10.0.0.2",
		"foo":      "bar",
	}
	h, err = NewHdrVia("TLS", "proxy.io", 0, p)
	assert.Nil(t, err)
	assert.Equal(t, "665", h.TTL())
	assert.Equal(t, "ssl.voip.com", h.MAddr())
	assert.Equal(t, "10.0.0.2", h.Received())
	assert.Equal(t,
		"Via: SIP/2.0/TLS proxy.io;ttl=665;MAddr=ssl.voip.com;received=10.0.0.2;foo=bar;branch="+
			h.Branch()+"\r\n",
		string(h.buf))
}

func TestHdrCreateTo(t *testing.T) {
	h := NewHdrTo("", "sip:alice@voip.com", nil)
	assert.Nil(t, h)
}
