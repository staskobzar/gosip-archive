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
		h.buf.String())

	h, err = NewHdrVia("TCP", "sip.info", 8060, nil)
	assert.Nil(t, err)
	assert.Equal(t, "TCP", h.Transport())
	assert.Equal(t, "sip.info", h.Host())
	assert.Equal(t, "8060", h.Port())
	assert.Equal(t, "Via: SIP/2.0/TCP sip.info:8060;branch="+h.Branch()+"\r\n",
		h.buf.String())

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
}

func TestHdrCreateTo(t *testing.T) {
	h := NewHdrTo("", "sip:alice@voip.com", nil)
	assert.NotNil(t, h)
	assert.Equal(t, "sip:alice@voip.com", h.Addr())
	assert.Empty(t, h.DisplayName())
	assert.Equal(t, "To: <sip:alice@voip.com>\r\n", h.buf.String())

	h = NewHdrTo("Alice Smith", "sips:55521@ssl.tower.com", nil)
	assert.NotNil(t, h)
	assert.Equal(t, "sips:55521@ssl.tower.com", h.Addr())
	assert.Equal(t, "\"Alice Smith\"", h.DisplayName())
	assert.Equal(t, "To: \"Alice Smith\" <sips:55521@ssl.tower.com>\r\n", h.buf.String())

	h = NewHdrTo("", "sip:bob@atlanta.com", map[string]string{"foo": "bar", "lr": "lr"})
	assert.NotNil(t, h)
	assert.Equal(t, "sip:bob@atlanta.com", h.Addr())
	p, ok := h.Param("foo")
	assert.True(t, ok)
	assert.Equal(t, "bar", p)
	p, ok = h.Param("lr")
	assert.True(t, ok)
	assert.Empty(t, p)
}

func TestHdrCreateFrom(t *testing.T) {
	h := NewHdrFrom("", "sip:alice@voip.com", nil)
	assert.NotNil(t, h)
	assert.Equal(t, "sip:alice@voip.com", h.Addr())
	assert.Equal(t, "From: <sip:alice@voip.com>\r\n", h.buf.String())

	h = NewHdrFrom("Carl", "sip:225@atlanta.com", nil)
	assert.NotNil(t, h)
	assert.Equal(t, "sip:225@atlanta.com", h.Addr())
	assert.Equal(t, "\"Carl\"", h.DisplayName())
	assert.Equal(t, "From: \"Carl\" <sip:225@atlanta.com>\r\n", h.buf.String())
}

func TestHdrCreateFromToTag(t *testing.T) {
	h := NewHdrFrom("", "sip:alice@voip.com", map[string]string{"user": "phone"})
	assert.NotNil(t, h)
	assert.Equal(t, "From: <sip:alice@voip.com>;user=phone\r\n", h.buf.String())
	assert.Empty(t, h.Tag())

	err := h.AddTag()
	assert.Nil(t, err)
	tag := h.Tag()
	assert.NotEmpty(t, tag)
	assert.Equal(t, "From: <sip:alice@voip.com>;user=phone;tag="+tag+"\r\n", h.buf.String())

	err = h.AddTag()
	assert.NotNil(t, err)
}

func TestHdrCreateContact(t *testing.T) {
	h := NewHdrContact("", "sip:alice@voip.com", nil)
	assert.NotNil(t, h)
	assert.Equal(t, "Contact: <sip:alice@voip.com>\r\n", h.buf.String())

	h = NewHdrContact("Alice", "sip:alice@voip.com", nil)
	assert.NotNil(t, h)
	assert.Equal(t, "Contact: \"Alice\" <sip:alice@voip.com>\r\n", h.buf.String())

	h = NewHdrContact("Alice", "sip:alice@voip.com", map[string]string{"q": "0.7"})
	assert.NotNil(t, h)
	assert.Equal(t, "Contact: \"Alice\" <sip:alice@voip.com>;q=0.7\r\n", h.buf.String())
}

func TestHdrCreateRoute(t *testing.T) {
	h := NewHdrRoute("sip:voip.com")
	assert.NotNil(t, h)
	assert.Equal(t, "Route: <sip:voip.com>\r\n", h.buf.String())
}

func TestHdrCreateRecordRoute(t *testing.T) {
	h := NewHdrRecordRoute("sips:224.199.0.100")
	assert.NotNil(t, h)
	assert.Equal(t, "Record-Route: <sips:224.199.0.100>\r\n", h.buf.String())
}
