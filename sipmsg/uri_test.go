package sipmsg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURICreate(t *testing.T) {
	uri, err := NewSIPURI("atlanta.com", 0)
	assert.Nil(t, err)
	assert.Equal(t, "sip:atlanta.com", uri.String())

	uri, err = NewSIPURI("atlanta.com", 5560)
	assert.Nil(t, err)
	assert.Equal(t, "sip:atlanta.com:5560", uri.String())

	uri, err = NewSIPURI("", 0)
	assert.NotNil(t, err)

	uri, err = NewSIPURI("atlanta.com", -3)
	assert.NotNil(t, err)

	uri, err = NewSIPURI("atlanta.com", 300000)
	assert.NotNil(t, err)

	uri, err = NewSIPSURI("voip.com", 0)
	assert.Nil(t, err)
	assert.Equal(t, "sips:voip.com", uri.String())
}

func TestURISetUserinfo(t *testing.T) {
	uri, err := NewSIPURI("atlanta.com", 0)
	assert.Nil(t, err)

	err = uri.SetUserinfo("alice", "")
	assert.Nil(t, err)
	assert.Equal(t, "sip:alice@atlanta.com", uri.String())

	err = uri.SetUserinfo("bob", "")
	assert.Nil(t, err)
	assert.Equal(t, "sip:bob@atlanta.com", uri.String())

	err = uri.SetUserinfo("", "")
	assert.Nil(t, err)
	assert.Equal(t, "sip:atlanta.com", uri.String())

	// second time set empty
	err = uri.SetUserinfo("", "")
	assert.Nil(t, err)
	assert.Equal(t, "sip:atlanta.com", uri.String())

	err = uri.SetUserinfo("5522", "secret")
	assert.Nil(t, err)
	assert.Equal(t, "sip:5522:secret@atlanta.com", uri.String())

	err = uri.SetUserinfo("", "secret")
	assert.NotNil(t, err)
	assert.Equal(t, "sip:5522:secret@atlanta.com", uri.String())

	err = uri.SetUserinfo("5522", "")
	assert.Nil(t, err)
	assert.Equal(t, "sip:5522@atlanta.com", uri.String())

	uri, err = NewSIPURI("voip.com", 8060)
	assert.Nil(t, err)
	assert.Equal(t, "sip:voip.com:8060", uri.String())

	uri.SetUserinfo("alice", "")
	assert.Equal(t, "sip:alice@voip.com:8060", uri.String())
	uri.SetUserinfo("bob", "secret")
	assert.Equal(t, "sip:bob:secret@voip.com:8060", uri.String())
	uri.SetUserinfo("", "")
	assert.Equal(t, "sip:voip.com:8060", uri.String())

	uri = URIParse([]byte("sips:bob:pa55w0rd@example.com:8080;user=phone;lr?X-t=foo&h=v"))
	assert.NotNil(t, uri)
	uri.SetUserinfo("", "")
	assert.Equal(t, "sips:example.com:8080;user=phone;lr?X-t=foo&h=v", uri.String())
	uri.SetUserinfo("55544433", "")
	assert.Equal(t, "sips:55544433@example.com:8080;user=phone;lr?X-t=foo&h=v", uri.String())

	uri = URIParse([]byte("https://john@www.example.com:123/path/?tag=network"))
	err = uri.SetPort(0)
	assert.NotNil(t, err)
}

func TestURISetPort(t *testing.T) {
	uri, err := NewSIPURI("voip.com", 0)
	assert.Nil(t, err)

	err = uri.SetPort(5060)
	assert.Nil(t, err)
	assert.Equal(t, "sip:voip.com:5060", uri.String())

	err = uri.SetPort(0)
	assert.Nil(t, err)
	assert.Equal(t, "sip:voip.com", uri.String())

	err = uri.SetPort(-1)
	assert.NotNil(t, err)

	err = uri.SetPort(200000)
	assert.NotNil(t, err)

	uri = URIParse([]byte("sips:bob:pa55w0rd@example.com:8080;user=phone;lr?X-t=foo&h=v"))
	assert.NotNil(t, uri)
	uri.SetPort(0)
	assert.Equal(t, "sips:bob:pa55w0rd@example.com;user=phone;lr?X-t=foo&h=v", uri.String())

	uri.SetPort(5060)
	uri.SetUserinfo("", "")
	assert.Equal(t, "sips:example.com:5060;user=phone;lr?X-t=foo&h=v", uri.String())

	uri.SetPort(9060)
	assert.Equal(t, "sips:example.com:9060;user=phone;lr?X-t=foo&h=v", uri.String())

	uri = URIParse([]byte("https://john@www.example.com:123/path/?tag=network"))
	err = uri.SetPort(0)
	assert.NotNil(t, err)
}

func TestURIAddParam(t *testing.T) {
	uri, err := NewSIPURI("voip.com", 0)
	assert.Nil(t, err)
	assert.Equal(t, "sip:voip.com", uri.String())

	uri.AddParam("foo", "bar")
	assert.Equal(t, "sip:voip.com;foo=bar", uri.String())

	uri.AddParam("lr", "lr")
	assert.Equal(t, "sip:voip.com;foo=bar;lr", uri.String())

	uri.SetPort(5655)
	uri.AddParam("user", "phone")
	assert.Equal(t, "sip:voip.com:5655;foo=bar;lr;user=phone", uri.String())

	err = uri.AddParam("user", "fax")
	assert.NotNil(t, err)
	assert.Equal(t, "sip:voip.com:5655;foo=bar;lr;user=phone", uri.String())

	v, exists := uri.Param("foo")
	assert.True(t, exists)
	assert.Equal(t, "bar", v)

	v, exists = uri.Param("lr")
	assert.True(t, exists)

	v, exists = uri.Param("user")
	assert.True(t, exists)
	assert.Equal(t, "phone", v)

	uri = URIParse([]byte("sip:voip.com:8080?X-t=foo"))
	assert.NotNil(t, uri)
	uri.AddParam("user", "fax")
	assert.Equal(t, "sip:voip.com:8080;user=fax?X-t=foo", uri.String())
	uri.AddParam("bar", "bar")
	assert.Equal(t, "sip:voip.com:8080;user=fax;bar?X-t=foo", uri.String())

	h, exists := uri.Header("x-t")
	assert.True(t, exists)
	assert.Equal(t, "foo", h)
}

func TestURIAddHeader(t *testing.T) {
	uri, err := NewSIPURI("voip.com", 0)
	assert.Nil(t, err)
	assert.Equal(t, "sip:voip.com", uri.String())

	h, exists := uri.Header("foo")
	assert.False(t, exists)

	uri.AddHeader("foo", "bar")
	assert.Equal(t, "sip:voip.com?foo=bar", uri.String())

	h, exists = uri.Header("foo")
	assert.True(t, exists)
	assert.Equal(t, "bar", h)

	uri.AddHeader("Agent", "device")
	assert.Equal(t, "sip:voip.com?foo=bar&Agent=device", uri.String())

	h, exists = uri.Header("foo")
	assert.True(t, exists)
	assert.Equal(t, "bar", h)

	h, exists = uri.Header("Agent")
	assert.True(t, exists)
	assert.Equal(t, "device", h)

	err = uri.AddHeader("Agent", "device")
	assert.NotNil(t, err)
	assert.Equal(t, "sip:voip.com?foo=bar&Agent=device", uri.String())

	uri.AddParam("lr", "lr")
	assert.Equal(t, "sip:voip.com;lr?foo=bar&Agent=device", uri.String())

	uri.AddParam("user", "phone")
	assert.Equal(t, "sip:voip.com;lr;user=phone?foo=bar&Agent=device", uri.String())

	p, exists := uri.Param("lr")
	assert.True(t, exists)

	p, exists = uri.Param("user")
	assert.True(t, exists)
	assert.Equal(t, "phone", p)

	h, exists = uri.Header("foo")
	assert.True(t, exists)
	assert.Equal(t, "bar", h)

	h, exists = uri.Header("Agent")
	assert.True(t, exists)
	assert.Equal(t, "device", h)
}
