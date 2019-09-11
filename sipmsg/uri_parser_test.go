package sipmsg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURIParse(t *testing.T) {
	uri := SIPURIParse([]byte("sip:alice@example.com"))
	assert.NotNil(t, uri)
	assert.Equal(t, "sip", uri.Scheme())
	assert.Equal(t, "alice", uri.User())
	assert.Equal(t, "example.com", uri.Host())
	assert.Equal(t, "", uri.Params())
	assert.Equal(t, "", uri.Headers())

	uri = SIPURIParse([]byte("sips:bob:pa55w0rd@example.com:8080;user=phone;lr?X-t=foo&h=v"))
	assert.NotNil(t, uri)
	assert.Equal(t, "sips", uri.Scheme())
	assert.Equal(t, "bob", uri.User())
	assert.Equal(t, "example.com", uri.Host())
	assert.Equal(t, "8080", uri.Port())
	assert.Equal(t, ";user=phone;lr", uri.Params())
	assert.Equal(t, "?X-t=foo&h=v", uri.Headers())

	uri = SIPURIParse([]byte("sip:atlanta.com"))
	assert.NotNil(t, uri)
	assert.Equal(t, "sip", uri.Scheme())
	assert.Equal(t, "", uri.User())
	assert.Equal(t, "", uri.Password())
	assert.Equal(t, "atlanta.com", uri.Host())
	assert.Equal(t, "", uri.Port())
	assert.Equal(t, "", uri.Params())
	assert.Equal(t, "", uri.Headers())
}

func BenchmarkURIParsSimple(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SIPURIParse([]byte("sips:bob:pa55w0rd@example.com:8080;user=phone?X-t=foo"))
	}
}
