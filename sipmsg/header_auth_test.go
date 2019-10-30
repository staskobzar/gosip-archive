package sipmsg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthChallenge(t *testing.T) {
	str := "Digest realm=\"atlanta.com\",\r\n" +
		" domain=\"sip:ss1.carrier.com\", qop=\"auth\",\r\n" +
		" nonce=\"f84f1cec41e6cbe5aea9c8e88d359\",\r\n" +
		" opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", \r\n" +
		" stale=TRUE, algorithm=MD5"
	ch, err := parseChallenge([]byte(str))
	assert.Nil(t, err)

	assert.Equal(t, "atlanta.com", ch.Realm())
	assert.Equal(t, "sip:ss1.carrier.com", ch.Domain())
	assert.Equal(t, QOPAuth, ch.QOP())
	assert.True(t, ch.IsQOPAuth())
	assert.False(t, ch.IsQOPAuthInt())
	assert.Equal(t, "f84f1cec41e6cbe5aea9c8e88d359", ch.Nonce())
	assert.Equal(t, "5ccc069c403ebaf9f0171e9517f40e41", ch.Opaque())
	assert.True(t, ch.Stale())
	assert.Equal(t, AlgoMD5, ch.Algo())

	str = "Digest realm=\"atlanta.com\" nonce=\"5ccc069c403ebaf9f0171e9517f40e41\""
	ch, err = parseChallenge([]byte(str))
	assert.NotNil(t, err)

	str = "Digest realm=\"atlanta.com\",\r\n" +
		" domain=\"sip:ss1.carrier.com\", qop=\"auth,auth-int\",\r\n" +
		" nonce=\"f84f1cec41e6cbe5aea9c8e88d359\",\r\n" +
		" stale=TRUE, algorithm=MD5"
	ch, err = parseChallenge([]byte(str))
	assert.Nil(t, err)
	assert.True(t, ch.IsQOPAuth())
	assert.True(t, ch.IsQOPAuthInt())
}

func TestAuthCredentials(t *testing.T) {
	str := "Digest username=\"Alice\", realm=\"atlanta.com\",\r\n" +
		"   nonce=\"c60f3082ee1212b402a21831ae\",\r\n" +
		"   response=\"e4d909c290d0fb1ca068ffaddf22cbd0\""
	cr, err := parseCredentials([]byte(str))
	assert.Nil(t, err)
	assert.Equal(t, "Alice", cr.Username())
	assert.Equal(t, "atlanta.com", cr.Realm())
	assert.Equal(t, "c60f3082ee1212b402a21831ae", cr.Nonce())
	assert.Equal(t, "e4d909c290d0fb1ca068ffaddf22cbd0", cr.Response())

	str = "Digest username=\"bob\", realm=\"example.com\",\r\n" +
		"  nonce=\"88df84f1cac4341aea9c8ee6cbe5a359\", opaque=\"403ebaf9f0\",\r\n" +
		"  URI=\"sips:biloxi.com\", response=\"ff0437c51696f9a76244f0cf1dbabbea\",\r\n" +
		"  cnonce=\"0a4f113b\", qop=auth-int, nc=00000001, algorithm=MD5-sess"
	cr, err = parseCredentials([]byte(str))
	assert.Nil(t, err)
	assert.Equal(t, "bob", cr.Username())
	assert.Equal(t, "example.com", cr.Realm())
	assert.Equal(t, "88df84f1cac4341aea9c8ee6cbe5a359", cr.Nonce())
	assert.Equal(t, "403ebaf9f0", cr.Opaque())
	assert.Equal(t, "sips:biloxi.com", cr.URI())
	assert.Equal(t, "ff0437c51696f9a76244f0cf1dbabbea", cr.Response())
	assert.Equal(t, "0a4f113b", cr.CNonce())
	assert.Equal(t, AlgoMD5sess, cr.Algo())
	assert.Equal(t, QOPAuthInt, cr.QOP())
	assert.Equal(t, 1, cr.NonceCount())
}

func TestAuthAuthorize(t *testing.T) {
	chlstr := "Digest realm=\"example.com\", " +
		"nonce=\"5db8cc4a0000142280ed54f9ae98253634445c433235da25\", stale=true"
	chlg, err := parseChallenge([]byte(chlstr))
	assert.Nil(t, err)

	cr := chlg.Authorize("REGISTER", "sip:example.com", "alice", "pa55w0rd")

	assert.Equal(t, "alice", cr.Username())
	assert.Equal(t, "example.com", cr.Realm())
	assert.Equal(t, "5db8cc4a0000142280ed54f9ae98253634445c433235da25", cr.Nonce())
	assert.Equal(t, "sip:example.com", cr.URI())
	assert.Equal(t, "1a74b013d700b1b3f8c455d2f58be6c4", cr.Response())
	assert.Equal(t, AlgoMD5, cr.Algo())
	assert.Equal(t, QOPAuth, cr.QOP())

	str := "Digest username=\"alice\", realm=\"example.com\", " +
		"nonce=\"5db8cc4a0000142280ed54f9ae98253634445c433235da25\", " +
		"uri=\"sip:example.com\", response=\"1a74b013d700b1b3f8c455d2f58be6c4\", " +
		"algorithm=MD5, qop=auth"
	assert.Equal(t, str, cr.String())
}

func BenchmarkParseCredentials(b *testing.B) {
	str := "Digest username=\"bob\", realm=\"example.com\",\r\n" +
		"  nonce=\"88df84f1cac4341aea9c8ee6cbe5a359\", opaque=\"403ebaf9f0\",\r\n" +
		"  URI=\"sips:biloxi.com\", response=\"ff0437c51696f9a76244f0cf1dbabbea\",\r\n" +
		"  cnonce=\"0a4f113b\", qop=auth-int, nc=00000001, algorithm=MD5-sess"
	for i := 0; i < b.N; i++ {
		parseCredentials([]byte(str))
	}
}

func BenchmarkParseChallenge(b *testing.B) {
	str := "Digest realm=\"atlanta.com\",\r\n" +
		" domain=\"sip:ss1.carrier.com\", qop=\"auth\",\r\n" +
		" nonce=\"f84f1cec41e6cbe5aea9c8e88d359\",\r\n" +
		" opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", \r\n" +
		" stale=TRUE, algorithm=MD5"
	for i := 0; i < b.N; i++ {
		parseChallenge([]byte(str))
	}
}
