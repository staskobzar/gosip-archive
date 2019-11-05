package sipmsg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHdrContentTypeParse(t *testing.T) {
	str := "application/sdp"
	ct, err := parseContentType([]byte(str))
	assert.Nil(t, err)

	assert.Equal(t, "application", ct.MediaType())
	assert.Equal(t, "sdp", ct.MediaSubtype())
	assert.True(t, ct.IsSDP())

	str = "text/html; charset=ISO-8859-4"
	ct, err = parseContentType([]byte(str))
	assert.Nil(t, err)
	assert.Equal(t, "text", ct.MediaType())
	assert.Equal(t, "html", ct.MediaSubtype())
	assert.False(t, ct.IsSDP())
	assert.Equal(t, "ISO-8859-4", ct.Param("charset"))

	str = "text/html; charset=utf8;foo=\"bar\""
	ct, err = parseContentType([]byte(str))
	assert.Nil(t, err)
	assert.Equal(t, "utf8", ct.Param("charset"))
	assert.Equal(t, "bar", ct.Param("foo"))
	assert.Equal(t, "", ct.Param("bar"))
}

func TestHdrContentTypeInvalidParse(t *testing.T) {
	str := "application bar"
	ct, err := parseContentType([]byte(str))
	assert.NotNil(t, err)
	assert.Nil(t, ct)
}
