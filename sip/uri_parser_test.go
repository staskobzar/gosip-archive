package sip

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURIParse(t *testing.T) {
	uri := []byte("sip:alice@example.com")
	u := SIPURIParse(uri)
	assert.NotNil(t, uri)
	assert.Equal(t, "sip", u.Scheme())
	assert.Equal(t, "alice", u.User())
	assert.Equal(t, "example.com", u.Host())
	fmt.Printf("%#v\n", u)
}
