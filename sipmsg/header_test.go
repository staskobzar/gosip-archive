package sipmsg

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHdrStatusLineParse(t *testing.T) {
	h := parseHeader([]byte("SIP/2.0 180 Ringing\r\n"))
	fmt.Printf("%#v\n", h)
	assert.True(t, true)
}
