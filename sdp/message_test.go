package sdp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseMinSDP(t *testing.T) {
	str := "v=0\r\n" +
		"o=alice 2890844526 2890844527 IN IP4 client.atlanta.example.com\r\n" +
		"s= \r\n" +
		"c=IN IP4 client.atlanta.example.com\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n"
	msg, err := Parse([]byte(str))
	assert.Nil(t, err)

	assert.Equal(t, 0, msg.Version())

	assert.NotNil(t, msg.Origin)
	assert.Equal(t, "alice", msg.Origin.Username())
	assert.Equal(t, 2890844526, msg.Origin.SessionID())
	assert.Equal(t, 2890844527, msg.Origin.SessionVer())
	assert.Equal(t, "IN", msg.Origin.NetType())
	assert.Equal(t, "IP4", msg.Origin.AddrType())
	assert.Equal(t, "client.atlanta.example.com", msg.Origin.UnicastAddr())
}
