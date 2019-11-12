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

	assert.Equal(t, "", msg.Subject())

	assert.Equal(t, "IN", msg.Conn.NetType())
	assert.Equal(t, "IP4", msg.Conn.AddrType())
	assert.Equal(t, "client.atlanta.example.com", msg.Conn.Address())

	m := msg.Medias[0]
	assert.Equal(t, 1, len(msg.Medias))
	assert.Equal(t, "audio", m.Type())
	assert.Equal(t, 49170, m.Port())
	assert.Equal(t, 0, m.NumPort())
	assert.Equal(t, "RTP/AVP", m.Proto())
	assert.Equal(t, "0", m.Fmt())

	// attributes
	//		"a=rtpmap:0 PCMU/8000\r\n"
	// assert.Equal(t, 1, len(m.attr))
	// a := m.attr[0]
	// assert.Equal(t)
}
