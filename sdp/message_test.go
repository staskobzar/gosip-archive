package sdp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseShortSDP(t *testing.T) {
	str := "v=0\r\n" +
		"o=alice 2890844526 2890844527 IN IP4 client.atlanta.example.com\r\n" +
		"s= \r\n" +
		"c=IN IP4 client.atlanta.example.com\r\n" +
		"t=0 0\r\n" +
		"a=session\r\n" +
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

	assert.Empty(t, msg.Subject())

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

	assert.Equal(t, 1, len(m.attr))
	a := m.attr[0]
	assert.False(t, a.IsFlag())
	assert.Equal(t, "rtpmap", a.Key())
	assert.Equal(t, "0 PCMU/8000", a.Value())
	assert.Empty(t, a.Flag())
}

func TestParseSDPNoMedia(t *testing.T) {
	str := "v=0\r\n" +
		"o=root 2890844566 2890844566 IN IP4 host.atlanta.example.com\r\n" +
		"s=-\r\n" +
		"c=IN IP4 h1.atlanta.example.com\r\n" +
		"t=0 0\r\n"
	msg, err := Parse([]byte(str))
	assert.Nil(t, err)

	assert.Equal(t, 0, msg.Version())

	assert.NotNil(t, msg.Origin)
	assert.Equal(t, "root", msg.Origin.Username())
	assert.Equal(t, 2890844566, msg.Origin.SessionID())
	assert.Equal(t, 2890844566, msg.Origin.SessionVer())
	assert.Equal(t, "IN", msg.Origin.NetType())
	assert.Equal(t, "IP4", msg.Origin.AddrType())
	assert.Equal(t, "host.atlanta.example.com", msg.Origin.UnicastAddr())

	assert.Equal(t, "-", msg.Subject())

	assert.Equal(t, "IN", msg.Conn.NetType())
	assert.Equal(t, "IP4", msg.Conn.AddrType())
	assert.Equal(t, "h1.atlanta.example.com", msg.Conn.Address())

	time := msg.Time
	assert.Equal(t, 1, len(time))
	assert.Equal(t, 0, time[0].StartTime())
	assert.Equal(t, 0, time[0].StopTime())

	assert.Equal(t, 0, len(msg.Medias))
}

func TestParseMultiMediasMultiAttributes(t *testing.T) {
	str := "v=0\r\n" +
		"o=bob 2890844526 2808844564 IN IP4 atlanta.com\r\n" +
		"s=Sales Conference\r\n" +
		"c=IN IP4 host.atlanta.com\r\n" +
		"t=0 0\r\n" +
		"a=active\r\n" +
		"a=media:full stack\r\n" +
		"m=audio 49170/2 RTP/AVP 0 8 97\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:8 PCMA/8000\r\n" +
		"a=rtpmap:97 iLBC/8000\r\n" +
		"m=video 51372 RTP/AVP 31 32\r\n" +
		"a=rtpmap:31 H261/90000\r\n" +
		"a=rtpmap:32 MPV/90000\r\n" +
		"a=fmtp:31 redundant-pic-cap=0;parameter-add=0;packetization-mode=0\r\n" +
		"a=sendonly\r\n"
	msg, err := Parse([]byte(str))
	assert.Nil(t, err)

	assert.Equal(t, 0, msg.Version())

	assert.NotNil(t, msg.Origin)
	assert.Equal(t, "bob", msg.Origin.Username())
	assert.Equal(t, 2890844526, msg.Origin.SessionID())
	assert.Equal(t, 2808844564, msg.Origin.SessionVer())
	assert.Equal(t, "IN", msg.Origin.NetType())
	assert.Equal(t, "IP4", msg.Origin.AddrType())
	assert.Equal(t, "atlanta.com", msg.Origin.UnicastAddr())

	assert.Equal(t, "Sales Conference", msg.Subject())

	// session attributes
	sa := msg.Attr
	assert.Equal(t, 2, len(sa))
	assert.True(t, sa[0].IsFlag())
	assert.Equal(t, "active", sa[0].Flag())
	assert.Empty(t, sa[0].Key())
	assert.Empty(t, sa[0].Value())
	assert.False(t, sa[1].IsFlag())
	assert.Empty(t, sa[1].Flag())
	assert.Equal(t, "media", sa[1].Key())
	assert.Equal(t, "full stack", sa[1].Value())

	// medias
	assert.Equal(t, 2, len(msg.Medias))
	m := msg.Medias[0]
	assert.Equal(t, "audio", m.Type())
	assert.Equal(t, 49170, m.Port())
	assert.Equal(t, 2, m.NumPort())
	assert.Equal(t, "RTP/AVP", m.Proto())
	assert.Equal(t, "0 8 97", m.Fmt())

	assert.Equal(t, 3, len(m.attr))
	a := m.attr[0]
	assert.False(t, a.IsFlag())
	assert.Equal(t, "rtpmap", a.Key())
	assert.Equal(t, "0 PCMU/8000", a.Value())
	assert.Empty(t, a.Flag())

	a = m.attr[1]
	assert.False(t, a.IsFlag())
	assert.Equal(t, "rtpmap", a.Key())
	assert.Equal(t, "8 PCMA/8000", a.Value())
	assert.Empty(t, a.Flag())

	a = m.attr[2]
	assert.False(t, a.IsFlag())
	assert.Equal(t, "rtpmap", a.Key())
	assert.Equal(t, "97 iLBC/8000", a.Value())
	assert.Empty(t, a.Flag())

	m = msg.Medias[1]
	assert.Equal(t, "video", m.Type())
	assert.Equal(t, 51372, m.Port())
	assert.Equal(t, 0, m.NumPort())
	assert.Equal(t, "RTP/AVP", m.Proto())
	assert.Equal(t, "31 32", m.Fmt())

	assert.Equal(t, 4, len(m.attr))

	a = m.attr[0]
	assert.False(t, a.IsFlag())
	assert.Equal(t, "rtpmap", a.Key())
	assert.Equal(t, "31 H261/90000", a.Value())
	assert.Empty(t, a.Flag())

	a = m.attr[1]
	assert.False(t, a.IsFlag())
	assert.Equal(t, "rtpmap", a.Key())
	assert.Equal(t, "32 MPV/90000", a.Value())
	assert.Empty(t, a.Flag())

	a = m.attr[2]
	assert.False(t, a.IsFlag())
	assert.Equal(t, "fmtp", a.Key())
	assert.Equal(t, "31 redundant-pic-cap=0;parameter-add=0;packetization-mode=0", a.Value())
	assert.Empty(t, a.Flag())

	a = m.attr[3]
	assert.True(t, a.IsFlag())
	assert.Empty(t, a.Key())
	assert.Empty(t, a.Value())
	assert.Equal(t, "sendonly", a.Flag())
}

func BenchmarkParseSDPMessage(b *testing.B) {
	str := "v=0\r\n" +
		"o=root 535635648 535635648 IN IP4 199.182.134.111\r\n" +
		"s=Modulis PBX\r\n" +
		"c=IN IP4 199.182.134.111\r\n" +
		"b=CT:384\r\n" +
		"t=0 0\r\n" +
		"m=audio 18018 RTP/AVP 0 9 97 110 101\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:9 G722/8000\r\n" +
		"a=rtpmap:97 iLBC/8000\r\n" +
		"a=fmtp:97 mode=30\r\n" +
		"a=rtpmap:110 speex/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=fmtp:101 0-16\r\n" +
		"a=ptime:20\r\n" +
		"a=sendrecv\r\n" +
		"m=video 13450 RTP/AVP 99\r\n" +
		"a=rtpmap:99 H264/90000\r\n" +
		"a=fmtp:99 redundant-pic-cap=0;parameter-add=0;packetization-mode=0;level-asymmetry-allowed=0\r\n" +
		"a=sendrecv\r\n"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse([]byte(str))
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkParseSDPMessage1(b *testing.B) {
	str := "v=0\r\n" +
		"o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n" +
		"s=SDP Seminar\r\n" +
		"i=A Seminar on the session description protocol\r\n" +
		"u=http://www.example.com/seminars/sdp.pdf\r\n" +
		"e=j.doe@example.com (Jane Doe)\r\n" +
		"p=12345\r\n" +
		"c=IN IP4 224.2.17.12/127\r\n" +
		"b=CT:154798\r\n" +
		"z=2882844526 -1h 2898848070 0\r\n" +
		"t=2873397496 2873404696\r\n" +
		"r=7d 3600 0 25h\r\n" +
		"k=clear:ab8c4df8b8f4as8v8iuy8re\r\n" +
		"a=recvonly\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"i=Some audio\r\n" +
		"m=video 51372 RTP/AVP 99\r\n" +
		"b=AS:66781\r\n" +
		"k=prompt\r\n" +
		"a=rtpmap:99 h263-1998/90000\r\n"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Parse([]byte(str))
		if err != nil {
			panic(err)
		}
	}
}
