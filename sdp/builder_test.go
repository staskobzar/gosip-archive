package sdp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildInit(t *testing.T) {
	id := string(idFromNTP())
	str := "v=0\r\n" +
		"o=- " + id + " " + id + " IN IP4 atlanta.com\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n"

	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	assert.Equal(t, str, msg.String())
}

func TestBuildSubjectInfoUri(t *testing.T) {
	str := "s=Online training\r\n" +
		"i=SIP and SDP with certification\r\n" +
		"u=http://lib.sip.com/2019-11-02/readme.pdf\r\n" +
		"t=0 0\r\n"
	msg := NewMessage("192.168.1.1")
	assert.NotNil(t, msg)

	msg.SetSubject("Online training")
	msg.SetInfo("SIP and SDP with certification")
	msg.SetURI("http://lib.sip.com/2019-11-02/readme.pdf")
	assert.Contains(t, msg.String(), str)
}

func TestBuildEmailPhoneFields(t *testing.T) {
	str := "s=-\r\n" +
		"e=j.doe@example.com (Jane Doe)\r\n" +
		"e=Jane Doe <j.doe@example.com>\r\n" +
		"p=+1 617 555-6011\r\n" +
		"p=+1 555-845-9685\r\n" +
		"p=1 800 555-9685\r\n" +
		"t=0 0\r\n"
	msg := NewMessage("example.com")
	assert.NotNil(t, msg)

	msg.SetEmail("j.doe@example.com (Jane Doe)")
	msg.SetPhone("+1 617 555-6011")
	msg.SetEmail("Jane Doe <j.doe@example.com>")
	msg.SetPhone("+1 555-845-9685")
	msg.SetPhone("1 800 555-9685")
	assert.Contains(t, msg.String(), str)
}

func TestBuildSessionConnection(t *testing.T) {
	str := "s=-\r\n" +
		"c=IN IP4 sip.atlanta.com\r\n" +
		"t=0 0\r\n"
	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	msg.SetSessionConn("sip.atlanta.com")

	assert.Contains(t, msg.String(), str)

	str = "s=-\r\n" +
		"c=IN IP4 10.0.0.1\r\n" +
		"t=0 0\r\n"
	msg.SetSessionConn("10.0.0.1")
	assert.Contains(t, msg.String(), str)
}

func TestBuildBandwidthFields(t *testing.T) {
	str := "s=-\r\n" +
		"b=CT:15247\r\n" +
		"t=0 0\r\n"
	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	msg.SetBandWidth("CT", 15247)
	assert.Contains(t, msg.String(), str)

	str = "s=-\r\n" +
		"b=AS:382\r\n" +
		"b=X-YZ:29547\r\n" +
		"t=0 0\r\n"

	msg = NewMessage("atlanta.com")
	assert.NotNil(t, msg)
	msg.SetBandWidth("AS", 382)
	msg.SetBandWidth("X-YZ", 29547)
	assert.Contains(t, msg.String(), str)
}

func TestBuildTimeRepeatFields(t *testing.T) {
	str := "s=-\r\n" +
		"t=3034423619 3034423619\r\n" +
		"t=2873397496 2873404696\r\n"
	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	msg.SetTime(3034423619, 3034423619, nil)
	msg.SetTime(2873397496, 2873404696, nil)
	assert.Contains(t, msg.String(), str)

	str = "s=-\r\n" +
		"t=3034423619 3034423619\r\n" +
		"r=604800 3600 0 90000\r\n" +
		"r=7d 1h 0 25h\r\n"
	msg = NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	repeat := [][]byte{
		[]byte("604800 3600 0 90000"),
		[]byte("7d 1h 0 25h"),
	}
	msg.SetTime(3034423619, 3034423619, repeat)
	assert.Contains(t, msg.String(), str)
}

func TestBuildZoneField(t *testing.T) {
	str := "s=-\r\n" +
		"t=3034423619 3034423619\r\n" +
		"z=2882844526 -1h 2898848070 0\r\n"
	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	msg.SetTime(3034423619, 3034423619, nil)
	msg.SetZone("2882844526 -1h 2898848070 0")
	assert.Contains(t, msg.String(), str)
}

func TestBuildEncryptKey(t *testing.T) {
	str := "s=-\r\n" +
		"t=0 0\r\n" +
		"k=clear:u34wvpmdq9my8fqsvmv\r\n"
	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	msg.SetEncKey("clear:u34wvpmdq9my8fqsvmv")
	assert.Contains(t, msg.String(), str)
}

func TestBuildSessionAttributes(t *testing.T) {
	str := "s=-\r\n" +
		"t=0 0\r\n" +
		"a=group:BUNDLE 0\r\n" +
		"a=msid-semantic: WMS T7SIu47NNTZMOOHX\r\n"
	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)
	msg.SetSessAttr("group", "BUNDLE 0")
	msg.SetSessAttr("msid-semantic", " WMS T7SIu47NNTZMOOHX")

	assert.Contains(t, msg.String(), str)

	msg.SetSessAttrFlag("sendrecv")
	assert.Contains(t, msg.String(), str+"a=sendrecv\r\n")
}

func TestBuildAddMedia(t *testing.T) {
	str := "s=-\r\n" +
		"t=0 0\r\n" +
		"m=audio 17476 RTP/AVP 0\r\n"
	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	media := NewMedia("audio", 17476, "RTP/AVP", "0")

	msg.AddMedia(media)
	assert.Contains(t, msg.String(), str)
}

func TestBuildMediaInfoAndKey(t *testing.T) {
	str := "s=-\r\n" +
		"t=0 0\r\n" +
		"m=audio 17476 RTP/AVP 0\r\n" +
		"i=Audio session\r\n" +
		"k=prompt\r\n"
	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	media := NewMedia("audio", 17476, "RTP/AVP", "0")
	media.SetInfo("Audio session")
	media.SetEncKey("prompt")

	msg.AddMedia(media)

	assert.Contains(t, msg.String(), str)
}

func TestBuildMediaConn(t *testing.T) {
	str := "s=-\r\n" +
		"t=0 0\r\n" +
		"m=audio 17476 RTP/AVP 0\r\n" +
		"c=IN IP4 99.18.134.112\r\n"
	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	media := NewMedia("audio", 17476, "RTP/AVP", "0")
	media.SetConn("99.18.134.112")

	msg.AddMedia(media)

	assert.Contains(t, msg.String(), str)
}

func TestBuildMediaBandwidth(t *testing.T) {
	str := "s=-\r\n" +
		"t=0 0\r\n" +
		"m=audio 17476 RTP/AVP 0\r\n" +
		"b=CT:15247\r\n" +
		"b=AS:382\r\n"
	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	media := NewMedia("audio", 17476, "RTP/AVP", "0")
	media.SetBandWidth("CT", 15247)
	media.SetBandWidth("AS", 382)
	msg.AddMedia(media)

	assert.Contains(t, msg.String(), str)
}

func TestBuildMediaAttributes(t *testing.T) {
	str := "s=-\r\n" +
		"t=0 0\r\n" +
		"m=audio 17476 RTP/AVP 0 9 97\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:9 G722/8000\r\n" +
		"a=rtpmap:97 iLBC/8000\r\n" +
		"a=fmtp:97 mode=30\r\n" +
		"a=sendrecv\r\n"

	msg := NewMessage("atlanta.com")
	assert.NotNil(t, msg)

	media := NewMedia("audio", 17476, "RTP/AVP", "0 9 97")
	media.SetSessAttr("rtpmap", "0 PCMU/8000")
	media.SetSessAttr("rtpmap", "9 G722/8000")
	media.SetSessAttr("rtpmap", "97 iLBC/8000")
	media.SetSessAttr("fmtp", "97 mode=30")
	media.SetSessAttrFlag("sendrecv")

	msg.AddMedia(media)

	assert.Contains(t, msg.String(), str)
}

func TestParseBuild(t *testing.T) {
	str := "v=0\r\n" +
		"o=- 646332240307033527 2 IN IP4 127.0.0.1\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"a=group:BUNDLE 0\r\n" +
		"a=msid-semantic: WMS T7SIu47NNTZMOOHXQi2NBLi102k4holNf3Mb\r\n" +
		"m=audio 54895 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126\r\n" +
		"c=IN IP4 172.17.0.1\r\n" +
		"a=rtcp:9 IN IP4 0.0.0.0\r\n" +
		"a=candidate:3885250869 1 udp 2122260223 172.17.0.1 54895 typ host generation 0 network-id 1 network-cost 50\r\n" +
		"a=candidate:3046255141 1 udp 2122194687 192.168.86.203 55303 typ host generation 0 network-id 2\r\n" +
		"a=candidate:983066214 1 udp 2122129151 10.254.128.27 47217 typ host generation 0 network-id 3\r\n" +
		"a=candidate:2836907461 1 tcp 1518280447 172.17.0.1 9 typ host tcptype active generation 0 network-id 1 network-cost 50\r\n" +
		"a=candidate:4212250325 1 tcp 1518214911 192.168.86.203 9 typ host tcptype active generation 0 network-id 2\r\n" +
		"a=candidate:1947966102 1 tcp 1518149375 10.254.128.27 9 typ host tcptype active generation 0 network-id 3\r\n" +
		"a=ice-ufrag:ycm+\r\n" +
		"a=ice-pwd:nsgyekQXLWK530RaCGfsLKJh\r\n" +
		"a=ice-options:trickle\r\n" +
		"a=fingerprint:sha-256 28:4B:10:74:2D:0B:85:79:FF:79:15:86:7B:FD:B2:97:5E:6B:2A:A7:AB:30:CC:64:1F:E8:F2:40:EA:11:DA:58\r\n" +
		"a=setup:actpass\r\n" +
		"a=mid:0\r\n" +
		"a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n" +
		"a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n" +
		"a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid\r\n" +
		"a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n" +
		"a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n" +
		"a=sendrecv\r\n" +
		"a=msid:T7SIu47NNTZMOOHXQi2NBLi102k4holNf3Mb 9fe83c21-4de6-4ea0-9485-5d6299134f0c\r\n" +
		"a=rtcp-mux\r\n" +
		"a=rtpmap:111 opus/48000/2\r\n" +
		"a=rtcp-fb:111 transport-cc\r\n" +
		"a=fmtp:111 minptime=10;useinbandfec=1\r\n" +
		"a=rtpmap:103 ISAC/16000\r\n" +
		"a=rtpmap:104 ISAC/32000\r\n" +
		"a=rtpmap:9 G722/8000\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:8 PCMA/8000\r\n" +
		"a=rtpmap:106 CN/32000\r\n" +
		"a=rtpmap:105 CN/16000\r\n" +
		"a=rtpmap:13 CN/8000\r\n" +
		"a=rtpmap:110 telephone-event/48000\r\n" +
		"a=rtpmap:112 telephone-event/32000\r\n" +
		"a=rtpmap:113 telephone-event/16000\r\n" +
		"a=rtpmap:126 telephone-event/8000\r\n" +
		"a=ssrc:1845280214 cname:8gM4B6lr9cvWXOHN\r\n" +
		"a=ssrc:1845280214 msid:T7SIu47NNTZMOOHXQi2NBLi102k4holNf3Mb 9fe83c21-4de6-4ea0-9485-5d6299134f0c\r\n" +
		"a=ssrc:1845280214 mslabel:T7SIu47NNTZMOOHXQi2NBLi102k4holNf3Mb\r\n" +
		"a=ssrc:1845280214 label:9fe83c21-4de6-4ea0-9485-5d6299134f0c\r\n"

	msg, err := Parse([]byte(str))
	assert.Nil(t, err)
	assert.NotNil(t, msg)

	// match parsed and generated message
	assert.Equal(t, msg.String(), str)
}

func TestBuildMultiMedias(t *testing.T) {
	id := string(idFromNTP())
	str := "v=0\r\n" +
		"o=root " + id + " " + id + " IN IP4 203.182.134.111\r\n" +
		"s=VoIP PBX\r\n" +
		"c=IN IP4 203.182.134.111\r\n" +
		"b=CT:384\r\n" +
		"t=0 0\r\n" +
		"m=audio 13912 RTP/AVP 0 9 97 110 101\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=rtpmap:9 G722/8000\r\n" +
		"a=rtpmap:97 iLBC/8000\r\n" +
		"a=fmtp:97 mode=30\r\n" +
		"a=rtpmap:110 speex/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=fmtp:101 0-16\r\n" +
		"a=ptime:20\r\n" +
		"a=sendrecv\r\n" +
		"m=video 19308 RTP/AVP 99\r\n" +
		"a=rtpmap:99 H264/90000\r\n" +
		"a=fmtp:99 redundant-pic-cap=0;packetization-mode=0;level-asymmetry-allowed=0\r\n" +
		"a=sendrecv\r\n"

	msg := NewMessage("203.182.134.111")
	assert.NotNil(t, msg)

	msg.SetOriginUser("root")
	msg.SetSubject("VoIP PBX")
	msg.SetSessionConn("203.182.134.111")
	msg.SetBandWidth("CT", 384)

	media := NewMedia("audio", 13912, "RTP/AVP", "0 9 97 110 101")
	media.SetSessAttr("rtpmap", "0 PCMU/8000")
	media.SetSessAttr("rtpmap", "9 G722/8000")
	media.SetSessAttr("rtpmap", "97 iLBC/8000")
	media.SetSessAttr("fmtp", "97 mode=30")
	media.SetSessAttr("rtpmap", "110 speex/8000")
	media.SetSessAttr("rtpmap", "101 telephone-event/8000")
	media.SetSessAttr("fmtp", "101 0-16")
	media.SetSessAttr("ptime", "20")
	media.SetSessAttrFlag("sendrecv")
	msg.AddMedia(media)

	media = NewMedia("video", 19308, "RTP/AVP", "99")
	media.SetSessAttr("rtpmap", "99 H264/90000")
	media.SetSessAttr("fmtp",
		"99 redundant-pic-cap=0;packetization-mode=0;level-asymmetry-allowed=0")
	media.SetSessAttrFlag("sendrecv")
	msg.AddMedia(media)

	assert.Equal(t, msg.String(), str)
}

func BenchmarkBuildSDP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		msg := NewMessage("203.182.134.111")

		msg.SetOriginUser("root")
		msg.SetSubject("VoIP PBX")
		msg.SetInfo("SIP and SDP with certification")
		msg.SetURI("http://lib.sip.com/2019-11-02/readme.pdf")
		msg.SetSessionConn("203.182.134.111")
		msg.SetBandWidth("CT", 384)
		msg.SetEmail("Jane Doe <j.doe@example.com>")
		msg.SetPhone("+1 555-845-9685")

		media := NewMedia("audio", 13912, "RTP/AVP", "0 9 97 110 101")
		media.SetSessAttr("rtpmap", "0 PCMU/8000")
		media.SetSessAttr("rtpmap", "9 G722/8000")
		media.SetSessAttr("rtpmap", "97 iLBC/8000")
		media.SetSessAttr("fmtp", "97 mode=30")
		media.SetSessAttr("rtpmap", "110 speex/8000")
		media.SetSessAttr("rtpmap", "101 telephone-event/8000")
		media.SetSessAttr("fmtp", "101 0-16")
		media.SetSessAttr("ptime", "20")
		media.SetSessAttrFlag("sendrecv")
		msg.AddMedia(media)

		media = NewMedia("video", 19308, "RTP/AVP", "99")
		media.SetSessAttr("rtpmap", "99 H264/90000")
		media.SetSessAttr("fmtp",
			"99 redundant-pic-cap=0;packetization-mode=0;level-asymmetry-allowed=0")
		media.SetSessAttrFlag("sendrecv")
		msg.AddMedia(media)

		_ = msg.String()
	}
}
