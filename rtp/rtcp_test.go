package rtp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRTCPHeaderDecode(t *testing.T) {
	// sender report
	pack := []byte{0x81, 0xc8, 0x00, 0x0c}
	// v: 2, p: 0, rc: 1, t: 200, l: 12 (52 byte)
	h, err := rtcpHeaderDecode(pack)
	assert.Nil(t, err)
	assert.Equal(t, RTCPSR, h.Type)
	assert.Equal(t, 2, int(h.Ver))
	assert.False(t, h.Pad)
	assert.Equal(t, 1, int(h.RCount))
	assert.Equal(t, 52, h.Len())
	assert.Equal(t, 48, h.PLen())
	assert.Equal(t, 12, int(h.Length))

	// receiver report
	pack = []byte{0x81, 0xc9, 0x00, 0x07}
	// v: 2, p: 0, rc: 1, t: 201, l: 7 (32 byte)
	h, err = rtcpHeaderDecode(pack)
	assert.Nil(t, err)
	assert.Equal(t, RTCPRR, h.Type)
	assert.Equal(t, 2, int(h.Ver))
	assert.False(t, h.Pad)
	assert.Equal(t, 1, int(h.RCount))
	assert.Equal(t, 32, h.Len())
	assert.Equal(t, 28, h.PLen())
	assert.Equal(t, 7, int(h.Length))

	// source description
	pack = []byte{0x81, 0xca, 0x00, 0x08}
	// v: 2, p: 0, rc: 1, t: 202, l: 8 (36 byte)
	h, err = rtcpHeaderDecode(pack)
	assert.Nil(t, err)
	assert.Equal(t, RTCPSDES, h.Type)
	assert.Equal(t, 2, int(h.Ver))
	assert.False(t, h.Pad)
	assert.Equal(t, 1, int(h.RCount))
	assert.Equal(t, 36, h.Len())
	assert.Equal(t, 32, h.PLen())
	assert.Equal(t, 8, int(h.Length))

	// bye header
	pack = []byte{0x81, 0xcb, 0x00, 0x05}
	// v: 2, p: 0, rc: 1, t: 203, l: 5 (24 byte)
	h, err = rtcpHeaderDecode(pack)
	assert.Nil(t, err)
	assert.Equal(t, RTCPBYE, h.Type)
	assert.Equal(t, 2, int(h.Ver))
	assert.False(t, h.Pad)
	assert.Equal(t, 1, int(h.RCount))
	assert.Equal(t, 24, h.Len())
	assert.Equal(t, 20, h.PLen())
	assert.Equal(t, 5, int(h.Length))

	// application specific
	pack = []byte{0x81, 0xcc, 0x00, 0x06}
	// v: 2, p: 0, rc: 1, t: 204, l: 6 (28 byte)
	h, err = rtcpHeaderDecode(pack)
	assert.Nil(t, err)
	assert.Equal(t, RTCPAPP, h.Type)
	assert.Equal(t, 2, int(h.Ver))
	assert.False(t, h.Pad)
	assert.Equal(t, 1, int(h.RCount))
	assert.Equal(t, 28, h.Len())
	assert.Equal(t, 24, h.PLen())
	assert.Equal(t, 6, int(h.Length))
}

func TestRTCPHeaderDecodeError(t *testing.T) {
	// data array is too short
	pack := []byte{0x81, 0xc8, 0x00}
	h, err := rtcpHeaderDecode(pack)
	assert.Error(t, err)
	assert.Equal(t, ErrorRTCPHeaderSize, err)
	assert.Nil(t, h)

	h, err = rtcpHeaderDecode([]byte{})
	assert.Error(t, err)
	assert.Equal(t, ErrorRTCPHeaderSize, err)
	assert.Nil(t, h)

	// invalid packet type
	pack = []byte{0x81, 0xff, 0x00, 0x06}
	h, err = rtcpHeaderDecode(pack)
	assert.Error(t, err)
	assert.Equal(t, ErrorRTCPHeaderType, err)
	assert.Nil(t, h)

	pack = []byte{0x81, 0x7c, 0x00, 0x06}
	h, err = rtcpHeaderDecode(pack)
	assert.Error(t, err)
	assert.Equal(t, ErrorRTCPHeaderType, err)
	assert.Nil(t, h)

	// invalid version
	pack = []byte{0xc1, 0xc8, 0x00, 0x06}
	h, err = rtcpHeaderDecode(pack)
	assert.Error(t, err)
	assert.Equal(t, ErrorRTCPHeaderVer, err)
	assert.Nil(t, h)

	pack = []byte{0x41, 0xc8, 0x00, 0x06}
	h, err = rtcpHeaderDecode(pack)
	assert.Error(t, err)
	assert.Equal(t, ErrorRTCPHeaderVer, err)
	assert.Nil(t, h)
}

func TestRTCPDecodeSender(t *testing.T) {
	input := "\x81\xc8\x00\x0c\x58\xf3\x3d\xea\x00\x02\x4f\xf2\x07\xef\x9d\xa9" +
		"\x11\x48\xe4\x02\x00\x00\x02\x4a\x00\x01\x6b\x25\xd2\xbd\x4e\x3e" +
		"\x00\x00\x00\x00\x00\x00\x01\x05\x00\x00\x00\x00\x86\xde\xfe\xf9" +
		"\x00\x03\xd9\x58"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPSR, h.Type)

	sr, err := rtcpSRDecode(data[4:h.PLen()])
	assert.Nil(t, err)
	assert.EqualValues(t, 1492336106, sr.SSRC)
	assert.EqualValues(t, 151538, sr.NTPMSW)
	assert.EqualValues(t, 133143977, sr.NTPLSW)
	assert.EqualValues(t, 289989634, sr.RTPTime)
	assert.EqualValues(t, 586, sr.PackSent)
	assert.EqualValues(t, 92965, sr.OctSent)

	// sender report blocks
	assert.Equal(t, 1, len(sr.RBlock))

	b := sr.RBlock[0]
	assert.EqualValues(t, 3535621694, b.SSRC)
	assert.EqualValues(t, 0, b.Fract)
	assert.EqualValues(t, 0, b.Lost)
	assert.EqualValues(t, 0, b.SeqNum)
	assert.EqualValues(t, 0, b.Jitter)
	assert.EqualValues(t, 2262761209, b.LSR)
	assert.EqualValues(t, 252248, b.DLSR)
}

/*
func TestRTCPDecode(t *testing.T) {
	pack := "\x81\xc8\x00\x0c\xd2\xbd\x4e\x3e\xc5\x92\x86\xd4\xe6\xe9\x78\xd5" +
		"\x00\x00\x01\x40\x00\x00\x00\x02\x00\x00\x01\x40\xd2\xbd\x4e\x3e" +
		"\x00\x00\x00\x00\x00\x02\x00\x02\x00\x00\x00\x00\x86\xd4\xe6\xe9" +
		"\x00\x00\x00\x01\x81\xc9\x00\x07\xd2\xbd\x4e\x3e\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x86\xd4\xe6\xe9" +
		"\x00\x00\x00\x01"

	rtcp, err := RTCPDecode([]byte(pack))
	assert.Nill(t, err)
	assert.NotNill(t, rtpc)

	assert.Equal(t, 2, len(rtcp))

	assert.Equal(t, RTCPSR, rtcp[0].ID())
	sr := rtcp[0].(RTCPSender)

	// TODO: RTCPSender methods

	assert.Equal(t, RTCPRR, rtcp[1].ID())
	sr := rtcp[0].(RTCPReceiver)
	// TODO: RTCPReceiver methods
}
*/
