package rtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestRTCPDecodeSenderNoBlock(t *testing.T) {
	input := "\x80\xc8\x00\x06\x00\x00\x4b\x51\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x57\x85\x14\x00\x00\x00\x22\x00\x00\x00\xc8"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPSR, h.Type)

	sr, err := rtcpSRDecode(data[4:h.Len()])
	assert.Nil(t, err)
	assert.EqualValues(t, 19281, sr.SSRC)
	assert.EqualValues(t, 0, sr.NTPMSW)
	assert.EqualValues(t, 0, sr.NTPLSW)
	assert.EqualValues(t, 5735700, sr.RTPTime)
	assert.EqualValues(t, 34, sr.PackSent)
	assert.EqualValues(t, 200, sr.OctSent)

	// sender report blocks
	assert.Equal(t, 0, len(sr.RBlock))
}

func TestRTCPDecodeSenderOneBlock(t *testing.T) {
	input := "\x81\xc8\x00\x0c\x58\xf3\x3d\xea\x00\x02\x4f\xf2\x07\xef\x9d\xa9" +
		"\x11\x48\xe4\x02\x00\x00\x02\x4a\x00\x01\x6b\x25\xd2\xbd\x4e\x3e" +
		"\x00\x00\x00\x00\x00\x00\x01\x05\x00\x00\x00\x00\x86\xde\xfe\xf9" +
		"\x00\x03\xd9\x58"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPSR, h.Type)

	sr, err := rtcpSRDecode(data[4:h.Len()])
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
	assert.EqualValues(t, 261, b.SeqNum)
	assert.EqualValues(t, 0, b.Jitter)
	assert.EqualValues(t, 2262761209, b.LSR)
	assert.EqualValues(t, 252248, b.DLSR)

	input = "\x81\xc8\x00\x0c\x58\xf3\x3d\xea\x00\x02\x4f\xf2\x07\xef\x9d\xa9" +
		"\x11\x48\xe4\x02\x00\x00\x02\x4a\x00\x01\x6b\x25\xd2\xbd\x4e\x3e" +
		"\x00\x00\x00\x00\x00\x00\x01\x05\x00\x00\x00\x00\x86\xde\xfe\xf9" +
		"\x00\x03\x58"
	data = []byte(input)
	sr, err = rtcpSRDecode(data[4 : h.Len()-1])
	assert.NotNil(t, err)
	assert.Nil(t, sr)
}

func TestRTCPDecodeSenderMultiBlock(t *testing.T) {
	input := "\x81\xc8\x00\x12\x58\xf3\x3d\xea\x00\x02\x4f\xf2\x07\xef\x9d\xa9" +
		"\x11\x48\xe4\x02\x00\x00\x02\x4a\x00\x01\x6b\x25\xd2\xbd\x4e\x3e" +
		"\x00\x00\x00\x00\x00\x00\x01\x05\x00\x00\x00\x00\x86\xde\xfe\xf9" +
		"\x00\x03\xd9\x58\x70\x58\xb5\x5a\x00\x00\x00\x01\x00\x00\xfc\x52" +
		"\x00\x00\x00\x1f\x9c\x76\x4c\x49\x00\x02\x86\x66"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPSR, h.Type)

	sr, err := rtcpSRDecode(data[4:h.Len()])
	assert.Nil(t, err)

	// sender report blocks
	assert.Equal(t, 2, len(sr.RBlock))
	b := sr.RBlock[1]
	assert.EqualValues(t, 1884861786, b.SSRC)
	assert.EqualValues(t, 0, b.Fract)
	assert.EqualValues(t, 1, b.Lost)
	assert.EqualValues(t, 64594, b.SeqNum)
	assert.EqualValues(t, 31, b.Jitter)
	assert.EqualValues(t, 2624998473, b.LSR)
	assert.EqualValues(t, 165478, b.DLSR)
}

func TestRTCPDecodeReceiver(t *testing.T) {
	input := "\x81\xc9\x00\x07\xd2\xbd\x4e\x3e\x58\xf3\x3d\xea\x00\x00\x00\x00" +
		"\x00\x00\x2e\x9b\x00\x00\x0b\x3e\x86\xe4\x06\x24\x00\x00\x00\x01"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPRR, h.Type)

	rr, err := rtcpRRDecode(data[4:h.Len()])
	assert.Nil(t, err)

	assert.EqualValues(t, 3535621694, rr.SSRC)

	// receiver report blocks
	assert.Equal(t, 1, len(rr.RBlock))
	b := rr.RBlock[0]
	assert.EqualValues(t, 1492336106, b.SSRC)
	assert.EqualValues(t, 0, b.Fract)
	assert.EqualValues(t, 0, b.Lost)
	assert.EqualValues(t, 11931, b.SeqNum)
	assert.EqualValues(t, 2878, b.Jitter)
	assert.EqualValues(t, 2263090724, b.LSR)
	assert.EqualValues(t, 1, b.DLSR)
}

func TestRTCPDecodeReceiverNoBlocks(t *testing.T) {
	input := "\x80\xc9\x00\x01\x22\x6a\x6a\xa1"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPRR, h.Type)

	rr, err := rtcpRRDecode(data[4:h.Len()])
	assert.Nil(t, err)

	assert.EqualValues(t, 577399457, rr.SSRC)

	// receiver report blocks
	assert.Equal(t, 0, len(rr.RBlock))
}

func TestRTCPDecodeReceiverWithTwoBlocks(t *testing.T) {
	input := "\x88\xc9\x00\x0d\xf5\x58\x94\x70\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x43\x8b\xac\x37\x00\x00\x00\x00\x00\x00\x26\xe7\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPRR, h.Type)

	rr, err := rtcpRRDecode(data[4:h.Len()])
	assert.Nil(t, err)

	assert.EqualValues(t, 4116223088, rr.SSRC)

	// receiver report blocks
	assert.Equal(t, 2, len(rr.RBlock))

	b := rr.RBlock[0]
	assert.EqualValues(t, 0, b.SSRC)
	assert.EqualValues(t, 0, b.Fract)
	assert.EqualValues(t, 0, b.Lost)
	assert.EqualValues(t, 0, b.SeqNum)
	assert.EqualValues(t, 0, b.Jitter)
	assert.EqualValues(t, 0, b.LSR)
	assert.EqualValues(t, 0, b.DLSR)

	b = rr.RBlock[1]
	assert.EqualValues(t, 1133227063, b.SSRC)
	assert.EqualValues(t, 0, b.Fract)
	assert.EqualValues(t, 0, b.Lost)
	assert.EqualValues(t, 9959, b.SeqNum)
	assert.EqualValues(t, 0, b.Jitter)
	assert.EqualValues(t, 0, b.LSR)
	assert.EqualValues(t, 0, b.DLSR)
}

func TestRTCPDecodeSDES(t *testing.T) {
	input := "\x81\xca\x00\x06\x43\x8b\xac\x37\x01\x0e\x51\x54\x53\x53\x31\x34" +
		"\x31\x30\x32\x39\x32\x38\x35\x38\x00\x00\x00\x00"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPSDES, h.Type)

	sdes, err := rtcpSDESDecode(data[4:h.Len()])
	assert.Nil(t, err)

	// source description report blocks
	assert.Equal(t, 1, len(sdes.Chunk))

	c := sdes.Chunk[0]

	assert.EqualValues(t, 1133227063, c.ID)

	assert.Equal(t, 1, len(c.Item))
	item := c.Item[0]

	assert.Equal(t, SDESCNAME, item.Type)
	assert.EqualValues(t, 14, item.Len)
	assert.Equal(t, "QTSS1410292858", string(item.Text))
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
