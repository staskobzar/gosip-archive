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

	sr, err := rtcpSRDecode(data[4:h.Len()], h)
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

	sr, err := rtcpSRDecode(data[4:h.Len()], h)
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
	sr, err = rtcpSRDecode(data[4:h.Len()-1], h)
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

	sr, err := rtcpSRDecode(data[4:h.Len()], h)
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

	rr, err := rtcpRRDecode(data[4:h.Len()], h)
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

	rr, err := rtcpRRDecode(data[4:h.Len()], h)
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

	rr, err := rtcpRRDecode(data[4:h.Len()], h)
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

	sdes, err := rtcpSDESDecode(data[4:h.Len()], h)
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

func TestRTCPDecodeSDESMultiItemsPriv(t *testing.T) {
	input := "\x81\xca\x00\x1e\x88\x54\xaa\x3d\x01\x3d\x34\x39\x36\x32\x38\x31" +
		"\x33\x42\x44\x46\x37\x30\x45\x45\x36\x34\x31\x34\x33\x33\x30\x36" +
		"\x32\x34\x37\x46\x46\x46\x43\x41\x31\x31\x40\x75\x6e\x69\x71\x75" +
		"\x65\x2e\x7a\x31\x41\x32\x37\x37\x30\x39\x45\x31\x31\x30\x39\x35" +
		"\x39\x44\x43\x2e\x6f\x72\x67\x08\x31\x10\x78\x2d\x72\x74\x70\x2d" +
		"\x73\x65\x73\x73\x69\x6f\x6e\x2d\x69\x64\x33\x44\x38\x32\x37\x43" +
		"\x39\x42\x37\x32\x45\x33\x45\x39\x38\x34\x34\x43\x32\x30\x35\x32" +
		"\x33\x33\x35\x33\x45\x33\x41\x37\x42\x46\x00\x00"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPSDES, h.Type)
	sdes, err := rtcpSDESDecode(data[4:h.Len()], h)
	assert.Nil(t, err)
	assert.NotNil(t, sdes)
}

func TestRTCPDecodeSDESMultiItems(t *testing.T) {
	input := "\x81\xca\x00\x1e\x88\x54\xaa\x3d\x01\x3d\x34\x39\x36\x32\x38\x31" +
		"\x33\x42\x44\x46\x37\x30\x45\x45\x36\x34\x31\x34\x33\x33\x30\x36" +
		"\x32\x34\x37\x46\x46\x46\x43\x41\x31\x31\x40\x75\x6e\x69\x71\x75" +
		"\x65\x2e\x7a\x31\x41\x32\x37\x37\x30\x39\x45\x31\x31\x30\x39\x35" +
		"\x39\x44\x43\x2e\x6f\x72\x67\x08\x31\x10\x78\x2d\x72\x74\x70\x2d" +
		"\x73\x65\x73\x73\x69\x6f\x6e\x2d\x69\x64\x33\x44\x38\x32\x37\x43" +
		"\x39\x42\x37\x32\x45\x33\x45\x39\x38\x34\x34\x43\x32\x30\x35\x32" +
		"\x33\x33\x35\x33\x45\x33\x41\x37\x42\x46\x00\x00"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPSDES, h.Type)

	sdes, err := rtcpSDESDecode(data[4:h.Len()], h)
	assert.Nil(t, err)

	// source description report blocks
	assert.Equal(t, 1, len(sdes.Chunk))

	c := sdes.Chunk[0]

	assert.EqualValues(t, 2287249981, c.ID)

	assert.Equal(t, 2, len(c.Item))
	item := c.Item[0]

	assert.Equal(t, SDESCNAME, item.Type)
	assert.EqualValues(t, 61, item.Len)
	assert.Equal(t, "4962813BDF70EE64143306247FFFCA11@unique.z1A27709E110959DC.org",
		string(item.Text))

	item = c.Item[1]

	assert.Equal(t, SDESPRIV, item.Type)
	assert.EqualValues(t, 49, item.Len)
	assert.Equal(t, "\x10x-rtp-session-id3D827C9B72E3E9844C20523353E3A7BF",
		string(item.Text))
}

func TestRTCPDecodeBYE(t *testing.T) {
	input := "\x81\xcb\x00\x05\x12\x34\x56\x78\x0f\x73\x65\x73\x73\x69\x6f\x6e" +
		"\x20\x73\x74\x6f\x70\x70\x65\x64"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPBYE, h.Type)

	bye, err := rtcpBYEDecode(data[4:], h)
	assert.Nil(t, err)
	assert.NotNil(t, bye)

	assert.EqualValues(t, 305419896, bye.SCSRC[0])
	assert.EqualValues(t, 15, bye.RLen)
	assert.Equal(t, "session stopped", string(bye.Reason))

	input = "\x81\xcb\x00\x01\x22\x6a\x6a\xa1"
	data = []byte(input)
	h, err = rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPBYE, h.Type)

	bye, err = rtcpBYEDecode(data[4:], h)
	assert.Nil(t, err)
	assert.NotNil(t, bye)

	assert.EqualValues(t, 577399457, bye.SCSRC[0])
	assert.Zero(t, bye.RLen)
	assert.Zero(t, bye.Reason)
}

func TestRTCPDecodeAPP(t *testing.T) {
	input := "\x81\xcc\x00\x06\x3c\xab\xa3\xbc\x71\x74\x73\x69\x00\x00\x00\x00" +
		"\x00\x00\x00\x02\x61\x74\x00\x04\x00\x00\x00\x14"
	data := []byte(input)
	h, err := rtcpHeaderDecode(data)
	assert.Nil(t, err)
	assert.Equal(t, len(data), h.Len())
	assert.Equal(t, RTCPAPP, h.Type)

	app, err := rtcpAPPDecode(data[4:], h)
	assert.Nil(t, err)
	assert.NotNil(t, app)

	assert.EqualValues(t, 1017881532, app.SRC)
	assert.Equal(t, "qtsi", string(app.Name))
	assert.Equal(t,
		"\x00\x00\x00\x00\x00\x00\x00\x02\x61\x74\x00\x04\x00\x00\x00\x14",
		string(app.Data))
}

func TestRTCPDecodeSRSDES(t *testing.T) {
	pack := "\x81\xc8\x00\x0c\x88\x54\xaa\x3d\xce\x01\xd0\xe1\x9c\x28\xf5\xc3" +
		"\xaf\x12\x94\x7c\x00\x00\x07\xdd\x00\x05\x46\xa8\x70\x58\xb5\x5a" +
		"\x00\x00\x00\x01\x00\x00\xe6\x5d\x00\x00\x00\x28\x9c\x40\x02\x0c" +
		"\x00\x00\x9c\x6a" +
		"\x81\xca\x00\x1e\x88\x54\xaa\x3d\x01\x3d\x34\x39\x36\x32\x38\x31" +
		"\x33\x42\x44\x46\x37\x30\x45\x45\x36\x34\x31\x34\x33\x33\x30\x36" +
		"\x32\x34\x37\x46\x46\x46\x43\x41\x31\x31\x40\x75\x6e\x69\x71\x75" +
		"\x65\x2e\x7a\x31\x41\x32\x37\x37\x30\x39\x45\x31\x31\x30\x39\x35" +
		"\x39\x44\x43\x2e\x6f\x72\x67\x08\x31\x10\x78\x2d\x72\x74\x70\x2d" +
		"\x73\x65\x73\x73\x69\x6f\x6e\x2d\x69\x64\x33\x44\x38\x32\x37\x43" +
		"\x39\x42\x37\x32\x45\x33\x45\x39\x38\x34\x34\x43\x32\x30\x35\x32" +
		"\x33\x33\x35\x33\x45\x33\x41\x37\x42\x46\x00\x00"
	rtcp, err := RTCPDecode([]byte(pack))
	assert.Nil(t, err)
	assert.NotNil(t, rtcp)

	assert.Equal(t, 2, len(rtcp))

	// == first report
	assert.Equal(t, RTCPSR, rtcp[0].Type())
	sr := rtcp[0].(*RTCPSender)
	assert.EqualValues(t, 2287249981, sr.SSRC)
	assert.EqualValues(t, 3456225505, sr.NTPMSW)
	assert.EqualValues(t, 2619930051, sr.NTPLSW)
	assert.EqualValues(t, 2937230460, sr.RTPTime)
	assert.EqualValues(t, 2013, sr.PackSent)
	assert.EqualValues(t, 345768, sr.OctSent)
	// sender report blocks
	assert.Equal(t, 1, len(sr.RBlock))

	b := sr.RBlock[0]
	assert.EqualValues(t, 1884861786, b.SSRC)
	assert.EqualValues(t, 0, b.Fract)
	assert.EqualValues(t, 1, b.Lost)
	assert.EqualValues(t, 58973, b.SeqNum)
	assert.EqualValues(t, 40, b.Jitter)
	assert.EqualValues(t, 2621440524, b.LSR)
	assert.EqualValues(t, 40042, b.DLSR)

	// == second report
	assert.Equal(t, RTCPSDES, rtcp[1].Type())
	sdes := rtcp[1].(*RTCPSDesc)
	assert.Equal(t, 1, len(sdes.Chunk))
	c := sdes.Chunk[0]
	assert.EqualValues(t, 2287249981, c.ID)

	assert.Equal(t, 2, len(c.Item))

	item := c.Item[0]
	assert.Equal(t, SDESCNAME, item.Type)
	assert.EqualValues(t, 61, item.Len)
	assert.Equal(t, "4962813BDF70EE64143306247FFFCA11@unique.z1A27709E110959DC.org",
		string(item.Text))

	item = c.Item[1]
	assert.Equal(t, SDESPRIV, item.Type)
	assert.EqualValues(t, 49, item.Len)
	assert.Equal(t, "\x10x-rtp-session-id3D827C9B72E3E9844C20523353E3A7BF",
		string(item.Text))
}

func TestRTCPDecodeSrSdesBye(t *testing.T) {
	input := "\x80\xc9\x00\x01\x88\x54\xaa\x3d" +
		"\x81\xca\x00\x1e\x88\x54\xaa\x3d\x01\x3d\x34\x39\x36\x32\x38\x31" +
		"\x33\x42\x44\x46\x37\x30\x45\x45\x36\x34\x31\x34\x33\x33\x30\x36" +
		"\x32\x34\x37\x46\x46\x46\x43\x41\x31\x31\x40\x75\x6e\x69\x71\x75" +
		"\x65\x2e\x7a\x31\x41\x32\x37\x37\x30\x39\x45\x31\x31\x30\x39\x35" +
		"\x39\x44\x43\x2e\x6f\x72\x67\x08\x31\x10\x78\x2d\x72\x74\x70\x2d" +
		"\x73\x65\x73\x73\x69\x6f\x6e\x2d\x69\x64\x33\x44\x38\x32\x37\x43" +
		"\x39\x42\x37\x32\x45\x33\x45\x39\x38\x34\x34\x43\x32\x30\x35\x32" +
		"\x33\x33\x35\x33\x45\x33\x41\x37\x42\x46\x00\x00" +
		"\x81\xcb\x00\x01\x88\x54\xaa\x3d"
	rtcp, err := RTCPDecode([]byte(input))
	assert.Nil(t, err)
	assert.NotNil(t, rtcp)

	assert.Equal(t, 3, len(rtcp))
	assert.Equal(t, RTCPRR, rtcp[0].Type())
	assert.Equal(t, RTCPSDES, rtcp[1].Type())
	assert.Equal(t, RTCPBYE, rtcp[2].Type())

	// -- first packet receiver report
	rr := rtcp[0].(*RTCPReceiver)
	assert.EqualValues(t, 2287249981, rr.SSRC)

	// -- second packet source description
	sdes := rtcp[1].(*RTCPSDesc)
	assert.Equal(t, 1, len(sdes.Chunk))
	c := sdes.Chunk[0]
	assert.EqualValues(t, 2287249981, c.ID)

	assert.Equal(t, 2, len(c.Item))

	item := c.Item[0]
	assert.Equal(t, SDESCNAME, item.Type)
	assert.EqualValues(t, 61, item.Len)
	assert.Equal(t, "4962813BDF70EE64143306247FFFCA11@unique.z1A27709E110959DC.org",
		string(item.Text))

	item = c.Item[1]
	assert.Equal(t, SDESPRIV, item.Type)
	assert.EqualValues(t, 49, item.Len)
	assert.Equal(t, "\x10x-rtp-session-id3D827C9B72E3E9844C20523353E3A7BF",
		string(item.Text))

	// -- third packet BYE
	bye := rtcp[2].(*RTCPBye)
	assert.EqualValues(t, 2287249981, bye.SCSRC[0])
}

func TestRTCPDecodeSrSdesAppBye(t *testing.T) {
	input := "\x80\xc8\x00\x06\x3c\xab\xa3\xbc\xd7\xb9\xeb\xc5\x6a\xc0\x83\x11" +
		"\x64\x46\x70\xc7\x00\x00\x00\xc4\x00\x03\x02\x73" +
		"\x81\xca\x00\x06\x3c\xab\xa3\xbc\x01\x0e\x51\x54\x53\x53\x31\x34" +
		"\x31\x30\x32\x39\x37\x31\x35\x32\x00\x00\x00\x00" +
		"\x81\xcc\x00\x06\x3c\xab\xa3\xbc\x71\x74\x73\x69\x79\x03\xad\x01" +
		"\x00\x00\x00\x02\x61\x74\x00\x04\x00\x00\x00\x14" +
		"\x81\xcb\x00\x01\x3c\xab\xa3\xbc"
	rtcp, err := RTCPDecode([]byte(input))
	assert.Nil(t, err)
	assert.NotNil(t, rtcp)

	assert.Equal(t, 4, len(rtcp))

	assert.Equal(t, RTCPSR, rtcp[0].Type())
	sr := rtcp[0].(*RTCPSender)
	assert.EqualValues(t, 1017881532, sr.SSRC)

	assert.Equal(t, RTCPSDES, rtcp[1].Type())
	sdes := rtcp[1].(*RTCPSDesc)
	assert.Equal(t, 1, len(sdes.Chunk))
	c := sdes.Chunk[0]
	assert.EqualValues(t, 1017881532, c.ID)
	assert.Equal(t, 1, len(c.Item))
	assert.Equal(t, "QTSS1410297152", string(c.Item[0].Text))

	assert.Equal(t, RTCPAPP, rtcp[2].Type())
	app := rtcp[2].(*RTCPApp)
	assert.EqualValues(t, 1017881532, app.SRC)
	assert.Equal(t, "qtsi", string(app.Name))
	assert.Equal(t,
		"\x79\x03\xad\x01\x00\x00\x00\x02\x61\x74\x00\x04\x00\x00\x00\x14",
		string(app.Data))

	assert.Equal(t, RTCPBYE, rtcp[3].Type())
	bye := rtcp[3].(*RTCPBye)
	assert.EqualValues(t, 1017881532, bye.SCSRC[0])
}
