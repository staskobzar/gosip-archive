package rtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRTPDecode(t *testing.T) {
	str := "\x80\x89\x11\x09\xb2\x8c\xa8\xf7\xd5\x23\x63\xd7\xfa\xfa\xfa\xfa" +
		"\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa" +
		"\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa" +
		"\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xf7\xf7\xf7\xf7\xf7\xf7\xf7\xf8" +
		"\xf7\xfa\xf7\xf8\xf8\xfa\xfa\xf7\xf7\xf8\xf7\xfa\xf8\xf7\xfa\xf8" +
		"\xf7\xfa\xf7\xf8\xf8\xfa\xdb\xf0\xf8\xf8\xf8\xf8\xfa\xdb\xf1\xf8" +
		"\xf8\xfa\xfa\xf8\xde\xf3\xfa\xf8\xf8\xfa\xfa\xde\xf0\xfa\xfa\xf8" +
		"\xf8\xfa\xdb\xf1\xfa\xfa\xf8\xf8\xfa\xdc\xf2\xfa\xf8\xf8\xfa\xfa" +
		"\xde\xf0\xfa\xfa\xf8\xf8\xfa\xd8\xf3\xfa\xf8\xf8\xfa\xde\xf3\xfa" +
		"\xf8\xf8\xfa\xde\xf3\xfa\xf8\xf8\xfa\xde\xf2\xfa\xf8\xf8\xfa\xde" +
		"\xf2\xfa\xf8\xf8\xfa\xde\xf2\xfa\xf8\xf8\xfa\xde"

	data := []byte(str)
	rtp := NewHeader()
	err := rtp.Decode(data)
	assert.Nil(t, err)

	assert.Equal(t, 2, rtp.Version())
	assert.False(t, rtp.Pad)
	assert.False(t, rtp.Ext)
	assert.Equal(t, 0, rtp.CSRCCount())
	assert.True(t, rtp.Marker)
	assert.Equal(t, 9, rtp.PayloadType())
	assert.Equal(t, 4361, rtp.SequenceNumber())
	assert.Equal(t, uint32(2995562743), rtp.Timestamp)
	assert.Equal(t, uint32(3575866327), rtp.SSRC)

	assert.Equal(t, 12, rtp.Len())
	assert.Equal(t, 160, len(data[rtp.Len():]))

	err = rtp.Decode([]byte{0x80, 0x81, 0x82})
	assert.NotNil(t, err)
}

func TestRTPEncode(t *testing.T) {
	bin := []byte{0x80, 0x00, 0x92, 0xe8, 0x00, 0x00, 0x08, 0xc0, 0x34, 0x3d, 0xa9, 0x9b}

	hdr := NewHeader()
	hdr.SetSeqNum(37608)
	hdr.SetTimestamp(2240)
	hdr.SetSSRC(0x343da99b)
	enc := hdr.Encode()

	assert.Equal(t, bin, enc)
}

func TestRTPCSRC(t *testing.T) {
	hdr := NewHeader()
	hdr.SetSeqNum(235)
	hdr.SetTimestamp(2995562743)
	hdr.SetSSRC(876456347)

	hdr.SetPadding()
	hdr.SetExtension()
	hdr.SetMarker()

	hdr.SetPayloadType(9)

	data := hdr.Encode()

	rtp := NewHeader()
	err := rtp.Decode(data)
	assert.Nil(t, err)
	assert.Equal(t, 2, rtp.Version())
	assert.True(t, rtp.Pad)
	assert.True(t, rtp.Ext)
	assert.Equal(t, 0, rtp.CSRCCount())
	assert.True(t, rtp.Marker)
	assert.Equal(t, 9, rtp.PayloadType())
	assert.Equal(t, 235, rtp.SequenceNumber())
	assert.Equal(t, uint32(2995562743), rtp.Timestamp)
	assert.Equal(t, uint32(876456347), rtp.SSRC)
}

// TODO: CSRC identifiers
// TODO: RTCPRead
