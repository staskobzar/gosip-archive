package rtp

import (
	"encoding/binary"
	"errors"
)

const minHeaderLen = 12

// ErrorRTPDecode error raised when failed to decode RTP packet
var ErrorRTPDecode = errors.New("RTP Packet decode failed")

// ErrorRTPHeaderCSRC error raised when CSRC values number overflows
var ErrorRTPHeaderCSRC = errors.New("Overflow number of CSRC values")

// Header RTP header structure as defined in RFC 3550
/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           timestamp                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           synchronization source (SSRC) identifier            |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
   |            contributing source (CSRC) identifiers             |
   |                             ....                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type Header struct {
	Ver       uint8    // version
	Pad       bool     // padding
	Ext       bool     // extension
	CCount    uint8    // CSRC Count
	Marker    bool     // marker definded by profile
	PType     uint8    // payload type
	SeqNum    uint16   // sequence number
	Timestamp uint32   // sampling timestamp
	SSRC      uint32   // synchronization source
	CSRC      []uint32 // 0 to 15 of contributing sources
}

// NewHeader initiates new Header
func NewHeader() *Header {
	return &Header{Ver: 2}
}

// Decode reads RTP packet bytes stream to Header struct
func (h *Header) Decode(data []byte) error {

	if len(data) < minHeaderLen {
		return ErrorRTPDecode
	}

	h.Ver = data[0] >> 6
	h.Pad = ((data[0] >> 5) & 0x01) == 1
	h.Ext = ((data[0] >> 4) & 0x01) == 1
	h.CCount = uint8(data[0] & 0x0f)
	h.Marker = ((data[1] >> 7) & 0x01) == 1
	h.PType = uint8(data[1] & 0x7f)
	h.SeqNum = binary.BigEndian.Uint16(data[2:4])
	h.Timestamp = binary.BigEndian.Uint32(data[4:8])
	h.SSRC = binary.BigEndian.Uint32(data[8:12])

	for i := 0; i < int(h.CCount); i++ {
		p := 12 + i*4
		l := p + 4
		h.CSRC = append(h.CSRC, binary.BigEndian.Uint32(data[p:l]))
	}

	return nil
}

// Encode RTP header to byte array
func (h *Header) Encode() []byte {
	buf := make([]byte, minHeaderLen+(int(h.CCount)*4))

	b2i := func(v bool) byte {
		if v {
			return 1
		}
		return 0
	}

	// first byte
	buf[0] = (h.Ver & 0x03) << 6
	buf[0] |= (b2i(h.Pad) & 0x01) << 5
	buf[0] |= (b2i(h.Ext) & 0x01) << 4
	buf[0] |= (h.CCount & 0x0f)

	// second byte
	buf[1] = (b2i(h.Marker) & 1) << 7
	buf[1] |= (h.PType & 0x7f)

	binary.BigEndian.PutUint16(buf[2:], h.SeqNum)
	binary.BigEndian.PutUint32(buf[4:], h.Timestamp)
	binary.BigEndian.PutUint32(buf[8:], h.SSRC)

	for i := 0; i < int(h.CCount); i++ {
		p := 12 + (i * 4)
		binary.BigEndian.PutUint32(buf[p:], h.CSRC[i])
	}
	return buf
}

// Version RTP header version feild
func (h *Header) Version() int { return int(h.Ver) }

// CSRCCount RTP header CSRC count feild
func (h *Header) CSRCCount() int { return int(h.CCount) }

// PayloadType RTP header payload type feild
func (h *Header) PayloadType() int { return int(h.PType) }

// SequenceNumber RTP header sequence number feild
func (h *Header) SequenceNumber() int { return int(h.SeqNum) }

// Len RTP header sequence number feild
func (h *Header) Len() int { return minHeaderLen + (int(h.CCount) * 4) }

// SetSeqNum set sequence number of the header
func (h *Header) SetSeqNum(num int) {
	h.SeqNum = uint16(num)
}

// SetTimestamp set header timestamp
func (h *Header) SetTimestamp(tstamp int) {
	h.Timestamp = uint32(tstamp)
}

// SetPayloadType set header payload type
func (h *Header) SetPayloadType(payload int) {
	h.PType = uint8(payload)
}

// SetSSRC set header timestamp
func (h *Header) SetSSRC(tstamp int) {
	h.SSRC = uint32(tstamp)
}

// SetPadding set header padding field to True
func (h *Header) SetPadding() { h.Pad = true }

// SetExtension set header extention field to True
func (h *Header) SetExtension() { h.Ext = true }

// SetMarker set header marker field to True
func (h *Header) SetMarker() { h.Marker = true }

// PushCSRC add item to CSRC stack
func (h *Header) PushCSRC(csrc int) error {
	if h.CCount > 15 {
		return ErrorRTPHeaderCSRC
	}
	h.CSRC = append(h.CSRC, uint32(csrc))
	h.CCount++
	return nil
}
