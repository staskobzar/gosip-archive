package rtp

import (
	"encoding/binary"
	"errors"
)

// ErrorRTPDecode error raised when failed to decode RTP packet
var ErrorRTPDecode = errors.New("RTP Packet decode failed")

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
	Len       int      // RTP header length. Used to start payload position
}

// Decode reads RTP packet bytes stream to Header struct
func Decode(data []byte) (*Header, error) {

	if len(data) < 12 {
		return nil, ErrorRTPDecode
	}

	h := &Header{}

	h.Ver = data[0] >> 6
	h.Pad = ((data[0] >> 5) & 0x01) == 1
	h.Ext = ((data[0] >> 4) & 0x01) == 1
	h.CCount = uint8(data[0] & 0x0f)
	h.Marker = ((data[1] >> 7) & 0x01) == 1
	h.PType = uint8(data[1] & 0x7f)
	h.SeqNum = binary.BigEndian.Uint16(data[2:4])
	h.Timestamp = binary.BigEndian.Uint32(data[4:8])
	h.SSRC = binary.BigEndian.Uint32(data[8:12])

	h.Len = 12

	return h, nil
}

// Version RTP header version feild
func (h *Header) Version() int { return int(h.Ver) }

// CSRCCount RTP header CSRC count feild
func (h *Header) CSRCCount() int { return int(h.CCount) }

// PayloadType RTP header payload type feild
func (h *Header) PayloadType() int { return int(h.PType) }

// SequenceNumber RTP header sequence number feild
func (h *Header) SequenceNumber() int { return int(h.SeqNum) }
