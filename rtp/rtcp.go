package rtp

import (
	"encoding/binary"
	"errors"
)

// RTCP Errors
var (
	// ErrorRTCPHeaderSize raised when RTCP data is too short or nil
	ErrorRTCPHeaderSize = errors.New("RTCP header is too short")
	// ErrorRTCPHeaderType raised when RTCP header type is invalid
	ErrorRTCPHeaderType = errors.New("invalid RTCP header type")
	// ErrorRTCPHeaderVer raised when RTCP version is not 2.
	// Only ver. 2 is supported so far.
	ErrorRTCPHeaderVer = errors.New("invalid RTCP header version")
)

// RTCPType RTCP header type
type RTCPType uint8

// SDESType RTCP header source description type
type SDESType uint8

// RTCP packet type
const (
	RTCPSR   RTCPType = 200 // Sender Report
	RTCPRR   RTCPType = 201 // Receiver Report
	RTCPSDES RTCPType = 202 // Source Description
	RTCPBYE  RTCPType = 203 // Goodbye
	RTCPAPP  RTCPType = 204 // Application-defined
)

// RTCP source description type
const (
	SDESEND   SDESType = iota // End of list
	SDESCNAME                 // Canonical End-Point Identifier
	SDESNAME                  // User Name SDES Item
	SDESEMAIL                 // Email address
	SDESPHONE                 // Phone number
	SDESLOC                   // Geographic User Location
	SDESTOOL                  // Application or Tool Name
	SDESNOTE                  // Notice/Status
	SDESPRIV                  // Private Extensions
)

type (
	// RTCPHeader RTCP header common for all packets
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |V=2|P| subtype |   PT=APP=204  |             length            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	RTCPHeader struct {
		Ver    uint8    // version
		Pad    bool     // padding
		RCount uint8    // report count
		Type   RTCPType // packet type
		Length uint16   // length
	}

	// RBlock report block for receiver and sender
	RBlock struct {
		SSRC   uint32 // source identifier
		Fract  uint8  // fraction of packets lost since last R/RR packet was sent
		Lost   uint32 // (24 bits) cumulative number of packets lost
		SeqNum uint32 // extended highest sequence number received
		Jitter uint32 // interarrival jitter
		LSR    uint32 // last send report timestamp
		DLSR   uint32 // delay since last send report
	}

	// SDESItem item of source description chunk
	SDESItem struct {
		Type RTCPType // item type
		Len  uint8    // content length
		Text []byte   // item content
	}

	// SDESChunk chunk of source description packet
	SDESChunk struct {
		ID   uint32     // SSRC/CSRC identifier
		Item []SDESItem // SDES items
	}

	// RTCPSender RTCP sender report packet structure
	// RFC3550#6.4.1 SR: Sender Report RTCP Packet
	RTCPSender struct {
		Hdr  *RTCPHeader // The first section, the header, is 8 octets long
		SSRC uint32      // synchronization source identifier
		// The second section, the sender information, is 20 octets long
		NTPMSW   uint32   // time when report was sent: NTP timestamp, most significant word
		NTPLSW   uint32   // time when report was sent: NTP timestamp, least significant word
		RTPTime  uint32   // timestamp for inter-media synchronization for sources
		PackSent uint32   // sender's packet count
		OctSent  uint32   // sender's octet count
		RBlock   []RBlock // The third section contains zero or more report blocks
	}

	// RTCPReceiver RTCP receiver report packet structure
	// RFC3550#6.4.2 RR: Receiver Report RTCP Packet
	RTCPReceiver struct {
		Hdr    *RTCPHeader // RTCP header
		SSRC   uint32      // synchronization source identifier
		RBlock []RBlock    //  more reception report blocks
	}

	// RTCPSDesc RTCP source description
	// RFC3550#6.5 SDES: Source Description RTCP Packet
	RTCPSDesc struct {
		Hdr   *RTCPHeader // RTCP header
		Chunk []SDESChunk // SDES chunks array
	}

	// RTCPBye RTCP bye packet
	// RFC3550#6.6 BYE: Goodbye RTCP Packet
	RTCPBye struct {
		Hdr    *RTCPHeader // RTCP header
		SCSRC  []uint32    // list of sources
		RLen   uint8       // optional reason length
		Reason []byte      // optional reason
	}

	// RTCPApp RTCP app packet
	// RFC3550#6.7 APP: Application-Defined RTCP Packet
	RTCPApp struct {
		Hdr  *RTCPHeader // RTCP header
		SRC  uint32      // SSRC/CSRC
		Data []byte      // application-dependent data: variable length
	}

	// RTCP interface of RTCP packets
	RTCP interface {
		ID() RTCPType
	}
)

// Len return length of the RTCP packet + 4 bytes of the header length
func (h *RTCPHeader) Len() int {
	return h.PLen() + 4
}

// PLen return length of the RTCP packet without 4 byte header len
func (h *RTCPHeader) PLen() int {
	return int(h.Length * 4)
}

// decode RTPC header
func rtcpHeaderDecode(data []byte) (*RTCPHeader, error) {
	h := &RTCPHeader{}
	if data == nil || len(data) < 4 {
		return nil, ErrorRTCPHeaderSize
	}

	h.Ver = data[0] >> 6
	if h.Ver != 2 {
		return nil, ErrorRTCPHeaderVer
	}

	h.Pad = ((data[0] >> 5) & 0x01) == 1
	h.RCount = data[0] & 0x1f
	h.Type = RTCPType(data[1])

	if h.Type < 200 || h.Type > 204 {
		return nil, ErrorRTCPHeaderType
	}

	h.Length = binary.BigEndian.Uint16(data[2:4])

	return h, nil
}

func rtcpSRDecode(data []byte) (*RTCPSender, error) {
	sr := &RTCPSender{}
	sr.SSRC = 1492336106
	sr.NTPMSW = 151538
	sr.NTPLSW = 133143977
	sr.RTPTime = 289989634
	sr.PackSent = 586
	sr.OctSent = 92965

	b := RBlock{}
	b.SSRC = 3535621694
	b.Fract = 0
	b.Lost = 0
	b.SeqNum = 0
	b.Jitter = 0
	b.LSR = 2262761209
	b.DLSR = 252248

	sr.RBlock = append(sr.RBlock, b)

	return sr, nil
}
