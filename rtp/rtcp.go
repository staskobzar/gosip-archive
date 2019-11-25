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
	// ErrorRTCPHeaderLen raised when RTCP packet header length is invalid
	ErrorRTCPHeaderLen = errors.New("invalid RTCP header length")
	// ErrorRTCPSDES raised when RTCP packet SDES has problem
	ErrorRTCPSDES = errors.New("invalid SDES packet")
	// ErrorRTCPBye raised when RTCP packet BYE has problem
	ErrorRTCPBye = errors.New("invalid BYE packet")
	// ErrorRTCPApp raised when RTCP packet APP has problem
	ErrorRTCPApp = errors.New("invalid APP packet")
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
		Type SDESType // item type
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
		Name []byte      // 4 bytes ASCII name
		Data []byte      // application-dependent data: variable length
	}

	// RTCPReport interface of RTCP packets
	RTCPReport interface {
		Type() RTCPType
	}
)

// Type RTCP sender report interface method
func (r RTCPSender) Type() RTCPType {
	return r.Hdr.Type
}

// Type RTCP receiver report interface method
func (r RTCPReceiver) Type() RTCPType {
	return r.Hdr.Type
}

// Type RTCP SDES report interface method
func (r RTCPSDesc) Type() RTCPType {
	return r.Hdr.Type
}

// Type RTCP Bye report interface method
func (r RTCPBye) Type() RTCPType {
	return r.Hdr.Type
}

// Type RTCP App report interface method
func (r RTCPApp) Type() RTCPType {
	return r.Hdr.Type
}

// RTCPDecode decodes RTCP packet to the list of RTCP reports
func RTCPDecode(data []byte) ([]RTCPReport, error) {
	reports := make([]RTCPReport, 0, 2)

	for p := 0; p < len(data); {
		var rprt RTCPReport
		var err error
		hdr, err := rtcpHeaderDecode(data[p:])

		if err != nil {
			return nil, err
		}
		if len(data[p:]) < hdr.Len() {
			return nil, ErrorRTCPHeaderLen
		}

		p += 4
		switch hdr.Type {
		case RTCPSR:
			rprt, err = rtcpSRDecode(data[p:], hdr)
		case RTCPRR:
			rprt, err = rtcpRRDecode(data[p:], hdr)
		case RTCPSDES:
			rprt, err = rtcpSDESDecode(data[p:], hdr)
		case RTCPBYE:
			rprt, err = rtcpBYEDecode(data[p:], hdr)
		case RTCPAPP:
			rprt, err = rtcpAPPDecode(data[p:], hdr)
		default:
			return nil, ErrorRTCPHeaderType
		}

		if err != nil {
			return nil, err
		}

		reports = append(reports, rprt)
		p += hdr.PLen()
	}
	return reports, nil
}

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

// decode sender report
func rtcpSRDecode(data []byte, hdr *RTCPHeader) (*RTCPSender, error) {
	sr := &RTCPSender{Hdr: hdr}
	sr.SSRC = binary.BigEndian.Uint32(data[:])
	sr.NTPMSW = binary.BigEndian.Uint32(data[4:])
	sr.NTPLSW = binary.BigEndian.Uint32(data[8:])
	sr.RTPTime = binary.BigEndian.Uint32(data[12:])
	sr.PackSent = binary.BigEndian.Uint32(data[16:])
	sr.OctSent = binary.BigEndian.Uint32(data[20:])

	for p := 24; p < hdr.PLen(); p += 24 {
		if len(data) < p+24 {
			return nil, errors.New("invalid SR block")
		}
		b := RBlock{}
		b.SSRC = binary.BigEndian.Uint32(data[p:])
		lost := binary.BigEndian.Uint32(data[p+4:])
		b.Fract = data[p+4]
		b.Lost = lost & 0x00ffffff
		b.SeqNum = binary.BigEndian.Uint32(data[p+8:])
		b.Jitter = binary.BigEndian.Uint32(data[p+12:])
		b.LSR = binary.BigEndian.Uint32(data[p+16:])
		b.DLSR = binary.BigEndian.Uint32(data[p+20:])

		sr.RBlock = append(sr.RBlock, b)
	}

	return sr, nil
}

// receiver sender report
func rtcpRRDecode(data []byte, hdr *RTCPHeader) (*RTCPReceiver, error) {
	rr := &RTCPReceiver{Hdr: hdr}
	rr.SSRC = binary.BigEndian.Uint32(data[:])

	for p := 4; p < hdr.PLen(); p += 24 {
		if hdr.PLen() < p+24 {
			return nil, errors.New("invalid RR block")
		}
		b := RBlock{}
		b.SSRC = binary.BigEndian.Uint32(data[p:])
		lost := binary.BigEndian.Uint32(data[p+4:])
		b.Fract = data[p+4]
		b.Lost = lost & 0x00ffffff
		b.SeqNum = binary.BigEndian.Uint32(data[p+8:])
		b.Jitter = binary.BigEndian.Uint32(data[p+12:])
		b.LSR = binary.BigEndian.Uint32(data[p+16:])
		b.DLSR = binary.BigEndian.Uint32(data[p+20:])

		rr.RBlock = append(rr.RBlock, b)
	}

	return rr, nil
}

// receiver sender report
func rtcpSDESDecode(data []byte, hdr *RTCPHeader) (*RTCPSDesc, error) {
	sdes := &RTCPSDesc{Hdr: hdr}

	if hdr.PLen() == 0 || len(data[:hdr.PLen()]) == 0 {
		return sdes, nil
	}

	// read SDES chunks
	p := 0
	for {
		c := SDESChunk{}
		if c.ID, p = readUint32(data[:hdr.PLen()], p); p == -1 {
			break
		}

		// 5.6 ... A chunk with zero items (four null octets) is valid but useless...
		if c.ID == 0 {
			break
		}

		for {
			if hdr.Len() < p+2 {
				return nil, ErrorRTCPSDES
			}
			item := SDESItem{}
			item.Type = SDESType(data[p])
			if item.Type == SDESEND {
				break
			}
			p++

			item.Len = data[p]
			p++

			l := int(item.Len)
			if hdr.Len() < p+l {
				return nil, ErrorRTCPSDES
			}
			item.Text = data[p : p+l]

			p += l
			c.Item = append(c.Item, item)
		}

		sdes.Chunk = append(sdes.Chunk, c)
		if p >= hdr.PLen() {
			break
		}
	}

	return sdes, nil
}

// bye report
func rtcpBYEDecode(data []byte, hdr *RTCPHeader) (*RTCPBye, error) {
	bye := &RTCPBye{Hdr: hdr}

	p := 0
	for i := 0; i < int(hdr.RCount); i++ {
		p = 4 * i
		if hdr.PLen() < p {
			return nil, ErrorRTCPBye
		}
		bye.SCSRC = append(bye.SCSRC, binary.BigEndian.Uint32(data[p:]))
	}
	p += 4 // shift last uint32 extract last position
	if hdr.PLen() <= p {
		return bye, nil
	}
	// extract optional data
	bye.RLen = data[p]
	bye.Reason = data[p+1:]

	return bye, nil
}

// bye report
func rtcpAPPDecode(data []byte, hdr *RTCPHeader) (*RTCPApp, error) {
	app := &RTCPApp{Hdr: hdr}
	p := 0
	if app.SRC, p = readUint32(data, p); p == -1 {
		return nil, ErrorRTCPApp
	}
	app.Name = data[p : p+4]
	app.Data = data[p+4 : hdr.PLen()]
	return app, nil
}

func readUint32(data []byte, p int) (uint32, int) {
	if len(data) < p+4 {
		return 0, -1
	}
	return binary.BigEndian.Uint32(data[p:]), p + 4
}
