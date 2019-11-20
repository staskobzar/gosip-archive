package rtp

// RRBlock reception report block
type RRBlock struct {
	SSRC   uint32 // source identifier
	Fract  uint8  // fraction of packets lost since last R/RR packet was sent
	Lost   uint32 // (24 bits) cumulative number of packets lost
	SeqNum uint32 // extended highest sequence number received
	Jitter uint32 // interarrival jitter
	LSR    uint32 // last send report timestamp
	DLSR   uint32 // delay since last send report
}

// RTCPSender RTCP sender report packet structure
// RFC3550#6.4.1 SR: Sender Report RTCP Packet
type RTCPSender struct {
	// The first section, the header, is 8 octets long
	Ver     uint8  // version
	Pad     bool   // padding
	RRCount uint8  // reception report count
	PType   uint8  // packet type
	Len     uint16 // length
	SSRC    uint32 // synchronization source identifier
	// The second section, the sender information, is 20 octets long
	NTPTimestamp uint32    // time when report was sent
	RTPTimestamp uint32    // timestamp for inter-media synchronization for sources
	PackSent     uint32    // sender's packet count
	OctSent      uint32    // sender's octet count
	RRBlocks     []RRBlock // The third section contains zero or more reception report blocks
}
