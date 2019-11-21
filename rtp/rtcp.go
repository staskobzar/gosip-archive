package rtp

// RTCPType RTCP header type
type RTCPType uint8

// SDESType RTCP header source description type
type SDESType uint8

// RTCP packet type
const (
	RTCPSR   RTCPType = 200 // Sender Report
	RTCPRR            = 201 // Receiver Report
	RTCPSDES          = 202 // Source Description
	RTCPBYE           = 203 // Goodbye
	RTCPAPP           = 204 // Application-defined
)

// RTCP source description type
const (
	SDESEND   RTCPType = iota // End of list
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
		Ver     uint8    // version
		Pad     bool     // padding
		RRCount uint8    // reception report count
		PType   RTCPType // packet type
		Len     uint16   // length
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
		Hdr  RTCPHeader // The first section, the header, is 8 octets long
		SSRC uint32     // synchronization source identifier
		// The second section, the sender information, is 20 octets long
		NTPTimestamp uint32   // time when report was sent
		RTPTimestamp uint32   // timestamp for inter-media synchronization for sources
		PackSent     uint32   // sender's packet count
		OctSent      uint32   // sender's octet count
		RBlocks      []RBlock // The third section contains zero or more reception report blocks
	}

	// RTCPReceiver RTCP receiver report packet structure
	// RFC3550#6.4.2 RR: Receiver Report RTCP Packet
	RTCPReceiver struct {
		Hdr    RTCPHeader // RTCP header
		SSRC   uint32     // synchronization source identifier
		RBlock []RBlock   //  more reception report blocks
	}

	// RTCPSDesc RTCP source description
	// RFC3550#6.5 SDES: Source Description RTCP Packet
	RTCPSDesc struct {
		Hdr   RTCPHeader  // RTCP header
		Chunk []SDESChunk // SDES chunks array
	}

	// RTCPBye RTCP bye packet
	// RFC3550#6.6 BYE: Goodbye RTCP Packet
	RTCPBye struct {
		Hdr    RTCPHeader // RTCP header
		SCSRC  []uint32   // list of sources
		RLen   uint8      // optional reason length
		Reason []byte     // optional reason
	}

	// RTCPApp RTCP app packet
	// RFC3550#6.7 APP: Application-Defined RTCP Packet
	RTCPApp struct {
		Hdr  RTCPHeader // RTCP header
		SRC  uint32     // SSRC/CSRC
		Data []byte     // application-dependent data: variable length
	}
)
