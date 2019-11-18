package rtp

type RTPHeader struct {
	version     uint8
	padding     bool
	extension   bool
	ccount      uint8 // CSRC Count
	marker      bool
	payloadType uint8
	seqNum      uint16
	timestamp   uint32
	ssrc        uint32
	csrc        []uint32
}

// Decode reads RTP packet bytes stream to RTPHeader struct
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
func Decode(data []byte) (*RTPHeader, error) {
	h := &RTPHeader{}

	h.version = data[0] >> 6
	h.padding = ((data[0] >> 5) & 0x01) == 1

	return h, nil
}

// Version RTP header version
func (h *RTPHeader) Version() int {
	return int(h.version)
}

// Padding RTP header padding
func (h *RTPHeader) Padding() bool {
	return h.padding
}
