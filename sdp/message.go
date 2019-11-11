package sdp

import "strconv"

// ErrorSDPParsing returned when failed to parse SDP message
var ErrorSDPParsing = errorNew("Error parding SDP message")

// Message SDP message structure
type Message struct {
	ver    byte
	Origin Origin
}

// Version SDP message version
func (m *Message) Version() int {
	return int(m.ver - 0x30)
}

// Origin SDP origin field (RFC4566 #5.2)
type Origin struct {
	username []byte
	sessID   []byte
	sessVer  []byte
	netType  []byte
	addrType []byte
	unicAddr []byte
}

// Username SDP origin field username
func (o Origin) Username() string {
	return string(o.username)
}

// SessionID SDP origin field session id
func (o Origin) SessionID() int {
	id, err := strconv.Atoi(string(o.sessID))
	if err != nil {
		return -1
	}
	return id
}

// SessionVer SDP origin field session version
func (o Origin) SessionVer() int {
	ver, err := strconv.Atoi(string(o.sessVer))
	if err != nil {
		return -1
	}
	return ver
}

// NetType SDP origin field net type
func (o Origin) NetType() string {
	return string(o.netType)
}

// AddrType SDP origin field address type
func (o Origin) AddrType() string {
	return string(o.addrType)
}

// UnicastAddr SDP origin field unicast address
func (o Origin) UnicastAddr() string {
	return string(o.unicAddr)
}
