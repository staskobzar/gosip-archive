package sdp

import "strconv"

// ErrorSDPParsing returned when failed to parse SDP message
var ErrorSDPParsing = errorNew("Error parding SDP message")

// Message SDP message structure
type Message struct {
	ver     byte
	subject []byte
	Origin  Origin
	Conn    Conn
	Media   Medias
}

// Version SDP message version field
func (m *Message) Version() int {
	return int(m.ver - 0x30)
}

// Subject SDP message subject field
func (m *Message) Subject() string {
	return string(m.subject)
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

// Conn SDP connection data field (RFC4566 #5.7)
type Conn struct {
	netType  []byte
	addrType []byte
	address  []byte
}

// NetType SDP connection data field net type
func (c Conn) NetType() string {
	return string(c.netType)
}

// AddrType SDP connection data field address type
func (c Conn) AddrType() string {
	return string(c.addrType)
}

// Address SDP connection data field unicast address
func (c Conn) Address() string {
	return string(c.address)
}

// Medias list of session medias
type Medias []Media

// Media media description of SDP session
type Media struct {
}
