package sdp

import (
	"bytes"
	"strconv"
)

// ErrorSDPParsing returned when failed to parse SDP message
var ErrorSDPParsing = errorNew("Error parsing SDP message")

// Message SDP message structure
type Message struct {
	mediaIdx  int
	ver       byte
	Origin    Origin
	subject   []byte
	info      []byte
	uri       []byte
	Email     [][]byte
	Phone     [][]byte
	Conn      Conn
	BandWidth []BandWidth
	Time      []TimeDesc
	tzones    []byte
	encKey    []byte
	Attr      []Attribute
	Medias    Medias
}

// -- private methods

func (m *Message) isSessCtx() bool {
	return m.mediaIdx == -1
}

func (m *Message) setInfo(data []byte) {
	if m.isSessCtx() {
		m.info = data
	} else {
		i := len(m.Medias) - 1
		m.Medias[i].info = data
	}
}

func (m *Message) setConnNetType(data []byte) {
	if m.isSessCtx() {
		m.Conn.netType = data
	} else {
		i := len(m.Medias) - 1
		m.Medias[i].Conn.netType = data
	}
}

func (m *Message) setConnAddrType(data []byte) {
	if m.isSessCtx() {
		m.Conn.addrType = data
	} else {
		i := len(m.Medias) - 1
		m.Medias[i].Conn.addrType = data
	}
}

func (m *Message) setConnAddress(data []byte) {
	if m.isSessCtx() {
		m.Conn.address = data
	} else {
		i := len(m.Medias) - 1
		m.Medias[i].Conn.address = data
	}
}

func (m *Message) setMedia() {
	if m.isSessCtx() {
		m.Medias = make(Medias, 1, 4)
	} else {
		m.Medias = append(m.Medias, Media{})
	}
	m.mediaIdx++
}

func (m *Message) setAttrKey(data []byte) {
	if m.isSessCtx() {
		m.Attr = append(m.Attr, Attribute{})
		i := len(m.Attr) - 1
		m.Attr[i].key = data
	} else {
		m.Medias[m.mediaIdx].Attr = append(m.Medias[m.mediaIdx].Attr, Attribute{})
		i := len(m.Medias[m.mediaIdx].Attr) - 1
		m.Medias[m.mediaIdx].Attr[i].key = data
	}
}

func (m *Message) setAttrValue(data []byte) {
	if m.isSessCtx() {
		i := len(m.Attr) - 1
		m.Attr[i].value = data
	} else {
		i := len(m.Medias[m.mediaIdx].Attr) - 1
		m.Medias[m.mediaIdx].Attr[i].value = data
	}
}

func (m *Message) setAttrFlag(data []byte) {
	if m.isSessCtx() {
		m.Attr = append(m.Attr, Attribute{})
		i := len(m.Attr) - 1
		m.Attr[i].flag = data
		m.Attr[i].isFlag = true
	} else {
		m.Medias[m.mediaIdx].Attr = append(m.Medias[m.mediaIdx].Attr, Attribute{})
		i := len(m.Medias[m.mediaIdx].Attr) - 1
		m.Medias[m.mediaIdx].Attr[i].flag = data
		m.Medias[m.mediaIdx].Attr[i].isFlag = true
	}
}

func (m *Message) setStartTime(data []byte) {
	m.Time = append(m.Time, TimeDesc{start: data})
}

func (m *Message) setStopTime(data []byte) {
	i := len(m.Time) - 1
	m.Time[i].stop = data
}

func (m *Message) setRepeatField(data []byte) {
	i := len(m.Time) - 1
	m.Time[i].Repeat = append(m.Time[i].Repeat, data)
}

func (m *Message) setBandwidth(data []byte) {
	if m.isSessCtx() {
		m.BandWidth = append(m.BandWidth, BandWidth{bt: data})
	} else {
		i := len(m.Medias) - 1
		m.Medias[i].BandWidth = append(m.Medias[i].BandWidth, BandWidth{bt: data})
	}
}

func (m *Message) setBwidthValue(data []byte) {
	if m.isSessCtx() {
		i := len(m.BandWidth) - 1
		m.BandWidth[i].bw = data
	} else {
		i := len(m.Medias) - 1
		j := len(m.Medias[i].BandWidth) - 1
		m.Medias[i].BandWidth[j].bw = data
	}
}

func (m *Message) setEncKey(data []byte) {
	if m.isSessCtx() {
		m.encKey = data
	} else {
		i := len(m.Medias) - 1
		m.Medias[i].encKey = data
	}
}

func byteToInt(data []byte) int {
	num, err := strconv.Atoi(string(data))
	if err != nil {
		return -1
	}
	return num
}

// -- public methods

// Version SDP message version field
func (m *Message) Version() int {
	return int(m.ver - 0x30)
}

// Subject SDP message subject field
func (m *Message) Subject() string {
	return string(bytes.TrimSpace(m.subject))
}

// Info SDP message session information field
func (m *Message) Info() string {
	return string(bytes.TrimSpace(m.info))
}

// UriString SDP message session uri field as string
func (m *Message) UriString() string {
	return string(bytes.TrimSpace(m.uri))
}

// TimeZones SDP message session time zones adjust field as string
func (m *Message) TimeZones() string {
	return string(bytes.TrimSpace(m.tzones))
}

// EncKey SDP message session encryption key value
func (m *Message) EncKey() string {
	return string(bytes.TrimSpace(m.encKey))
}

// AddMedia add media to SDP Session
func (m *Message) AddMedia(media Media) {
	m.Medias = append(m.Medias, media)
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
	return byteToInt(o.sessID)
}

// SessionVer SDP origin field session version
func (o Origin) SessionVer() int {
	return byteToInt(o.sessVer)
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

// BandWidth information structure
type BandWidth struct {
	bt []byte // type
	bw []byte // bandwidth
}

// Type bandwidth field type
func (b BandWidth) Type() string {
	return string(b.bt)
}

// BW bandwidth field value
func (b BandWidth) BW() int {
	return byteToInt(b.bw)
}

// TimeDesc time description structure that contains time and repeat time fields
type TimeDesc struct {
	start  []byte
	stop   []byte
	Repeat [][]byte
}

// StartTime time description field
func (t TimeDesc) StartTime() int {
	return byteToInt(t.start)
}

// StopTime time description field
func (t TimeDesc) StopTime() int {
	return byteToInt(t.stop)
}

// Medias list of session medias
type Medias []Media

// Media media description of SDP session
type Media struct {
	mtype     []byte
	port      []byte
	nport     []byte
	proto     []byte
	fmt       []byte
	info      []byte
	Conn      Conn
	BandWidth []BandWidth
	encKey    []byte
	Attr      []Attribute
}

// Type SDP media field type
func (m Media) Type() string {
	return string(m.mtype)
}

// Port SDP media field port
func (m Media) Port() int {
	return byteToInt(m.port)
}

// NumPort SDP media field ports number
func (m Media) NumPort() int {
	if n := byteToInt(m.nport); n >= 0 {
		return n
	}
	return 0
}

// Proto SDP media field protocol
func (m Media) Proto() string {
	return string(m.proto)
}

// Fmt SDP media field formats list
func (m Media) Fmt() string {
	return string(bytes.TrimSpace(m.fmt))
}

// EncKey SDP message media encryption key value
func (m Media) EncKey() string {
	return string(bytes.TrimSpace(m.encKey))
}

// Attribute SDP field
type Attribute struct {
	isFlag bool
	key    []byte
	value  []byte
	flag   []byte
}

// IsFlag returns true if attribute is flag (a=sendonly)
func (a Attribute) IsFlag() bool { return a.isFlag }

// Key attribute key (a=key:value)
func (a Attribute) Key() string { return string(a.key) }

// Value attribute value (a=key:value)
func (a Attribute) Value() string { return string(a.value) }

// Flag attribute (a=flag)
func (a Attribute) Flag() string { return string(a.flag) }
