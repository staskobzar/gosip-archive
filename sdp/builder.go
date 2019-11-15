package sdp

import (
	"bytes"
	"strconv"
	"time"
)

// NewMessage initiates new SDP Message
func NewMessage(host string) *Message {
	id := idFromNTP()
	msg := &Message{
		mediaIdx: -1,
		ver:      0,
		Origin: Origin{
			username: []byte{'-'},
			sessID:   id,
			sessVer:  id,
			netType:  []byte("IN"),
			addrType: []byte("IP4"),
			unicAddr: []byte(host),
		},
		subject: []byte{'-'},
	}

	return msg
}

// String SDP Message as string
func (m *Message) String() string {
	var b buffer

	b.compile(m)
	return b.String()
}

// SetSubject session subject s=* field set
func (m *Message) SetSubject(subj string) {
	m.subject = []byte(subj)
}

// SetInfo session info i=* field set
func (m *Message) SetInfo(info string) {
	m.info = []byte(info)
}

// SetURI session uri u=* field set
func (m *Message) SetURI(uri string) {
	m.uri = []byte(uri)
}

// private methods
func idFromNTP() []byte {
	n := time.Now().Unix()
	s := strconv.FormatInt(n, 10)
	return []byte(s)
}

type buffer struct {
	bytes.Buffer
}

// compile SDP message to buffer
func (b *buffer) compile(m *Message) {
	// Session description
	b.kv('v', []byte{m.ver + 0x30}) // v=  (protocol version)
	b.o(m)                          // o=  (originator and session identifier)
	b.kv('s', m.subject)            // s=  (session name)
	b.kv('i', m.info)               // i=* (session information)
	b.kv('u', m.uri)                // u=* (URI of description)
	// e=* (email address)
	// p=* (phone number)
	// c=* (connection information -- not required if included in all media)
	// b=* (zero or more bandwidth information lines)

	// One or more time descriptions ("t=" and "r=" lines; see below)
	// Time description
	// t=  (time the session is active)
	// r=* (zero or more repeat times)
	b.t(m)
	// z=* (time zone adjustments)
	// k=* (encryption key)
	// a=* (zero or more session attribute lines)
	// Zero or more media descriptions

	// Media description, if present
	// m=  (media name and transport address)
	// i=* (media title)
	// c=* (connection information -- optional if included at
	//      session level)
	// b=* (zero or more bandwidth information lines)
	// k=* (encryption key)
	// a=* (zero or more media attribute lines)
}

// write key/value field
func (b *buffer) kv(key byte, val []byte) {
	if len(val) == 0 {
		return
	}
	b.WriteByte(key)
	b.WriteByte('=')
	b.Write(val)
	b.crlf()
}

// origin o=
func (b *buffer) o(m *Message) {
	b.WriteString("o=")
	b.writeWSpace(m.Origin.username)
	b.writeWSpace(m.Origin.sessID)
	b.writeWSpace(m.Origin.sessVer)
	b.writeWSpace(m.Origin.netType)
	b.writeWSpace(m.Origin.addrType)
	b.Write(m.Origin.unicAddr)
	b.crlf()
}

// timing t=
func (b *buffer) t(m *Message) {
	if len(m.Time) == 0 {
		b.kv('t', []byte("0 0"))
		return
	}

	for _, t := range m.Time {
		b.WriteString("t=")
		b.writeWSpace(t.start)
		b.Write(t.stop)
		b.crlf()
	}
}

// write CRLF
func (b *buffer) crlf() {
	b.WriteString("\r\n")
}

func (b *buffer) writeWSpace(data []byte) {
	b.Write(data)
	b.WriteByte(' ')
}
