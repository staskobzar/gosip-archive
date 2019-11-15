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
		ver:      '0',
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

// SetEmail session email e=* fields set
func (m *Message) SetEmail(email string) {
	m.Email = append(m.Email, []byte(email))
}

// SetPhone session phone p=* fields set
func (m *Message) SetPhone(phone string) {
	m.Phone = append(m.Phone, []byte(phone))
}

// SetSessionConn session connection c=* fields set
func (m *Message) SetSessionConn(addr string) {
	m.Conn = Conn{
		netType:  []byte("IN"),
		addrType: []byte("IP4"),
		address:  []byte(addr),
	}
}

// SetBandWidth session bandwidth b=* fields set
func (m *Message) SetBandWidth(bwtype string, bandwidth int) {
	m.BandWidth = append(m.BandWidth, BandWidth{
		bt: []byte(bwtype),
		bw: []byte(strconv.FormatInt(int64(bandwidth), 10)),
	})
}

// SetTime session time fields set t=*, r=*
func (m *Message) SetTime(start, stop int64, repeat [][]byte) {
	m.Time = append(m.Time, TimeDesc{
		start:  []byte(strconv.FormatInt(start, 10)),
		stop:   []byte(strconv.FormatInt(stop, 10)),
		Repeat: repeat,
	})
}

// SetZone session zone adjustment fields set z=*
func (m *Message) SetZone(zone string) {
	m.tzones = []byte(zone)
}

// SetEncKey session encryption key fields set k=*
func (m *Message) SetEncKey(value string) {
	m.encKey = []byte(value)
}

// SetSessAttr session attribute key:value fields set a=key:value
func (m *Message) SetSessAttr(key, value string) {
	m.Attr = append(m.Attr, Attribute{
		isFlag: false,
		key:    []byte(key),
		value:  []byte(value),
	})
}

// SetSessAttrFlag session attribute flag fields set a=flagname
func (m *Message) SetSessAttrFlag(value string) {
	m.Attr = append(m.Attr, Attribute{
		isFlag: true,
		flag:   []byte(value),
	})
}

// NewMedia creates new media structure that can be added to SDP session
// mediaType "audio" or "video"
// media port, proto (ex.: RTP/AVP), fmt is a list of formats like "0 9 97"
func NewMedia(mediaType string, port int, proto, fmt string) Media {
	return Media{
		mtype: []byte(mediaType),
		port:  []byte(strconv.FormatInt(int64(port), 10)),
		proto: []byte(proto),
		fmt:   []byte(fmt),
	}
}

// SetInfo media info i=* field set
func (m *Media) SetInfo(info string) {
	m.info = []byte(info)
}

// SetEncKey media encryption key fields set k=*
func (m *Media) SetEncKey(value string) {
	m.encKey = []byte(value)
}

// SetConn media connection c=* fields set
func (m *Media) SetConn(addr string) {
	m.Conn = Conn{
		netType:  []byte("IN"),
		addrType: []byte("IP4"),
		address:  []byte(addr),
	}
}

// SetBandWidth media connection c=* fields set
func (m *Media) SetBandWidth(bwtype string, bandwidth int) {
	m.BandWidth = append(m.BandWidth, BandWidth{
		bt: []byte(bwtype),
		bw: []byte(strconv.FormatInt(int64(bandwidth), 10)),
	})
}

// SetSessAttr media attribute key:value fields set a=key:value
func (m *Media) SetSessAttr(key, value string) {
	m.Attr = append(m.Attr, Attribute{
		isFlag: false,
		key:    []byte(key),
		value:  []byte(value),
	})
}

// SetSessAttrFlag media attribute flag fields set a=flagname
func (m *Media) SetSessAttrFlag(value string) {
	m.Attr = append(m.Attr, Attribute{
		isFlag: true,
		flag:   []byte(value),
	})
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
	b.kv('v', []byte{m.ver}) // v=  (protocol version)
	b.o(m)                   // o=  (originator and session identifier)
	b.kv('s', m.subject)     // s=  (session name)
	b.kv('i', m.info)        // i=* (session information)
	b.kv('u', m.uri)         // u=* (URI of description)
	b.e(m)                   // e=* (email address)
	b.p(m)                   // p=* (phone number)
	b.c(m.Conn)              // c=* (connection information)
	b.b(m.BandWidth)         // b=* (zero or more bandwidth information lines)
	b.t(m)                   // one or more time descriptions ("t=" and "r=" lines)
	b.kv('z', m.tzones)      // z=* (time zone adjustments)
	b.kv('k', m.encKey)      // k=* (encryption key)
	b.a(m.Attr)              // a=* (zero or more session attribute lines)

	// Zero or more media descriptions, if present
	for _, media := range m.Medias {
		b.m(media)              // m=  (media name and transport address)
		b.kv('i', media.info)   // i=* (media title)
		b.c(media.Conn)         // c=* (connection information)
		b.b(media.BandWidth)    // b=* (zero or more bandwidth information lines)
		b.kv('k', media.encKey) // k=* (encryption key)
		b.a(media.Attr)         // a=* (zero or more media attribute lines)
	}
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

// email e=
func (b *buffer) e(m *Message) {
	for _, e := range m.Email {
		b.WriteString("e=")
		b.Write(e)
		b.crlf()
	}
}

// phone p=
func (b *buffer) p(m *Message) {
	for _, p := range m.Phone {
		b.WriteString("p=")
		b.Write(p)
		b.crlf()
	}
}

// connection data c=
func (b *buffer) c(c Conn) {
	if c.address == nil {
		return
	}
	b.WriteString("c=")
	b.writeWSpace(c.netType)
	b.writeWSpace(c.addrType)
	b.Write(c.address)
	b.crlf()
}

// bandwidth b=
func (b *buffer) b(bwidth []BandWidth) {
	if bwidth == nil {
		return
	}
	for _, bw := range bwidth {
		b.WriteString("b=")
		b.Write(bw.bt)
		b.WriteByte(':')
		b.Write(bw.bw)
		b.crlf()
	}
}

// timing t=
func (b *buffer) t(m *Message) {
	if len(m.Time) == 0 {
		b.kv('t', []byte("0 0"))
		return
	}

	for _, t := range m.Time {
		// t=  (time the session is active)
		b.WriteString("t=")
		b.writeWSpace(t.start)
		b.Write(t.stop)
		b.crlf()

		if t.Repeat != nil {
			for _, r := range t.Repeat {
				// r=* (zero or more repeat times)
				b.WriteString("r=")
				b.Write(r)
				b.crlf()
			}
		}
	}
}

// attributes a=*
func (b *buffer) a(attributes []Attribute) {
	for _, attr := range attributes {
		if attr.isFlag {
			b.kv('a', attr.flag)
		} else {
			b.WriteString("a=")
			b.Write(attr.key)
			b.WriteByte(':')
			b.Write(attr.value)
		}
		b.crlf()
	}
}

// media m=*
func (b *buffer) m(m Media) {
	b.WriteString("m=")
	b.Write(bytes.Join([][]byte{
		m.mtype, m.port, m.proto, m.fmt}, []byte{' '}))
	b.crlf()
}

// write CRLF
func (b *buffer) crlf() {
	b.WriteString("\r\n")
}

func (b *buffer) writeWSpace(data []byte) {
	b.Write(data)
	b.WriteByte(' ')
}
