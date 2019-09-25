package sipmsg

import (
	"bytes"
	"strconv"
)

type ptr uint16

// Structure to replresent position in []byte buffer
// "p" points to start position and "l" points to the last.
// That helps to avoid additional memory allocations.
type pl struct {
	p ptr
	l ptr
}

var ErrorSIPMsgParse = errorNew("Invalid SIP Message")

// Message SIP message structure
type Message struct {
	ReqLine    *RequestLine
	StatusLine *StatusLine
	From       *HeaderFromTo
	To         *HeaderFromTo
	Contacts   ContactsList
	Vias       ViaList
	Routes     RouteList
	RecRoutes  RouteList
	CallID     string
	CSeq       uint
	ContentLen uint // Content-Length
	Expires    uint
	MaxFwd     uint
}

// MsgParse parser SIP message to Message structure
func MsgParse(data []byte) (*Message, error) {
	msg := &Message{}

	idx := bytes.Index(data, []byte("\r\n"))
	if idx == -1 {
		return nil, ErrorSIPMsgParse
	}
	// parse first line
	idx += 2
	hid, err := parseHeader(msg, data[:idx])
	if err != nil {
		return nil, err
	}
	if !(hid == SIPHdrRequestLine || hid == SIPHdrStatusLine) {
		return nil, ErrorSIPMsgParse.msg("Missing Request/Status line")
	}

	start := idx
	for i := idx; i < len(data); {
		if bytes.HasPrefix(data[i:], []byte("\r\n")) {
			i += 2
			if i < len(data) && (data[i] == ' ' || data[i] == '\t') {
				continue
			}
			hid, err = parseHeader(msg, data[start:i])
			if err != nil {
				return nil, err
			}
			if hid == MsgEOF {
				break
			}
			start = i
			continue
		}
		i++
	}
	// must be CRLF in the end of the SIP Message
	if hid != MsgEOF {
		return nil, ErrorSIPMsgParse.msg("Message must be finished with CRLF (%d)", hid)
	}
	return msg, nil
}

// IsRequest returns true is SIP Message is request
func (m *Message) IsRequest() bool { return m.ReqLine != nil }

// IsResponse returns true is SIP Message is response
func (m *Message) IsResponse() bool { return m.StatusLine != nil }

// private methods
func (m *Message) setStatusLine(buf []byte, pos []pl) HdrType {
	sl := &StatusLine{
		buf:    buf,
		ver:    pos[0],
		code:   pos[1],
		reason: pos[2],
	}
	m.StatusLine = sl
	return SIPHdrStatusLine
}

func (m *Message) setRequestLine(buf []byte, pos []pl) HdrType {
	rl := &RequestLine{
		buf:    buf,
		method: pos[0],
		uri:    pos[1],
		ver:    pos[2],
	}
	m.ReqLine = rl
	return SIPHdrRequestLine
}

func (m *Message) setCSeq(buf []byte, pos []pl) HdrType {
	num := buf[pos[1].p:pos[1].l]
	// do not check return. Parser must assure it is a number
	cseq, _ := strconv.ParseUint(string(num), 10, 32)
	m.CSeq = uint(cseq)
	return SIPHdrCSeq
}

func (m *Message) setCallID(buf []byte, pos []pl) HdrType {
	m.CallID = string(buf[pos[1].p:pos[1].l])
	return SIPHdrCallID
}

func (m *Message) setContentLen(buf []byte, pos []pl) HdrType {
	num := buf[pos[1].p:pos[1].l]
	// do not check return. Parser must assure it is a number
	ln, _ := strconv.ParseUint(string(num), 10, 32)
	m.ContentLen = uint(ln)
	return SIPHdrContentLength
}

func (m *Message) setFrom(buf []byte, params []pl, fname, dname, addr, tag pl) HdrType {
	m.From = newHeaderFromTo(buf, params, fname, dname, addr, tag)
	return SIPHdrFrom
}

func (m *Message) setTo(buf []byte, params []pl, fname, dname, addr, tag pl) HdrType {
	m.To = newHeaderFromTo(buf, params, fname, dname, addr, tag)
	return SIPHdrTo
}

func (m *Message) setContact(buf []byte, name, dname, addr pl, params []pl, i int) {
	if m.Contacts.Count() == 0 || m.Contacts.Count() == i {
		m.Contacts.cnt = append(m.Contacts.cnt, &Contact{buf: buf, name: name})
	}
	m.Contacts.cnt[i].name = name
	m.Contacts.cnt[i].dname = dname
	m.Contacts.cnt[i].addr = addr
	m.Contacts.cnt[i].params = params
}

func (m *Message) setContactStar() {
	m.Contacts.star = true
}

func (m *Message) setVia(data []byte, name, trans, addr, port, branch, ttl, maddr, recevd pl, i int) {
	if m.Vias.Count() == 0 || m.Vias.Count() == i {
		m.Vias = append(m.Vias, &Via{buf: data, name: name})
	}
	m.Vias[i].trans = trans
	m.Vias[i].host = addr
	m.Vias[i].port = port
	m.Vias[i].branch = branch
	m.Vias[i].ttl = ttl
	m.Vias[i].maddr = maddr
	m.Vias[i].recevd = recevd
}

func (m *Message) setRoute(hid HdrType, buf []byte, fname, dname, addr pl, params []pl) {
	r := &Route{
		buf:    buf,
		fname:  fname,
		dname:  dname,
		addr:   addr,
		params: params,
	}
	if hid == SIPHdrRecordRoute {
		m.RecRoutes = append(m.RecRoutes, r)
		return
	}
	m.Routes = append(m.Routes, r)
}

func (m *Message) setExpires(num []byte) HdrType {
	// do not check return. Parser must assure it is a number
	expires, _ := strconv.ParseUint(string(num), 10, 32)
	m.Expires = uint(expires)
	return SIPHdrExpires
}

func (m *Message) setMaxFwd(num []byte) HdrType {
	// do not check return. Parser must assure it is a number
	max, _ := strconv.ParseUint(string(num), 10, 32)
	m.MaxFwd = uint(max)
	return SIPHdrMaxForwards
}
