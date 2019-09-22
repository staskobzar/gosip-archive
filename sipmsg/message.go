package sipmsg

import (
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

// Message SIP message structure
type Message struct {
	reqLine    *RequestLine
	statusLine *StatusLine
	from       *HeaderFromTo
	to         *HeaderFromTo
	contacts   *ContactsList
	via        ViaList
	route      RouteList
	rroute     RouteList
	maxfwd     uint
	cseq       uint
	callID     []byte
	cntLen     uint // Content-Length
}

// StatusLine returns SIP message status line
func (m *Message) StatusLine() *StatusLine { return m.statusLine }

// RequestLine returns SIP message request line
func (m *Message) RequestLine() *RequestLine { return m.reqLine }

// CSeq returns SIP message sequence number
func (m *Message) CSeq() uint { return m.cseq }

// CallID returns SIP message call ID string
func (m *Message) CallID() string { return string(m.callID) }

// ContentLen returns SIP message content length.
// If there are no content (body) then 0
func (m *Message) ContentLen() uint { return m.cntLen }

// From returns SIP message from header
func (m *Message) From() *HeaderFromTo { return m.from }

// To returns SIP message from header
func (m *Message) To() *HeaderFromTo { return m.to }

// Contacts returns SIP message contacts list
func (m *Message) Contacts() *ContactsList { return m.contacts }

// Via returns SIP message Via headers list
func (m *Message) Via() ViaList { return m.via }

// Routes returns SIP message Route headers list
func (m *Message) Routes() RouteList { return m.route }

// RecordRoutes returns SIP message Route headers list
func (m *Message) RecordRoutes() RouteList { return m.rroute }

// MaxForwards returns SIP Max-Forwards number
func (m *Message) MaxForwards() uint { return m.maxfwd }

// private methods
func (m *Message) setStatusLine(buf []byte, pos []pl) HdrType {
	sl := &StatusLine{
		buf:    buf,
		ver:    pos[0],
		code:   pos[1],
		reason: pos[2],
	}
	m.statusLine = sl
	return SIPHdrStatusLine
}

func (m *Message) setRequestLine(buf []byte, pos []pl) HdrType {
	rl := &RequestLine{
		buf:    buf,
		method: pos[0],
		uri:    pos[1],
		ver:    pos[2],
	}
	m.reqLine = rl
	return SIPHdrRequestLine
}

func (m *Message) setCSeq(buf []byte, pos []pl) HdrType {
	num := buf[pos[1].p:pos[1].l]
	cseq, err := strconv.ParseUint(string(num), 10, 32)
	if err != nil {
		panic("Failed to parse CSeq header.")
	}
	m.cseq = uint(cseq)
	return SIPHdrCSeq
}

func (m *Message) setCallID(buf []byte, pos []pl) HdrType {
	m.callID = buf[pos[1].p:pos[1].l]
	return SIPHdrCallID
}

func (m *Message) setContentLen(buf []byte, pos []pl) HdrType {
	num := buf[pos[1].p:pos[1].l]
	ln, err := strconv.ParseUint(string(num), 10, 32)
	if err != nil {
		panic("Failed to parse Content-Length header.")
	}
	m.cntLen = uint(ln)
	return SIPHdrContentLength
}

func (m *Message) setFrom(buf []byte, params []pl, fname, dname, addr, tag pl) HdrType {
	m.from = newHeaderFromTo(buf, params, fname, dname, addr, tag)
	return SIPHdrFrom
}

func (m *Message) setTo(buf []byte, params []pl, fname, dname, addr, tag pl) HdrType {
	m.to = newHeaderFromTo(buf, params, fname, dname, addr, tag)
	return SIPHdrTo
}

func (m *Message) initContact(buf []byte, name pl) {
	m.contacts = &ContactsList{
		buf:  buf,
		name: name,
	}
}

func (m *Message) setContact(dname, addr pl, params []pl, eol ptr) {
	s := dname.p // shift len
	for i := range params {
		params[i].p -= s
		params[i].l -= s
	}
	cnt := Contact{
		buf:    m.contacts.buf[dname.p:eol],
		dname:  pl{dname.p - s, dname.l - s},
		addr:   pl{addr.p - s, addr.l - s},
		params: params,
	}
	m.contacts.push(cnt)
}

func (m *Message) setContactStar() {
	m.contacts.star = true
}

func (m *Message) setVia(data []byte, name, trans, addr, port, branch, ttl, maddr, recevd pl, i int, eol ptr) {
	if m.via.Count() == 0 || m.via.Count() == i {
		m.via = append(m.via, &Via{buf: data, name: name})
	}
	m.via[i].trans = trans
	m.via[i].host = addr
	m.via[i].port = port
	m.via[i].branch = branch
	m.via[i].ttl = ttl
	m.via[i].maddr = maddr
	m.via[i].recevd = recevd
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
		m.rroute = append(m.rroute, r)
		return
	}
	m.route = append(m.route, r)
}

func (m *Message) setMaxFwd(num []byte) HdrType {
	max, err := strconv.ParseUint(string(num), 10, 32)
	if err != nil {
		panic("Failed to parse Max-Forwards header.")
	}
	m.maxfwd = uint(max)
	return SIPHdrMaxForwards
}
