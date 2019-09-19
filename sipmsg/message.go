package sipmsg

import (
	"fmt"
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
	via        *ViaList
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

func (m *Message) initVia(buf []byte, name pl) {
	fmt.Println("Init Via")
	m.via = &ViaList{buf: buf, name: name}
}

func (m *Message) setVia(i int, trans, addr, port, branch, ttl, maddr, recevd pl, eol ptr) {
	fmt.Println(i)
	fmt.Println(trans, addr, port, branch, ttl, maddr, recevd, eol)
}
