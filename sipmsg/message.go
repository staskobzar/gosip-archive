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

func (m *Message) setContact(buf []byte, pos []pl) HdrType {
	fmt.Println(pos)
	return SIPHdrContact
}
