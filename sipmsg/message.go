package sipmsg

import (
	"bufio"
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

// Message SIP message structure
type Message struct {
	ReqLine    *RequestLine
	StatusLine *StatusLine
	From       *HeaderFromTo
	To         *HeaderFromTo
	Contacts   *ContactsList
	Vias       ViaList
	Routes     RouteList
	RecRoutes  RouteList
	MaxFwd     uint
	CSeq       uint
	CallID     string
	ContentLen uint // Content-Length
}

// MsgParse parser SIP message to Message structure
func MsgParse(data []byte) *Message {
	msg := &Message{}

	idx := bytes.Index(data, []byte("\r\n"))
	if idx == -1 {
		panic("Invalid SIP Message.")
	}
	idx += 2
	hid, err := parseHeader(msg, data[:idx])
	if err != nil {
		return nil // TODO: return errors ?
	}
	if !(hid == SIPHdrRequestLine || hid == SIPHdrStatusLine) {
		return nil // TODO: return errors ?
	}

	splitFun := func(data []byte, atEOF bool) (int, []byte, error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if ix := bytes.Index(data, []byte("\r\n")); ix >= 0 {
			return ix + 2, data[:ix+2], nil
		}

		return 0, nil, nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(data[idx:]))
	scanner.Split(splitFun)
	for scanner.Scan() {
		if _, err := parseHeader(msg, scanner.Bytes()); err != nil {
			return nil // TODO: return errors ?
		}
	}
	if err := scanner.Err(); err != nil {
		return nil // TODO: return errors ?
	}
	return msg
}

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
	cseq, err := strconv.ParseUint(string(num), 10, 32)
	if err != nil {
		panic("Failed to parse CSeq header.")
	}
	m.CSeq = uint(cseq)
	return SIPHdrCSeq
}

func (m *Message) setCallID(buf []byte, pos []pl) HdrType {
	m.CallID = string(buf[pos[1].p:pos[1].l])
	return SIPHdrCallID
}

func (m *Message) setContentLen(buf []byte, pos []pl) HdrType {
	num := buf[pos[1].p:pos[1].l]
	ln, err := strconv.ParseUint(string(num), 10, 32)
	if err != nil {
		panic("Failed to parse Content-Length header.")
	}
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

func (m *Message) initContact(buf []byte, name pl) {
	m.Contacts = &ContactsList{
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
		buf:    m.Contacts.buf[dname.p:eol],
		dname:  pl{dname.p - s, dname.l - s},
		addr:   pl{addr.p - s, addr.l - s},
		params: params,
	}
	m.Contacts.push(cnt)
}

func (m *Message) setContactStar() {
	m.Contacts.star = true
}

func (m *Message) setVia(data []byte, name, trans, addr, port, branch, ttl, maddr, recevd pl, i int, eol ptr) {
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

func (m *Message) setMaxFwd(num []byte) HdrType {
	max, err := strconv.ParseUint(string(num), 10, 32)
	if err != nil {
		panic("Failed to parse Max-Forwards header.")
	}
	m.MaxFwd = uint(max)
	return SIPHdrMaxForwards
}
