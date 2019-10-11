package sipmsg

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// HdrType type header ID
type HdrType int

// SIP Header identifiers
const (
	MsgEOF HdrType = iota
	SIPHdrGeneric
	SIPHdrRequestLine
	SIPHdrStatusLine
	SIPHdrAccept
	SIPHdrAcceptEncoding
	SIPHdrAcceptLanguage
	SIPHdrAlertInfo
	SIPHdrAllow
	SIPHdrAuthenticationInfo
	SIPHdrAuthorization
	SIPHdrCallID
	SIPHdrCallInfo
	SIPHdrContact
	SIPHdrContentDisposition
	SIPHdrContentEncoding
	SIPHdrContentLanguage
	SIPHdrContentLength
	SIPHdrContentType
	SIPHdrCSeq
	SIPHdrDate
	SIPHdrErrorInfo
	SIPHdrExpires
	SIPHdrFrom
	SIPHdrInReplyTo
	SIPHdrMaxForwards
	SIPHdrMIMEVersion
	SIPHdrMinExpires
	SIPHdrOrganization
	SIPHdrPriority
	SIPHdrProxyAuthenticate
	SIPHdrProxyAuthorization
	SIPHdrProxyRequire
	SIPHdrRecordRoute
	SIPHdrReplyTo
	SIPHdrRequire
	SIPHdrRetryAfter
	SIPHdrRoute
	SIPHdrServer
	SIPHdrSubject
	SIPHdrSupported
	SIPHdrTimestamp
	SIPHdrTo
	SIPHdrUnsupported
	SIPHdrUserAgent
	SIPHdrVia
	SIPHdrWarning
	SIPHdrWWWAuthenticate
)

// HeadersList SIP headers list
type HeadersList []*Header

// Count number of headers
func (l HeadersList) Count() int {
	return len(l)
}

// FindByName find header by name
func (l HeadersList) FindByName(name string) *Header {
	for _, h := range l {
		if strings.EqualFold(name, h.Name()) {
			return h
		}
	}
	return nil
}

// Find find header by ID
func (l HeadersList) Find(id HdrType) *Header {
	for _, h := range l {
		if h.ID() == id {
			return h
		}
	}
	return nil
}

func (l HeadersList) exists(buf []byte) bool {
	for _, h := range l {
		if bytes.Equal(buf, h.buf) {
			return true
		}
	}
	return false
}

// Header SIP header
type Header struct {
	buf   []byte
	id    HdrType
	name  pl
	value pl
}

// ID SIP header ID
func (h *Header) ID() HdrType {
	return h.id
}

// Name SIP header name
func (h *Header) Name() string {
	return string(h.buf[h.name.p:h.name.l])
}

// Value SIP header value
func (h *Header) Value() string {
	return string(h.buf[h.value.p:h.value.l])
}

// CSeq SIP sequence number
type CSeq struct {
	Num    uint
	Method string
}

func searchParam(name string, buf []byte, params []pl) (string, bool) {
	for _, p := range params {
		prm := bytes.SplitN(buf[p.p:p.l], []byte("="), 2)
		if bytes.EqualFold([]byte(name), prm[0]) {
			if len(prm) < 2 {
				return "", true
			}
			return string(prm[1]), true
		}
	}
	return "", false
}

// local helper functions and structures
func randomString() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%x", rand.Uint32())
}

func randomStringPrefix(prefix string) string {
	return fmt.Sprintf("%s%s", prefix, randomString())
}

// local buffer extended structrue
type buffer struct {
	bytes.Buffer
}

func (b *buffer) plen() ptr {
	return ptr(b.Len())
}

// field name with colon and space prepended and pl set.
func (b *buffer) name(name string, p *pl) {
	b.WriteString(name)
	p.l = b.plen()
	b.WriteString(": ")
}

func (b *buffer) write(val string, p *pl) {
	if p != nil {
		p.p = b.plen()
	}
	b.WriteString(val)
	if p != nil {
		p.l = b.plen()
	}
}

func (b *buffer) writeBytePrefix(prefix byte, value string, p *pl) {
	b.WriteByte(prefix)
	b.write(value, p)
}

// write parameter (name=value) to buffer and prepend ";"
// pl pointer for parameter is set only for value.
// if name == value then single word parameter is written: ;param
func (b *buffer) paramVal(name, value string, p *pl) {
	b.WriteByte(';')
	b.WriteString(name)
	if name != value {
		b.WriteByte('=')
		b.write(value, p)
	}
}

func (b *buffer) param(name, value string) pl {
	c := pl{}
	b.WriteByte(';')
	c.p = b.plen()
	b.WriteString(name)
	if name != value {
		b.WriteByte('=')
		b.write(value, nil)
	}
	c.l = b.plen()
	return c
}

// write and wrap
// if plInside is true then set pl only around value, otherwise all with wrapper
func (b *buffer) wwrap(wrapper, value string, p *pl, plInside bool) {
	p.p = b.plen()
	b.WriteByte(wrapper[0])
	b.WriteString(value)
	b.WriteByte(wrapper[1])
	p.l = b.plen()

	if plInside {
		p.p++
		p.l--
	}
}

func (b *buffer) crlf() []byte {
	b.WriteString("\r\n")
	return b.Bytes()
}
