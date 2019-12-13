package sipmsg

import "bytes"

// RequestLine SIP message request line structure
type RequestLine struct {
	buf    buffer
	method pl
	uri    pl
	ver    pl
}

// NewReqLine creates new request line
func NewReqLine(method, ruri string) *RequestLine {
	r := &RequestLine{}
	b := buffer{}
	b.write(method, &r.method)
	b.WriteByte(' ')
	b.write(ruri, &r.uri)
	b.WriteByte(' ')
	b.write("SIP/2.0", &r.ver)
	b.crlf()
	r.buf = b
	return r
}

// Method request line method
func (s *RequestLine) Method() string { return s.buf.str(s.method) }

// IsInvite returns true if request line method is INVITE
func (s *RequestLine) IsInvite() bool {
	return bytes.EqualFold([]byte("invite"), s.buf.byt(s.method))
}

// RequestURI request line URI as string
func (s *RequestLine) RequestURI() string { return s.buf.str(s.uri) }

// Version request line version
func (s *RequestLine) Version() string { return s.buf.str(s.ver) }

// Bytes returns request line as bytes slice
func (s *RequestLine) Bytes() []byte { return s.buf.Bytes() }

// StatusLine SIP message status line structure
type StatusLine struct {
	buf    buffer
	ver    pl
	code   pl
	reason pl
}

// NewStatusLine creates new status line
func NewStatusLine(code, reason string) *StatusLine {
	s := &StatusLine{}
	b := buffer{}
	b.write("SIP/2.0", &s.ver)
	b.WriteByte(' ')
	b.write(code, &s.code)
	b.WriteByte(' ')
	b.write(reason, &s.reason)
	b.crlf()
	s.buf = b
	return s
}

// Version status line version
func (s *StatusLine) Version() string { return s.buf.str(s.ver) }

// Code status line code
func (s *StatusLine) Code() string { return s.buf.str(s.code) }

// Reason status line reason phrase
func (s *StatusLine) Reason() string { return s.buf.str(s.reason) }

// Bytes returns status line as bytes slice
func (s *StatusLine) Bytes() []byte { return s.buf.Bytes() }
