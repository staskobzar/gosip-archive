package sipmsg

// RequestLine SIP message request line structure
type RequestLine struct {
	buf    []byte
	method pl
	uri    pl
	ver    pl
}

// Method request line method
func (s *RequestLine) Method() string { return string(s.buf[s.method.p:s.method.l]) }

// RequestURI request line URI as string
func (s *RequestLine) RequestURI() string { return string(s.buf[s.uri.p:s.uri.l]) }

// Version request line version
func (s *RequestLine) Version() string { return string(s.buf[s.ver.p:s.ver.l]) }

// StatusLine SIP message status line structure
type StatusLine struct {
	buf    []byte
	ver    pl
	code   pl
	reason pl
}

// Version status line version
func (s *StatusLine) Version() string { return string(s.buf[s.ver.p:s.ver.l]) }

// Code status line code
func (s *StatusLine) Code() string { return string(s.buf[s.code.p:s.code.l]) }

// Reason status line reason phrase
func (s *StatusLine) Reason() string { return string(s.buf[s.reason.p:s.reason.l]) }
