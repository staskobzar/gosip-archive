package sipmsg

import (
	"strings"
)

// Structure to replresent position in []byte buffer
// "p" points to start position and "l" points to the last.
// That helps to avoid additional memory allocations.
type pl struct {
	p int
	l int
}

// URI holds SIP(s) uri structure
type URI struct {
	buf      []byte
	scheme   pl
	user     pl
	password pl
	host     pl
	port     pl
	params   pl // parameters string
	headers  pl // headers string
}

// Scheme URI scheme as string
func (u *URI) Scheme() string { return string(u.buf[u.scheme.p:u.scheme.l]) }

// User URI user as string
func (u *URI) User() string { return string(u.buf[u.user.p:u.user.l]) }

// Password URI password as string
func (u *URI) Password() string { return string(u.buf[u.password.p:u.password.l]) }

// Host URI host/ip as string
func (u *URI) Host() string { return string(u.buf[u.host.p:u.host.l]) }

// Port URI port as string
func (u *URI) Port() string { return string(u.buf[u.port.p:u.port.l]) }

// Params URI all parameters as string
func (u *URI) Params() string {
	if u.params.p == u.params.l {
		return ""
	}
	return string(u.buf[u.params.p+1 : u.params.l])
}

// Headers URI all headers as string
func (u *URI) Headers() string {
	if u.headers.p == u.headers.l {
		return ""
	}
	return string(u.buf[u.headers.p+1 : u.headers.l])
}

// Header returns URI header and true if header exists
func (u *URI) Header(name string) (string, bool) {
	headers := u.Headers()
	for _, header := range strings.Split(headers, "&") {
		p := strings.SplitN(header, "=", 2)
		if strings.EqualFold(p[0], name) {
			return p[1], true
		}
	}
	return "", false
}

// Param returns URI parameter and true if it exists
func (u *URI) Param(name string) (string, bool) {
	params := u.Params()
	for _, param := range strings.Split(params, ";") {
		p := strings.SplitN(param, "=", 2)
		if strings.EqualFold(p[0], name) {
			if len(p) == 2 {
				return p[1], true
			}
			return "", true
		}
	}
	return "", false
}
