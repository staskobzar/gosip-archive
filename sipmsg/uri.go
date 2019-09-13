package sipmsg

import (
	"net/url"
	"strings"
)

// URIType identificator of URI
type URIType int

const (
	// URIabs represents absolute URI type
	URIabs URIType = iota + 1
	// URIsip represents SIP URI type
	URIsip
	// URIsips represents SIPS URI type
	URIsips
)

// URI holds SIP(s) uri structure
type URI struct {
	buf      []byte
	id       URIType
	scheme   pl // string representation
	user     pl
	password pl
	host     pl
	port     pl
	params   pl // parameters string
	headers  pl // headers string
}

// Scheme URI scheme as string
func (u *URI) Scheme() string { return string(u.buf[u.scheme.p:u.scheme.l]) }

// ID returns URI id (sip/sips/absolute)
func (u *URI) ID() URIType { return u.id }

// User URI user as string
func (u *URI) User() string {
	if u.id != URIabs {
		return string(u.buf[u.user.p:u.user.l])
	}
	uri, _ := url.Parse(string(u.buf))
	return uri.User.Username()
}

// Password URI password as string
func (u *URI) Password() string {
	if u.id != URIabs {
		return string(u.buf[u.password.p:u.password.l])
	}
	uri, _ := url.Parse(string(u.buf))
	pass, _ := uri.User.Password()
	return pass
}

// Host URI host/ip as string
func (u *URI) Host() string {
	if u.id != URIabs {
		return string(u.buf[u.host.p:u.host.l])
	}
	uri, _ := url.Parse(string(u.buf))
	return uri.Hostname()
}

// Port URI port as string
func (u *URI) Port() string {
	if u.id != URIabs {
		return string(u.buf[u.port.p:u.port.l])
	}
	uri, _ := url.Parse(string(u.buf))
	return uri.Port()
}

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

// Path absolute URI path
func (u *URI) Path() string {
	if u.id != URIabs {
		return ""
	}
	uri, _ := url.Parse(string(u.buf))
	return uri.Path
}

// Query absolute URI query
func (u *URI) Query() string {
	if u.id != URIabs {
		return ""
	}
	uri, _ := url.Parse(string(u.buf))
	return uri.RawQuery
}
