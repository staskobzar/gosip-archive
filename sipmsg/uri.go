package sipmsg

import (
	"net/url"
	"strings"
)

var ErrorURI = errorNew("Invalid URI")

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
	buf      buffer
	id       URIType
	scheme   pl // string representation
	user     pl
	password pl
	host     pl
	port     pl
	params   pl // parameters string
	headers  pl // headers string
}

// NewSIPURI Create SIP URI struct
func NewSIPURI(host string, port int) (*URI, error) {
	uri := &URI{}
	return uri.init("sip", host, port)
}

// NewSIPSURI Create SIP URI struct
func NewSIPSURI(host string, port int) (*URI, error) {
	uri := &URI{}
	return uri.init("sips", host, port)
}

// SetUserinfo updates user and password segment of URI.
// String argument should contain user and/of password: "user:pass", "user"
// Empty string removes user/password part of URI.
func (u *URI) SetUserinfo(user, pass string) error {
	if u.id == URIabs {
		return ErrorURI.msg("SetUserinfo is only available for sip uri.")
	}

	buf := buffer{}

	if len(user) == 0 && len(pass) > 0 {
		return ErrorURI.msg("Userinfo can not have empty username when password present.")
	}

	buf.Write(u.buf.byt(u.scheme))
	buf.WriteByte(':')

	buf.write(user, &u.user)
	if len(pass) > 0 {
		buf.writeBytePrefix(':', pass, &u.password)
	}

	if u.user.l > u.user.p {
		buf.WriteByte('@')
	}
	buf.write(u.buf.str(u.host), &u.host)

	if u.port.l > u.port.p {
		buf.writeBytePrefix(':', u.buf.str(u.port), &u.port)
	}

	if u.params.l > u.params.p {
		buf.write(u.buf.str(u.params), &u.params)
	}

	if u.headers.l > u.headers.p {
		buf.write(u.buf.str(u.headers), &u.headers)
	}

	u.buf = buf

	return nil
}

// SetPort set URI port. If 0 then removes port from URI.
func (u *URI) SetPort(port int) error {
	if u.id == URIabs {
		return ErrorURI.msg("SetUserinfo is only available for sip uri.")
	}

	buf := buffer{}
	buf.write(u.buf.str(pl{0, u.host.l}), nil)

	if err := buf.appendPort(port, &u.port); err != nil {
		return err
	}

	if u.params.l > u.params.p {
		buf.write(u.buf.str(u.params), &u.params)
	}

	if u.headers.l > u.headers.p {
		buf.write(u.buf.str(u.headers), &u.headers)
	}

	u.buf = buf

	return nil
}

// String return URI as string
func (u *URI) String() string {
	return u.buf.String()
}

// Scheme URI scheme as string
func (u *URI) Scheme() string { return u.buf.str(u.scheme) }

// ID returns URI id (sip/sips/absolute)
func (u *URI) ID() URIType { return u.id }

// User URI user as string
func (u *URI) User() string {
	if u.id != URIabs {
		return u.buf.str(u.user)
	}
	uri, _ := url.Parse(u.buf.String())
	return uri.User.Username()
}

// Password URI password as string
func (u *URI) Password() string {
	if u.id != URIabs {
		return u.buf.str(u.password)
	}
	uri, _ := url.Parse(u.buf.String())
	pass, _ := uri.User.Password()
	return pass
}

// Host URI host/ip as string
func (u *URI) Host() string {
	if u.id != URIabs {
		return u.buf.str(u.host)
	}
	uri, _ := url.Parse(u.buf.String())
	return uri.Hostname()
}

// Port URI port as string
func (u *URI) Port() string {
	if u.id != URIabs {
		return u.buf.str(u.port)
	}
	uri, _ := url.Parse(u.buf.String())
	return uri.Port()
}

// Params URI all parameters as string
func (u *URI) Params() string {
	if u.params.p == u.params.l {
		return ""
	}
	p := pl{u.params.p + 1, u.params.l}
	return u.buf.str(p)
}

// Headers URI all headers as string
func (u *URI) Headers() string {
	if u.headers.p == u.headers.l {
		return ""
	}
	p := pl{u.headers.p + 1, u.headers.l}
	return u.buf.str(p)
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

// AddHeader adds new header to URI. Does not update existing header.
// Return error if header already exists.
func (u *URI) AddHeader(name, value string) error {
	var p ptr
	buf := buffer{}

	if _, exists := u.Header(name); exists {
		return ErrorURI.msg("AddHeader: header '%s' exists.", name)
	}

	if u.headers.l > u.headers.p {
		p = u.headers.l
	} else if u.params.l > u.params.p {
		p = u.params.l
		u.headers.p = p
	} else if u.port.l > u.port.p {
		p = u.port.l
		u.headers.p = p
	} else {
		p = u.host.l
		u.headers.p = p
	}

	buf.write(u.buf.str(pl{0, p}), nil)

	if u.headers.l > u.headers.p {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}

	buf.WriteString(name)
	buf.WriteByte('=')
	buf.WriteString(value)
	u.headers.l = buf.plen()

	u.buf = buf
	return nil
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

// AddParam adds new parameter to URI. Does not update existing parameter.
// Return error if parameter already exists.
// When name  equals value then single value parameter will be added.
// For example AddParam("lr", "lr") will create ";lr" parameter.
func (u *URI) AddParam(name, value string) error {
	var p ptr
	buf := buffer{}

	if _, exists := u.Param(name); exists {
		return ErrorURI.msg("AddParam: parameter '%s' exists.", name)
	}

	if u.params.l > u.params.p {
		p = u.params.l
	} else if u.port.l > u.port.p {
		p = u.port.l
		u.params.p = p
	} else {
		p = u.host.l
		u.params.p = p
	}

	buf.write(u.buf.str(pl{0, p}), nil)

	c := buf.param(name, value)
	u.params.l = c.l

	if u.headers.l > u.headers.p {
		buf.write(u.buf.str(pl{p, u.buf.plen()}), &u.headers)
	}

	u.buf = buf
	return nil
}

// Path absolute URI path
func (u *URI) Path() string {
	if u.id != URIabs {
		return ""
	}
	uri, _ := url.Parse(u.buf.String())
	return uri.Path
}

// Query absolute URI query
func (u *URI) Query() string {
	if u.id != URIabs {
		return ""
	}
	uri, _ := url.Parse(u.buf.String())
	return uri.RawQuery
}

// local functions

func (uri *URI) init(scheme, host string, port int) (*URI, error) {
	b := buffer{}
	b.write(scheme, &uri.scheme)
	b.WriteByte(':')

	if len(host) == 0 {
		return nil, ErrorURI.msg("Invalid host. Can not be empty.")
	}

	b.write(host, &uri.host)

	if err := b.appendPort(port, &uri.port); err != nil {
		return nil, err
	}

	uri.buf = b
	return uri, nil
}
