package sipmsg

// Structure to replresent position in []byte buffer
// "p" points to start position and "l" points to the last.
// That helps to avoid additional memory allocations.
type pl struct {
	p int
	l int
}

// uri header (name/value) position
type header struct {
	name pl
	val  pl
}

// URI holds SIP(s) uri structure
type URI struct {
	buf      []byte
	scheme   pl
	user     pl
	password pl
	host     pl
	port     pl
	params   pl
	headers  pl
	h        []header
}

func (u *URI) Scheme() string   { return string(u.buf[u.scheme.p:u.scheme.l]) }
func (u *URI) User() string     { return string(u.buf[u.user.p:u.user.l]) }
func (u *URI) Password() string { return string(u.buf[u.password.p:u.password.l]) }
func (u *URI) Host() string     { return string(u.buf[u.host.p:u.host.l]) }
func (u *URI) Port() string     { return string(u.buf[u.port.p:u.port.l]) }
func (u *URI) Params() string   { return string(u.buf[u.params.p:u.params.l]) }
func (u *URI) Headers() string  { return string(u.buf[u.headers.p:u.headers.l]) }
